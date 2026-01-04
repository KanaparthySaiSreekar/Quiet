use libp2p::{
    core::upgrade,
    futures::StreamExt,
    identity::Keypair,
    kad::{self, store::MemoryStore, Mode},
    mdns,
    noise,
    quic,
    relay,
    request_response::{self, OutboundRequestId, ResponseChannel},
    swarm::{NetworkBehaviour, Swarm, SwarmBuilder, SwarmEvent},
    tcp, yamux, Multiaddr, PeerId as Libp2pPeerId, Transport,
};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn, error};

use crate::error::{DarkTermError, Result};
use crate::identity::Identity;
use super::{ChatRequest, ChatResponse, DiscoveryConfig};
use super::protocol::create_chat_protocol;

/// P2P network node
pub struct P2PNode {
    swarm: Swarm<ChatBehaviour>,
    event_tx: mpsc::UnboundedSender<P2PEvent>,
    pending_requests: HashMap<OutboundRequestId, PendingRequest>,
}

/// Network behavior combining all protocols
#[derive(NetworkBehaviour)]
pub struct ChatBehaviour {
    chat: request_response::Behaviour<super::protocol::ChatCodec>,
    kad: kad::Behaviour<MemoryStore>,
    mdns: mdns::tokio::Behaviour,
    relay_client: relay::client::Behaviour,
    identify: libp2p::identify::Behaviour,
}

/// P2P events
#[derive(Debug, Clone)]
pub enum P2PEvent {
    /// New peer discovered
    PeerDiscovered {
        peer_id: Libp2pPeerId,
        addresses: Vec<Multiaddr>,
    },

    /// Peer disconnected
    PeerDisconnected {
        peer_id: Libp2pPeerId,
    },

    /// Incoming chat request
    IncomingRequest {
        peer_id: Libp2pPeerId,
        request: ChatRequest,
        channel: ResponseChannel<ChatResponse>,
    },

    /// Response received
    ResponseReceived {
        peer_id: Libp2pPeerId,
        response: ChatResponse,
    },

    /// Request failed
    RequestFailed {
        peer_id: Libp2pPeerId,
        error: String,
    },

    /// Connection established
    ConnectionEstablished {
        peer_id: Libp2pPeerId,
        endpoint: String,
    },

    /// Listening on new address
    NewListenAddr {
        address: Multiaddr,
    },
}

/// Pending request tracker
struct PendingRequest {
    peer_id: Libp2pPeerId,
}

impl P2PNode {
    /// Create new P2P node
    pub async fn new(
        identity: &Identity,
        config: DiscoveryConfig,
    ) -> Result<(Self, mpsc::UnboundedReceiver<P2PEvent>)> {
        info!("Initializing P2P node");

        // Create libp2p keypair from identity
        let keypair = Self::identity_to_keypair(identity)?;
        let peer_id = keypair.public().to_peer_id();

        info!("Local peer ID: {}", peer_id);

        // Build swarm
        let swarm = Self::build_swarm(keypair, config).await?;

        // Create event channel
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let node = Self {
            swarm,
            event_tx,
            pending_requests: HashMap::new(),
        };

        Ok((node, event_rx))
    }

    /// Build libp2p swarm
    async fn build_swarm(
        keypair: Keypair,
        config: DiscoveryConfig,
    ) -> Result<Swarm<ChatBehaviour>> {
        let peer_id = keypair.public().to_peer_id();

        // Create chat protocol
        let chat = create_chat_protocol();

        // Create Kademlia DHT
        let store = MemoryStore::new(peer_id);
        let mut kad_config = kad::Config::default();
        kad_config.set_protocol_names(vec![
            libp2p::StreamProtocol::new("/darkterm/kad/1.0.0")
        ]);
        let mut kad = kad::Behaviour::with_config(peer_id, store, kad_config);
        kad.set_mode(Some(Mode::Server));

        // Add bootstrap nodes
        for bootstrap in &config.bootstrap_nodes {
            if let Ok(peer_id) = bootstrap.peer_id.parse::<Libp2pPeerId>() {
                if let Ok(addr) = bootstrap.address.parse::<Multiaddr>() {
                    kad.add_address(&peer_id, addr);
                }
            }
        }

        // Create mDNS
        let mdns = mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            peer_id,
        ).map_err(|e| DarkTermError::Network(format!("Failed to create mDNS: {}", e)))?;

        // Create relay client
        let (relay_transport, relay_client) = relay::client::new(peer_id);

        // Create identify protocol
        let identify = libp2p::identify::Behaviour::new(
            libp2p::identify::Config::new(
                "/darkterm/id/1.0.0".to_string(),
                keypair.public(),
            )
        );

        // Create behaviour
        let behaviour = ChatBehaviour {
            chat,
            kad,
            mdns,
            relay_client,
            identify,
        };

        // Build transport with QUIC and TCP
        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_quic()
            .with_other_transport(|keypair| {
                tcp::tokio::Transport::default()
                    .upgrade(upgrade::Version::V1)
                    .authenticate(noise::Config::new(keypair)?)
                    .multiplex(yamux::Config::default())
                    .or_transport(relay_transport)
            })?
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(60))
            })
            .build();

        Ok(swarm)
    }

    /// Convert identity to libp2p keypair
    fn identity_to_keypair(identity: &Identity) -> Result<Keypair> {
        // Create Ed25519 keypair from identity
        let signing_key_bytes = identity.signing_key_bytes();

        let keypair = Keypair::ed25519_from_bytes(signing_key_bytes)
            .map_err(|e| DarkTermError::Identity(format!("Failed to create keypair: {}", e)))?;

        Ok(keypair)
    }

    /// Start listening on all interfaces
    pub fn listen(&mut self, port: u16) -> Result<()> {
        let tcp_addr = format!("/ip4/0.0.0.0/tcp/{}", port)
            .parse::<Multiaddr>()
            .map_err(|e| DarkTermError::Network(format!("Invalid address: {}", e)))?;

        let quic_addr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", port)
            .parse::<Multiaddr>()
            .map_err(|e| DarkTermError::Network(format!("Invalid address: {}", e)))?;

        self.swarm.listen_on(tcp_addr.clone())
            .map_err(|e| DarkTermError::Network(format!("Failed to listen on TCP: {}", e)))?;

        self.swarm.listen_on(quic_addr.clone())
            .map_err(|e| DarkTermError::Network(format!("Failed to listen on QUIC: {}", e)))?;

        info!("Listening on port {}", port);
        Ok(())
    }

    /// Dial a peer
    pub fn dial(&mut self, peer_id: Libp2pPeerId, addr: Multiaddr) -> Result<()> {
        self.swarm.dial(addr.clone())
            .map_err(|e| DarkTermError::Network(format!("Failed to dial peer: {}", e)))?;

        info!("Dialing peer {} at {}", peer_id, addr);
        Ok(())
    }

    /// Send chat request to peer
    pub fn send_request(&mut self, peer_id: Libp2pPeerId, request: ChatRequest) -> Result<()> {
        let request_id = self.swarm.behaviour_mut().chat.send_request(&peer_id, request);

        self.pending_requests.insert(request_id, PendingRequest { peer_id });

        debug!("Sent request to peer {}", peer_id);
        Ok(())
    }

    /// Send response to peer
    pub fn send_response(
        &mut self,
        channel: ResponseChannel<ChatResponse>,
        response: ChatResponse,
    ) -> Result<()> {
        self.swarm.behaviour_mut().chat.send_response(channel, response)
            .map_err(|_| DarkTermError::Network("Failed to send response".to_string()))?;

        Ok(())
    }

    /// Run the swarm event loop
    pub async fn run(mut self) -> Result<()> {
        info!("Starting P2P node event loop");

        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Listening on {}", address);
                    let _ = self.event_tx.send(P2PEvent::NewListenAddr { address });
                }

                SwarmEvent::Behaviour(ChatBehaviourEvent::Chat(event)) => {
                    self.handle_chat_event(event);
                }

                SwarmEvent::Behaviour(ChatBehaviourEvent::Mdns(event)) => {
                    self.handle_mdns_event(event);
                }

                SwarmEvent::Behaviour(ChatBehaviourEvent::Kad(event)) => {
                    self.handle_kad_event(event);
                }

                SwarmEvent::Behaviour(ChatBehaviourEvent::Identify(event)) => {
                    self.handle_identify_event(event);
                }

                SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                    info!("Connection established with peer {}", peer_id);
                    let _ = self.event_tx.send(P2PEvent::ConnectionEstablished {
                        peer_id,
                        endpoint: format!("{:?}", endpoint),
                    });
                }

                SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                    info!("Connection closed with peer {}: {:?}", peer_id, cause);
                    let _ = self.event_tx.send(P2PEvent::PeerDisconnected { peer_id });
                }

                _ => {}
            }
        }
    }

    /// Handle chat protocol events
    fn handle_chat_event(&mut self, event: request_response::Event<ChatRequest, ChatResponse>) {
        match event {
            request_response::Event::Message { peer, message } => {
                match message {
                    request_response::Message::Request { request, channel, .. } => {
                        debug!("Received request from peer {}", peer);
                        let _ = self.event_tx.send(P2PEvent::IncomingRequest {
                            peer_id: peer,
                            request,
                            channel,
                        });
                    }

                    request_response::Message::Response { request_id, response } => {
                        if let Some(pending) = self.pending_requests.remove(&request_id) {
                            debug!("Received response from peer {}", pending.peer_id);
                            let _ = self.event_tx.send(P2PEvent::ResponseReceived {
                                peer_id: pending.peer_id,
                                response,
                            });
                        }
                    }
                }
            }

            request_response::Event::OutboundFailure { peer, request_id, error } => {
                if let Some(pending) = self.pending_requests.remove(&request_id) {
                    warn!("Request failed to peer {}: {:?}", peer, error);
                    let _ = self.event_tx.send(P2PEvent::RequestFailed {
                        peer_id: pending.peer_id,
                        error: format!("{:?}", error),
                    });
                }
            }

            request_response::Event::InboundFailure { peer, error, .. } => {
                warn!("Inbound failure from peer {}: {:?}", peer, error);
            }

            _ => {}
        }
    }

    /// Handle mDNS events
    fn handle_mdns_event(&mut self, event: mdns::Event) {
        match event {
            mdns::Event::Discovered(list) => {
                for (peer_id, addr) in list {
                    info!("Discovered peer via mDNS: {} at {}", peer_id, addr);

                    // Add to Kademlia routing table
                    self.swarm.behaviour_mut().kad.add_address(&peer_id, addr.clone());

                    let _ = self.event_tx.send(P2PEvent::PeerDiscovered {
                        peer_id,
                        addresses: vec![addr],
                    });
                }
            }

            mdns::Event::Expired(list) => {
                for (peer_id, addr) in list {
                    debug!("mDNS peer expired: {} at {}", peer_id, addr);
                }
            }
        }
    }

    /// Handle Kademlia DHT events
    fn handle_kad_event(&mut self, event: kad::Event) {
        match event {
            kad::Event::RoutingUpdated { peer, addresses, .. } => {
                debug!("Kademlia routing updated: {} at {:?}", peer, addresses);
                let _ = self.event_tx.send(P2PEvent::PeerDiscovered {
                    peer_id: peer,
                    addresses: addresses.into_vec(),
                });
            }

            kad::Event::InboundRequest { request } => {
                debug!("Kademlia inbound request: {:?}", request);
            }

            _ => {}
        }
    }

    /// Handle Identify protocol events
    fn handle_identify_event(&mut self, event: libp2p::identify::Event) {
        match event {
            libp2p::identify::Event::Received { peer_id, info } => {
                debug!("Identified peer {}: {:?}", peer_id, info);

                // Add addresses to Kademlia
                for addr in info.listen_addrs {
                    self.swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                }
            }

            libp2p::identify::Event::Sent { .. } => {}
            libp2p::identify::Event::Pushed { .. } => {}
            libp2p::identify::Event::Error { peer_id, error } => {
                warn!("Identify error with peer {}: {:?}", peer_id, error);
            }
        }
    }

    /// Bootstrap Kademlia DHT
    pub fn bootstrap(&mut self) -> Result<()> {
        self.swarm.behaviour_mut().kad.bootstrap()
            .map_err(|e| DarkTermError::Network(format!("Bootstrap failed: {}", e)))?;

        info!("DHT bootstrap initiated");
        Ok(())
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> &Libp2pPeerId {
        self.swarm.local_peer_id()
    }

    /// Get listening addresses
    pub fn listeners(&self) -> Vec<Multiaddr> {
        self.swarm.listeners().cloned().collect()
    }
}
