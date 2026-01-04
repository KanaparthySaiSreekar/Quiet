use libp2p::{Multiaddr, PeerId as Libp2pPeerId};
use serde::{Deserialize, Serialize};

/// Discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Enable mDNS for local network discovery
    pub enable_mdns: bool,

    /// Enable Kademlia DHT for WAN discovery
    pub enable_kademlia: bool,

    /// Enable relay for NAT traversal
    pub enable_relay: bool,

    /// Bootstrap nodes for DHT
    pub bootstrap_nodes: Vec<BootstrapNode>,

    /// Known relay nodes
    pub relay_nodes: Vec<Multiaddr>,
}

/// Bootstrap node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapNode {
    pub peer_id: String,
    pub address: String,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enable_mdns: true,
            enable_kademlia: true,
            enable_relay: true,
            bootstrap_nodes: Vec::new(),
            relay_nodes: Vec::new(),
        }
    }
}

impl DiscoveryConfig {
    /// Create new discovery config with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Add bootstrap node
    pub fn with_bootstrap_node(mut self, peer_id: String, address: String) -> Self {
        self.bootstrap_nodes.push(BootstrapNode { peer_id, address });
        self
    }

    /// Add relay node
    pub fn with_relay_node(mut self, address: Multiaddr) -> Self {
        self.relay_nodes.push(address);
        self
    }

    /// Disable mDNS
    pub fn disable_mdns(mut self) -> Self {
        self.enable_mdns = false;
        self
    }

    /// Disable Kademlia
    pub fn disable_kademlia(mut self) -> Self {
        self.enable_kademlia = false;
        self
    }

    /// Disable relay
    pub fn disable_relay(mut self) -> Self {
        self.enable_relay = false;
        self
    }
}

/// Peer discovery event
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// Peer discovered via mDNS
    MdnsDiscovered {
        peer_id: Libp2pPeerId,
        addresses: Vec<Multiaddr>,
    },

    /// Peer expired from mDNS
    MdnsExpired {
        peer_id: Libp2pPeerId,
    },

    /// Peer discovered via Kademlia
    KademliaDiscovered {
        peer_id: Libp2pPeerId,
        addresses: Vec<Multiaddr>,
    },

    /// Relay reservation successful
    RelayReservationAccepted {
        relay_peer_id: Libp2pPeerId,
    },

    /// Relay reservation failed
    RelayReservationFailed {
        relay_peer_id: Libp2pPeerId,
        error: String,
    },
}
