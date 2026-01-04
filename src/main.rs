mod error;
mod identity;
mod crypto;
mod state;
mod network;
mod ui;

use tracing::{info, error, warn};
use tracing_subscriber::{EnvFilter, fmt};

use crate::error::Result;
use crate::identity::{Identity, keystore::Keystore};
use crate::network::{P2PNode, DiscoveryConfig};
use crate::state::StateManager;
use crate::ui::{TerminalUI, UIEvent, terminal::DisplayMessage};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info"))
        )
        .init();

    info!("Starting DarkTerm - Encrypted P2P Terminal Messenger");

    // Initialize keystore and load/create identity
    let keystore = Keystore::new()?;
    let identity = keystore.load_or_create_identity()?;

    info!("Identity loaded: {}", identity.peer_id());
    info!("Fingerprint: {} (verify this with your peers!)", identity.fingerprint());

    // Load trust database
    let trust_db = keystore.load_trust_db()?;

    // Initialize state manager
    let state_dir = keystore.path().join("state");
    let pickle_key = [0u8; 32]; // In production, derive this from user password or identity
    let state_manager = StateManager::new(state_dir, pickle_key)?;

    // Initialize P2P network
    let discovery_config = DiscoveryConfig::new();
    let (mut p2p_node, p2p_event_rx) = P2PNode::new(&identity, discovery_config).await?;

    info!("P2P node initialized: {}", p2p_node.local_peer_id());

    // Start listening
    p2p_node.listen(0)?; // Let OS choose port

    // Spawn P2P event loop
    let p2p_handle = tokio::spawn(async move {
        if let Err(e) = p2p_node.run().await {
            error!("P2P node error: {}", e);
        }
    });

    // Initialize terminal UI
    let ui = TerminalUI::new();
    let (ui_msg_tx, ui_msg_rx) = tokio::sync::mpsc::unbounded_channel();

    // Start UI
    let ui_event_rx = ui.run(ui_msg_rx).await?;

    // Main event loop
    run_event_loop(
        identity,
        trust_db,
        keystore,
        state_manager,
        p2p_event_rx,
        ui_event_rx,
        ui_msg_tx,
    ).await?;

    // Wait for P2P node to finish
    let _ = p2p_handle.await;

    info!("DarkTerm shut down gracefully");
    Ok(())
}

/// Main event loop coordinating P2P and UI events
async fn run_event_loop(
    identity: Identity,
    mut trust_db: identity::keystore::TrustDb,
    keystore: Keystore,
    state_manager: StateManager,
    mut p2p_event_rx: tokio::sync::mpsc::UnboundedReceiver<network::P2PEvent>,
    mut ui_event_rx: tokio::sync::mpsc::UnboundedReceiver<UIEvent>,
    ui_msg_tx: tokio::sync::mpsc::UnboundedSender<DisplayMessage>,
) -> Result<()> {
    loop {
        tokio::select! {
            // Handle P2P events
            Some(p2p_event) = p2p_event_rx.recv() => {
                handle_p2p_event(
                    p2p_event,
                    &identity,
                    &mut trust_db,
                    &keystore,
                    &state_manager,
                    &ui_msg_tx,
                ).await?;
            }

            // Handle UI events
            Some(ui_event) = ui_event_rx.recv() => {
                match ui_event {
                    UIEvent::Quit => {
                        info!("User requested quit");
                        break;
                    }

                    UIEvent::SendMessage(message) => {
                        info!("User wants to send message: {}", message);
                        // In a full implementation, this would send via P2P
                    }

                    UIEvent::AddPeer(peer_info) => {
                        info!("User wants to add peer: {}", peer_info);
                        // In a full implementation, this would parse and dial the peer
                    }

                    _ => {}
                }
            }

            else => {
                break;
            }
        }
    }

    Ok(())
}

/// Handle P2P network events
async fn handle_p2p_event(
    event: network::P2PEvent,
    identity: &Identity,
    trust_db: &mut identity::keystore::TrustDb,
    keystore: &Keystore,
    state_manager: &StateManager,
    ui_msg_tx: &tokio::sync::mpsc::UnboundedSender<DisplayMessage>,
) -> Result<()> {
    use network::P2PEvent;

    match event {
        P2PEvent::PeerDiscovered { peer_id, addresses } => {
            info!("Peer discovered: {} at {:?}", peer_id, addresses);
        }

        P2PEvent::ConnectionEstablished { peer_id, endpoint } => {
            info!("Connection established: {} via {}", peer_id, endpoint);
        }

        P2PEvent::IncomingRequest { peer_id, request, channel } => {
            info!("Incoming request from peer: {}", peer_id);

            // In a full implementation, handle different request types
            // For now, just acknowledge
        }

        P2PEvent::ResponseReceived { peer_id, response } => {
            info!("Response received from peer: {}", peer_id);
        }

        P2PEvent::NewListenAddr { address } => {
            info!("Listening on new address: {}", address);
        }

        _ => {}
    }

    Ok(())
}
