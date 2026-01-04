pub mod swarm;
pub mod discovery;
pub mod protocol;

pub use swarm::{P2PNode, P2PEvent};
pub use discovery::DiscoveryConfig;
pub use protocol::{ChatProtocol, ChatRequest, ChatResponse};
