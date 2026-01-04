use libp2p::{
    request_response::{self, ProtocolSupport},
    StreamProtocol,
};
use serde::{Deserialize, Serialize};
use crate::crypto::EncryptedMessage;
use crate::identity::PeerId;

/// Custom protocol for direct encrypted messaging
/// Uses request-response pattern instead of GossipSub to avoid metadata leakage
#[derive(Debug, Clone)]
pub struct ChatProtocol;

impl ChatProtocol {
    pub const PROTOCOL_NAME: &'static str = "/darkterm/chat/1.0.0";

    pub fn new() -> Self {
        Self
    }
}

/// Chat request message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChatRequest {
    /// Encrypted message
    Message(EncryptedMessage),

    /// Handshake initiation
    Handshake {
        initiator_peer_id: PeerId,
        handshake_data: Vec<u8>,
    },

    /// Pre-key bundle request
    RequestPreKeyBundle {
        requester_peer_id: PeerId,
    },

    /// Ping for connection testing
    Ping,
}

/// Chat response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChatResponse {
    /// Message acknowledgment
    MessageAck { received: bool },

    /// Handshake response
    HandshakeResponse {
        responder_peer_id: PeerId,
        handshake_data: Vec<u8>,
    },

    /// Pre-key bundle
    PreKeyBundle {
        bundle_data: Vec<u8>,
    },

    /// Pong response
    Pong,

    /// Error
    Error { message: String },
}

/// Codec for CBOR serialization
#[derive(Debug, Clone, Default)]
pub struct ChatCodec;

impl request_response::Codec for ChatCodec {
    type Protocol = StreamProtocol;
    type Request = ChatRequest;
    type Response = ChatResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;

        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;

        serde_cbor::from_slice(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: futures::AsyncRead + Unpin + Send,
    {
        use futures::AsyncReadExt;

        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;

        serde_cbor::from_slice(&buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        use futures::AsyncWriteExt;

        let data = serde_cbor::to_vec(&req)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        io.write_all(&data).await?;
        io.close().await?;

        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> std::io::Result<()>
    where
        T: futures::AsyncWrite + Unpin + Send,
    {
        use futures::AsyncWriteExt;

        let data = serde_cbor::to_vec(&res)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        io.write_all(&data).await?;
        io.close().await?;

        Ok(())
    }
}

/// Create chat protocol behavior
pub fn create_chat_protocol() -> request_response::Behaviour<ChatCodec> {
    let protocols = std::iter::once((StreamProtocol::new(ChatProtocol::PROTOCOL_NAME), ProtocolSupport::Full));
    request_response::Behaviour::new(
        protocols,
        request_response::Config::default(),
    )
}
