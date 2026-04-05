//! WebRTC Signaling Bridge
//! 
//! Provides secure transport of WebRTC negotiation payloads (SDP Offer/Answer
//! and ICE Candidates) over the Sibna Protocol's encrypted channels.

use serde::{Serialize, Deserialize};

/// WebRTC Signaling Message Types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WebRtcSignal {
    /// WebRTC Session Description Protocol (SDP) Offer
    Offer {
        /// The raw SDP string from the local WebRTC engine
        sdp: String,
    },
    /// WebRTC Session Description Protocol (SDP) Answer
    Answer {
        /// The raw SDP string from the answering WebRTC engine
        sdp: String,
    },
    /// Interactive Connectivity Establishment (ICE) Candidate
    IceCandidate {
        /// The ICE candidate string
        candidate: String,
        /// The media stream identification
        sdp_mid: String,
        /// The zero-based index of the media description
        sdp_m_line_index: u16,
    },
    /// Hangup / Disconnect signal
    Hangup,
}

/// The inner payload wrapper that distinguishes between standard messages and media signaling
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProtocolPayload {
    /// Standard application data
    Data(Vec<u8>),
    /// WebRTC Negotiation Signaling
    WebRtc(WebRtcSignal),
}

impl ProtocolPayload {
    /// Serialize payload to raw bytes for the encryptor
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::ProtocolError> {
        bincode::serialize(self).map_err(|_| crate::error::ProtocolError::InvalidMessage)
    }

    /// Deserialize payload from a decrypted byte stream
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::error::ProtocolError> {
        bincode::deserialize(data).map_err(|_| crate::error::ProtocolError::InvalidMessage)
    }
}
