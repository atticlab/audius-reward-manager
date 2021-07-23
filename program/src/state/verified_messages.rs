use super::UNINITIALIZED_VERSION;
use crate::{utils::EthereumAddress, PROGRAM_VERSION};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{program_pack::IsInitialized, pubkey::Pubkey};

/// Signed payload
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub struct SignedPayload {
    /// Ethereum address
    pub address: EthereumAddress,
    /// Message
    pub message: [u8; 128],
}

/// Verified message (SignedPayload + Operator)
pub type VerifiedMessage = (SignedPayload, EthereumAddress);

/// Verified messages
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub struct VerifiedMessages {
    /// Version
    pub version: u8,
    /// Reward manager
    pub reward_manager: Pubkey,
    /// Messages
    pub messages: Vec<VerifiedMessage>,
}

impl VerifiedMessages {
    /// Creates new `VerifiedMessages`
    pub fn new(reward_manager: Pubkey) -> Self {
        Self {
            version: PROGRAM_VERSION,
            reward_manager,
            messages: vec![],
        }
    }

    /// Add verified message
    pub fn add(&mut self, signed_payload: SignedPayload, operator: EthereumAddress) {
        self.messages.push((signed_payload, operator));
    }
}

impl IsInitialized for VerifiedMessages {
    fn is_initialized(&self) -> bool {
        self.version != UNINITIALIZED_VERSION
    }
}
