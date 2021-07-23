use super::UNINITIALIZED_VERSION;
use crate::{utils::EthereumAddress, PROGRAM_VERSION};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{program_pack::IsInitialized, pubkey::Pubkey};

/// Sender account
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub struct SenderAccount {
    /// Version
    pub version: u8,
    /// Reward manager
    pub reward_manager: Pubkey,
    /// Ethereum address
    pub eth_address: EthereumAddress,
    /// Sender operator
    pub operator: EthereumAddress,
}

impl SenderAccount {
    /// The struct size on bytes
    pub const LEN: usize = 73;

    /// Creates new `SenderAccount`
    pub fn new(
        reward_manager: Pubkey,
        eth_address: EthereumAddress,
        operator: EthereumAddress,
    ) -> Self {
        Self {
            version: PROGRAM_VERSION,
            reward_manager,
            eth_address,
            operator,
        }
    }
}

impl IsInitialized for SenderAccount {
    fn is_initialized(&self) -> bool {
        self.version != UNINITIALIZED_VERSION
    }
}
