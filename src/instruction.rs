//! Instruction types

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
    system_program, sysvar,
};

use crate::{
    processor::{SENDER_SEED_PREFIX, TRANSFER_SEED_PREFIX},
    utils::{get_address_pair, get_base_address, EthereumAddress},
};
/// `Transfer` instruction parameters
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub struct Transfer {
    /// Amount to transfer
    pub amount: u64,
    /// ID generated on backend
    pub id: String,
    /// Recipient's Eth address
    pub eth_recipient: EthereumAddress,
}

/// Instruction definition
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub enum Instructions {
    ///   Initialize `Reward Manager`
    ///
    ///   0. `[w]` Account that will be initialized as `Reward Manager`.
    ///   1. `[w]` The new account that to be initialized as the token account.
    ///   2. `[]`  Mint with which the new token account will be associated on initialization.
    ///   3. `[]`  Manager account to be set as the `Reward Manager`.
    ///   4. `[]`  `Reward Manager` authority.
    ///   5. `[]`  Token program
    ///   6. `[]`  Rent sysvar
    InitRewardManager {
        /// Number of signer votes required for sending rewards
        min_votes: u8,
    },

    ///   Admin method creating new authorized sender
    ///
    ///   0. `[]`  `Reward Manager`
    ///   1. `[s]` Manager account
    ///   2. `[]`  `Reward Manager` authority
    ///   3. `[]`  Funder account
    ///   4. `[]`  Addidable sender
    ///   5. `[]`  System program id
    ///   6. `[]`  Rent sysvar
    CreateSender {
        /// Ethereum address
        eth_address: EthereumAddress,
        /// Sender operator
        operator: EthereumAddress,
    },

    ///   Admin method removing sender
    ///  
    ///   0. `[]`   `Reward Manager`
    ///   1. `[s]`  Manager account
    ///   2. `[]`   `Reward Manager` authority
    ///   3. `[w]`  Removed sender
    ///   4. `[]`   Refunder account
    DeleteSender,

    ///
    ///
    /// 0. `[r]`  reward_manager
    /// 1. `[r]`  `Reward Manager` authority
    /// 2. `[ws]` funder
    /// 3. `[w]`  new_sender
    /// 4. `[r]`  old_sender_0
    /// ... Bunch of old senders which prove adding new one
    /// n. `[r]`  old_sender_n
    AddSender {
        /// Ethereum address
        eth_address: EthereumAddress,
        /// Sender operator
        operator: EthereumAddress,
    },

    ///   Transfer tokens to pointed receiver
    ///
    ///   0. `[]` `Reward Manager`
    ///   1. `[]` `Reward Manager` authority. Program account
    ///   2. `[w]` Recipient. Key generated from Eth address
    ///   3. `[w]` Vault with all the "reward" tokens. Program is authority
    ///   4. `[]` Bot oracle
    ///   5. `[sw]` Funder. Account which pay for new account creation
    ///   6. `[w]` Transfer account to create
    ///   7. `[]` Sysvar instruction id
    ///   8. `[]` SPL Token id
    ///   9. `[]` System program
    ///   10. `[]` Senders
    ///   ...
    ///   n. `[]`
    Transfer {
        /// Amount to transfer
        amount: u64,
        /// ID generated on backend
        id: String,
        /// Recipient's Eth address
        eth_recipient: EthereumAddress,
    },
}

/// Create `InitRewardManager` instruction
pub fn init(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    token_account: &Pubkey,
    mint: &Pubkey,
    manager: &Pubkey,
    min_votes: u8,
) -> Result<Instruction, ProgramError> {
    let init_data = Instructions::InitRewardManager { min_votes };
    let data = init_data.try_to_vec()?;

    let (base, _) = get_base_address(program_id, reward_manager);

    let accounts = vec![
        AccountMeta::new(*reward_manager, false),
        AccountMeta::new(*token_account, false),
        AccountMeta::new_readonly(*mint, false),
        AccountMeta::new_readonly(*manager, false),
        AccountMeta::new_readonly(base, false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
    ];
    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Create `CreateSender` instruction
pub fn create_sender(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    manager_account: &Pubkey,
    funder_account: &Pubkey,
    eth_address: EthereumAddress,
    operator: EthereumAddress,
) -> Result<Instruction, ProgramError> {
    let create_data = Instructions::CreateSender {
        eth_address,
        operator,
    };
    let data = create_data.try_to_vec()?;

    let pair = get_address_pair(
        program_id,
        reward_manager,
        [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
    )?;

    let accounts = vec![
        AccountMeta::new_readonly(*reward_manager, false),
        AccountMeta::new_readonly(*manager_account, true),
        AccountMeta::new_readonly(pair.base.address, false),
        AccountMeta::new(*funder_account, true),
        AccountMeta::new(pair.derive.address, false),
        AccountMeta::new_readonly(system_program::id(), false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Create `DeleteSender` instruction
pub fn delete_sender(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    manager_account: &Pubkey,
    refunder_account: &Pubkey,
    eth_address: EthereumAddress,
) -> Result<Instruction, ProgramError> {
    let delete_data = Instructions::DeleteSender;
    let data = delete_data.try_to_vec()?;

    let pair = get_address_pair(
        program_id,
        reward_manager,
        [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
    )?;

    let accounts = vec![
        AccountMeta::new_readonly(*reward_manager, false),
        AccountMeta::new_readonly(*manager_account, true),
        AccountMeta::new(pair.derive.address, false),
        AccountMeta::new(*refunder_account, false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Create `AddSender` instruction
pub fn add_sender<'a, I>(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    funder: &Pubkey,
    eth_address: EthereumAddress,
    operator: EthereumAddress,
    signers: I,
) -> Result<Instruction, ProgramError>
where
    I: IntoIterator<Item = &'a Pubkey>,
{
    let data = Instructions::AddSender {
        eth_address,
        operator,
    }
    .try_to_vec()?;

    let pair = get_address_pair(
        program_id,
        reward_manager,
        [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
    )?;

    let mut accounts = vec![
        AccountMeta::new_readonly(*reward_manager, false),
        AccountMeta::new_readonly(pair.base.address, false),
        AccountMeta::new(*funder, false),
        AccountMeta::new(pair.derive.address, false),
        AccountMeta::new_readonly(sysvar::instructions::id(), false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
    ];
    let iter = signers
        .into_iter()
        .map(|i| AccountMeta::new_readonly(*i, true));
    accounts.extend(iter);

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Create `Transfer` instruction
pub fn transfer<I>(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    recipient: &Pubkey,
    vault_token_account: &Pubkey,
    bot_oracle: &Pubkey,
    funder: &Pubkey,
    senders: I,
    params: Transfer,
) -> Result<Instruction, ProgramError>
where
    I: IntoIterator<Item = Pubkey>,
{
    let data = Instructions::Transfer {
        amount: params.amount,
        id: params.id.clone(),
        eth_recipient: params.eth_recipient,
    }
    .try_to_vec()?;

    let transfer_acc_to_create = get_address_pair(
        program_id,
        reward_manager,
        [TRANSFER_SEED_PREFIX.as_bytes().as_ref(), params.id.as_ref()].concat(),
    )?;

    let mut accounts = vec![
        AccountMeta::new_readonly(*reward_manager, false),
        AccountMeta::new_readonly(transfer_acc_to_create.base.address, false),
        AccountMeta::new(*recipient, false),
        AccountMeta::new(*vault_token_account, false),
        AccountMeta::new_readonly(*bot_oracle, false),
        AccountMeta::new(*funder, true),
        AccountMeta::new(transfer_acc_to_create.derive.address, false),
        AccountMeta::new_readonly(sysvar::instructions::id(), false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];
    let iter = senders
        .into_iter()
        .map(|i| AccountMeta::new_readonly(i, false));
    accounts.extend(iter);

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}
