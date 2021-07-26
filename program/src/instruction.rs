//! Instruction types

use crate::{
    processor::{SENDER_SEED_PREFIX, TRANSFER_SEED_PREFIX},
    state::SignedPayload,
    utils::{get_address_pair, get_base_address, EthereumAddress},
};
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    instruction::{AccountMeta, Instruction},
    program_error::ProgramError,
    pubkey::Pubkey,
    system_program, sysvar,
};

/// `InitRewardManager` instruction args
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub struct InitRewardManagerArgs {
    /// Number of signer votes required for sending rewards
    pub min_votes: u8,
}

/// `CreateSender` instruction args
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub struct CreateSenderArgs {
    /// Ethereum address
    pub eth_address: EthereumAddress,
    /// Sender operator
    pub operator: EthereumAddress,
}

/// `AddSender` instruction args
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub struct AddSenderArgs {
    /// Ethereum address
    pub eth_address: EthereumAddress,
    /// Sender operator
    pub operator: EthereumAddress,
}

/// `Transfer` instruction args
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub struct TransferArgs {
    /// Amount to transfer
    pub amount: u64,
    /// ID generated on backend
    pub id: String,
    /// Recipient's Eth address
    pub eth_recipient: EthereumAddress,
}

/// `VerifyTransferSignature` instruction args
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub struct VerifyTransferSignatureArgs {
    /// Signed payload
    pub signed_payload: SignedPayload,
}

/// Instruction definition
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub enum Instructions {
    ///   Initialize Reward manager
    ///
    ///   0. `[writable]` Account that will be initialized as Reward manager.
    ///   1. `[writable]` The new account that to be initialized as the token account.
    ///   2. `[]` Mint with which the new token account will be associated on initialization.
    ///   3. `[]` Manager account to be set as the Reward manager.
    ///   4. `[]` Reward manager authority.
    ///   5. `[]` Token program
    ///   6. `[]` Rent sysvar
    InitRewardManager(InitRewardManagerArgs),

    ///   Admin method creating new authorized sender
    ///
    ///   0. `[]` Reward manager
    ///   1. `[signer]` Manager account
    ///   2. `[]` Reward manager authority
    ///   3. `[]` Funder account
    ///   4. `[]` Addidable sender
    ///   5. `[]` System program id
    ///   6. `[]` Rent sysvar
    CreateSender(CreateSenderArgs),

    ///   Admin method removing sender
    ///  
    ///   0. `[]` Reward manager
    ///   1. `[signer]` Manager account
    ///   2. `[]` Reward manager authority
    ///   3. `[writable]` Removed sender
    ///   4. `[]` Refunder account
    DeleteSender,

    ///
    ///
    /// 0. `[]` Reward manager
    /// 1. `[]` Reward manager authority
    /// 2. `[signer]` Funder
    /// 3. `[writable]` new_sender
    /// 4. `[]` Bunch of old senders which prove adding new one
    /// ...
    AddSender(AddSenderArgs),

    ///   Verify transfer signature
    ///
    ///   0. `[writable]` New or existing account storing verified messages
    ///   1. `[]` Reward manager
    ///   2. `[]` Sender
    ///   3. `[signer]` Funder. Account which pay for new account creation
    ///   4. `[writable]` Transfer account to create
    ///   5. `[]` Sysvar instruction id
    ///   7. `[]` System program
    VerifyTransferSignature(VerifyTransferSignatureArgs),

    ///   Transfer tokens to pointed receiver
    ///
    ///   0. `[]` Verified messages
    ///   1. `[]` Reward manager
    ///   2. `[]` Reward manager authority
    ///   3. `[]` Reward token source
    ///   4. `[]` Reward token recipient
    ///   5. `[]` Transfer account
    ///   6. `[]` Bot oracle
    ///   7. `[]` Payer
    ///   8. `[]` Sysvar rent
    ///   9. `[]` Token program id
    ///  10. `[]` System program id
    Transfer(TransferArgs),
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
    let init_data = Instructions::InitRewardManager(InitRewardManagerArgs { min_votes });
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
    let create_data = Instructions::CreateSender(CreateSenderArgs {
        eth_address,
        operator,
    });
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
    let data = Instructions::AddSender(AddSenderArgs {
        eth_address,
        operator,
    })
    .try_to_vec()?;

    let pair = get_address_pair(
        program_id,
        reward_manager,
        [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
    )?;

    let mut accounts = vec![
        AccountMeta::new_readonly(*reward_manager, false),
        AccountMeta::new_readonly(pair.base.address, false),
        AccountMeta::new(*funder, true),
        AccountMeta::new(pair.derive.address, false),
        AccountMeta::new_readonly(sysvar::instructions::id(), false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];
    let iter = signers
        .into_iter()
        .map(|i| AccountMeta::new_readonly(*i, false));
    accounts.extend(iter);

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Create `VerifyTransferSignature` instruction
pub fn verify_transfer_signature(
    program_id: &Pubkey,
    verified_messages: &Pubkey,
    reward_manager: &Pubkey,
    sender: &Pubkey,
    funder: &Pubkey,
    signed_payload: SignedPayload,
) -> Result<Instruction, ProgramError> {
    let data =
        Instructions::VerifyTransferSignature(VerifyTransferSignatureArgs { signed_payload })
            .try_to_vec()?;

    let accounts = vec![
        AccountMeta::new(*verified_messages, false),
        AccountMeta::new_readonly(*reward_manager, false),
        AccountMeta::new_readonly(*sender, false),
        AccountMeta::new(*funder, true),
        AccountMeta::new_readonly(sysvar::instructions::id(), false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}

/// Create `Transfer` instruction
#[allow(clippy::too_many_arguments)]
pub fn transfer(
    program_id: &Pubkey,
    verified_messages: &Pubkey,
    reward_manager: &Pubkey,
    reward_token_source: &Pubkey,
    reward_token_recipient: &Pubkey,
    bot_oracle: &Pubkey,
    payer: &Pubkey,
    amount: u64,
    id: String,
    eth_recipient: [u8; 20],
) -> Result<Instruction, ProgramError> {
    let data = Instructions::Transfer(TransferArgs {
        amount,
        id: id.clone(),
        eth_recipient,
    })
    .try_to_vec()?;

    let transfer_account = get_address_pair(
        program_id,
        reward_manager,
        [TRANSFER_SEED_PREFIX.as_bytes().as_ref(), id.as_ref()].concat(),
    )?;

    let accounts = vec![
        AccountMeta::new_readonly(*verified_messages, false),
        AccountMeta::new_readonly(*reward_manager, false),
        AccountMeta::new_readonly(transfer_account.base.address, false),
        AccountMeta::new(*reward_token_source, false),
        AccountMeta::new(*reward_token_recipient, false),
        AccountMeta::new(transfer_account.derive.address, false),
        AccountMeta::new_readonly(*bot_oracle, false),
        AccountMeta::new_readonly(*payer, true),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
        AccountMeta::new_readonly(spl_token::id(), false),
        AccountMeta::new_readonly(system_program::id(), false),
    ];

    Ok(Instruction {
        program_id: *program_id,
        accounts,
        data,
    })
}
