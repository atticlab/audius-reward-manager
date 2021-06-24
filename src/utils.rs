#![allow(missing_docs)]

use crate::{
    error::{to_audius_program_error, AudiusProgramError},
    instruction::Transfer,
    processor::SENDER_SEED_PREFIX,
    state::SenderAccount,
};
use borsh::BorshDeserialize;
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    instruction::Instruction,
    program::invoke_signed,
    program_error::ProgramError,
    program_pack::IsInitialized,
    pubkey::{Pubkey, PubkeyError},
    secp256k1_program, system_instruction, sysvar,
};
use std::convert::TryInto;

/// Represent compressed ethereum pubkey
pub type EthereumAddress = [u8; 20];

/// Base PDA related with some mint
pub struct Base {
    pub address: Pubkey,
    pub seed: u8,
}

/// Derived account related with some Base and Ethereum address
pub struct Derived {
    pub address: Pubkey,
    pub seed: String,
}

/// Base with related
pub struct AddressPair {
    pub base: Base,
    pub derive: Derived,
}

/// Return `Base` account with seed and corresponding derive
/// with seed
pub fn get_address_pair(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    seeds: &[&[u8]],
) -> Result<AddressPair, PubkeyError> {
    let mut composed = Vec::new();
    for seed in seeds {
        composed.extend_from_slice(seed);
    }

    let (base_pk, base_seed) = get_base_address(program_id, reward_manager);
    let (derived_pk, derive_seed) = get_derived_address(program_id, &base_pk.clone(), composed)?;
    Ok(AddressPair {
        base: Base {
            address: base_pk,
            seed: base_seed,
        },
        derive: Derived {
            address: derived_pk,
            seed: derive_seed,
        },
    })
}

/// Return PDA(that named `Base`) corresponding to specific `reward manager`
/// and it bump seed
pub fn get_base_address(program_id: &Pubkey, reward_manager: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[&reward_manager.to_bytes()[..32]], program_id)
}

/// Return derived token account address corresponding to specific
/// ethereum account and it seed
pub fn get_derived_address(
    program_id: &Pubkey,
    base: &Pubkey,
    seeds: &[u8],
) -> Result<(Pubkey, String), PubkeyError> {
    let eseed = bs58::encode(seeds).into_string();
    Pubkey::create_with_seed(&base, eseed.as_str(), program_id).map(|i| (i, eseed))
}

/// Transfer tokens with program address
#[allow(clippy::too_many_arguments)]
pub fn token_transfer<'a>(
    program_id: &Pubkey,
    reward_manager: &Pubkey,
    source: &AccountInfo<'a>,
    destination: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    amount: u64,
) -> ProgramResult {
    let bump_seed = get_base_address(reward_manager, program_id).1;

    let authority_signature_seeds = [&reward_manager.to_bytes()[..32], &[bump_seed]];
    let signers = &[&authority_signature_seeds[..]];

    let tx = spl_token::instruction::transfer(
        &spl_token::id(),
        source.key,
        destination.key,
        authority.key,
        &[&authority.key],
        amount,
    )?;
    invoke_signed(
        &tx,
        &[source.clone(), destination.clone(), authority.clone()],
        signers,
    )
}

/// Create account with seed signed
#[allow(clippy::too_many_arguments)]
pub fn create_account_with_seed<'a>(
    program_id: &Pubkey,
    funder: &AccountInfo<'a>,
    account_to_create: &AccountInfo<'a>,
    base: &AccountInfo<'a>,
    reward_manager: &Pubkey,
    seed: &[u8],
    required_lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> ProgramResult {
    let bump_seed = get_base_address(program_id, reward_manager).1;

    let signature = &[&reward_manager.to_bytes()[..32], &[bump_seed]];
    invoke_signed(
        &system_instruction::create_account_with_seed(
            &funder.key,
            &account_to_create.key,
            &base.key,
            &bs58::encode(seed).into_string(),
            required_lamports,
            space,
            owner,
        ),
        &[funder.clone(), account_to_create.clone(), base.clone()],
        &[signature],
    )
}

pub fn get_secp_instructions<'a>(
    index_current_instruction: u16,
    necessary_instructions_count: usize,
    instruction_info: &AccountInfo<'a>,
) -> Result<Vec<Instruction>, AudiusProgramError> {
    let mut secp_instructions: Vec<Instruction> = Vec::new();

    for ind in 0..index_current_instruction {
        let instruction = sysvar::instructions::load_instruction_at(
            ind as usize,
            &instruction_info.data.borrow(),
        )
        .map_err(to_audius_program_error)?;

        if instruction.program_id == secp256k1_program::id()
            && !secp_instructions.contains(&instruction)
        {
            secp_instructions.push(instruction);
        }
    }

    if secp_instructions.len() != necessary_instructions_count {
        return Err(AudiusProgramError::Secp256InstructionMissing);
    }

    Ok(secp_instructions)
}

pub fn get_eth_addresses<'a>(
    program_id: &Pubkey,
    reward_manager_key: &Pubkey,
    senders: Vec<&AccountInfo<'a>>,
) -> Result<Vec<EthereumAddress>, ProgramError> {
    let mut senders_eth_addresses: Vec<EthereumAddress> = Vec::new();

    for sender in senders {
        let sender_data = SenderAccount::try_from_slice(&sender.data.borrow())?;
        if !sender_data.is_initialized() {
            return Err(ProgramError::UninitializedAccount);
        }
  
        let generated_sender_key = get_address_pair(
            program_id, 
            reward_manager_key, 
            &[SENDER_SEED_PREFIX.as_ref(), sender_data.eth_address.as_ref()],
        )?;
        if generated_sender_key.derive.address != *sender.key {
            return Err(ProgramError::InvalidSeeds);
        }
        if senders_eth_addresses.contains(&sender_data.eth_address) {
            return Err(AudiusProgramError::RepeatedSenders.into());
        }
        senders_eth_addresses.push(sender_data.eth_address);
    }

    Ok(senders_eth_addresses)
}

pub fn get_signer_from_secp_instruction(secp_instruction_data: Vec<u8>) -> EthereumAddress {
    let eth_address_offset = 12;
    let instruction_signer =
        secp_instruction_data[eth_address_offset..eth_address_offset + 20].to_vec();
    let instruction_signer: EthereumAddress = instruction_signer.as_slice().try_into().unwrap();
    instruction_signer
}

pub fn validate_eth_signature(
    expected_message: &[u8],
    secp_instruction_data: Vec<u8>,
) -> Result<(), ProgramError> {
    //NOTE: meta (12) + address (20) + signature (65) = 97
    let message_data_offset = 97;
    let instruction_message = secp_instruction_data[message_data_offset..].to_vec();
    if instruction_message != *expected_message {
        return Err(AudiusProgramError::SignatureVerificationFailed.into());
    }

    Ok(())
}

pub fn verify_secp_instructions(
    bot_oracle: EthereumAddress,
    senders: Vec<EthereumAddress>,
    secp_instructions: Vec<Instruction>,
    transfer_data: Transfer,
) -> Result<(), ProgramError> {
    let mut successful_verifications = 0;

    let mut bot_oracle_message = Vec::new();
    bot_oracle_message.extend_from_slice(transfer_data.eth_recipient.as_ref());
    bot_oracle_message.extend_from_slice(b"_");
    bot_oracle_message.extend_from_slice(transfer_data.amount.to_le_bytes().as_ref());
    bot_oracle_message.extend_from_slice(b"_");
    bot_oracle_message.extend_from_slice(transfer_data.id.as_ref());

    let mut senders_message = Vec::new();
    senders_message.extend_from_slice(transfer_data.eth_recipient.as_ref());
    senders_message.extend_from_slice(b"_");
    senders_message.extend_from_slice(transfer_data.amount.to_le_bytes().as_ref());
    senders_message.extend_from_slice(b"_");
    senders_message.extend_from_slice(transfer_data.id.as_ref());
    senders_message.extend_from_slice(b"_");
    senders_message.extend_from_slice(bot_oracle.as_ref());

    for instruction in secp_instructions {
        let eth_signer = get_signer_from_secp_instruction(instruction.data.clone());
        if eth_signer == bot_oracle {
            validate_eth_signature(bot_oracle_message.as_ref(), instruction.data.clone())?;
            successful_verifications += 1;
        }
        if senders.contains(&eth_signer) {
            validate_eth_signature(senders_message.as_ref(), instruction.data)?;
            successful_verifications += 1;
        }
    }

    if successful_verifications < senders.len() as u8 {
        return Err(AudiusProgramError::SignatureVerificationFailed.into());
    }

    Ok(())
}
