#![cfg(feature = "test-bpf")]
mod utils;
use audius_reward_manager::{
    instruction,
    processor::SENDER_SEED_PREFIX,
    state::{RewardManager, SenderAccount},
    utils::get_address_pair,
};
use borsh::BorshSerialize;
use solana_program::{program_pack::Pack, pubkey::Pubkey, rent::Rent, system_instruction, instruction::Instruction,};
use solana_program_test::*;
use solana_sdk::{
    account::Account, signature::Keypair, signer::Signer, transaction::Transaction,
    transport::TransportError,
    secp256k1_instruction::*,
};
use utils::program_test;
use rand::{thread_rng, Rng};
use secp256k1::{PublicKey, SecretKey, Message};
use sha3::Digest;
use serde_derive::{Deserialize, Serialize};

#[tokio::test]
async fn transfer_test() {
    let mut program_test = program_test();
    let mut context = program_test.start_with_context().await;

    let mint = Keypair::new();
    let mint_authority = Keypair::new();

    let token_account = Keypair::new();
    let reward_manager = Keypair::new();
    let manager_account = Keypair::new();

    let rent = context.banks_client.get_rent().await.unwrap();

    create_mint(
        &mut context,
        &mint,
        rent.minimum_balance(spl_token::state::Mint::LEN),
        &mint_authority.pubkey(),
    )
    .await
    .unwrap();

    init_reward_manager(
        &mut context,
        &reward_manager,
        &token_account,
        &mint.pubkey(),
        &manager_account.pubkey(),
        2,
    )
    .await;

    let mut rng = thread_rng();
    let key: [u8; 32] = rng.gen();
    let sender_priv_key = SecretKey::parse(&key).unwrap();
    let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
    let eth_address_1 = construct_eth_pubkey(&secp_pubkey);
    let mut seed = Vec::new();
    seed.extend_from_slice(&eth_address_1.as_ref());
    seed.extend_from_slice(SENDER_SEED_PREFIX.as_ref());

    let first_sender = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager.pubkey(),
        seed.as_ref(),
    )
    .unwrap();
    create_sender(&mut context, &reward_manager.pubkey(), &manager_account, eth_address_1).await;

    let mut rng = thread_rng();
    let key: [u8; 32] = rng.gen();
    let oracle_priv_key = SecretKey::parse(&key).unwrap();
    let secp_pubkey = PublicKey::from_secret_key(&oracle_priv_key);
    let eth_address_2 = construct_eth_pubkey(&secp_pubkey);
    let mut seed = Vec::new();
    seed.extend_from_slice(&eth_address_2.as_ref());
    seed.extend_from_slice(SENDER_SEED_PREFIX.as_ref());

    let second_sender = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager.pubkey(),
        seed.as_ref(),
    )
    .unwrap();
    create_sender(&mut context, &reward_manager.pubkey(), &manager_account, eth_address_2).await;

    let tokens_amount = 10_000;

    mint_tokens_to(
        &mut context,
        &mint.pubkey(),
        &token_account.pubkey(),
        &mint_authority,
        tokens_amount,
    )
    .await
    .unwrap();

    let recipient_eth_key = [7u8; 20];
    let mut seed = Vec::new();
    seed.extend_from_slice(&recipient_eth_key.as_ref());
    let recipient_sol_key = get_address_pair(&claimable_tokens::id(), &mint.pubkey(), seed.as_ref()).unwrap();
    create_recipient_with_claimable_program(&mut context, &mint.pubkey(), recipient_eth_key).await;

    let transfer_id = "4r4t23df32543f55";

    let mut senders_message = Vec::new();
    senders_message.extend_from_slice(recipient_eth_key.as_ref());
    senders_message.extend_from_slice(b"_");
    senders_message.extend_from_slice(tokens_amount.to_le_bytes().as_ref());
    senders_message.extend_from_slice(b"_");
    senders_message.extend_from_slice(transfer_id.as_ref());
    senders_message.extend_from_slice(b"_");
    senders_message.extend_from_slice(eth_address_2.as_ref());

    let mut bot_oracle_message = Vec::new();
    bot_oracle_message.extend_from_slice(recipient_eth_key.as_ref());
    bot_oracle_message.extend_from_slice(b"_");
    bot_oracle_message.extend_from_slice(tokens_amount.to_le_bytes().as_ref());
    bot_oracle_message.extend_from_slice(b"_");
    bot_oracle_message.extend_from_slice(transfer_id.as_ref());

    // let sender_secp256_program_instruction = new_secp256k1_instruction(&sender_priv_key, senders_message.as_ref());
    // let oracle_secp256_program_instruction = new_secp256k1_instruction(&oracle_priv_key, bot_oracle_message.as_ref());

    let secp_instruction = custom_secp256k1_instruction(vec![&sender_priv_key, &oracle_priv_key], vec![senders_message.as_ref(), bot_oracle_message.as_ref()]);

    let tx = Transaction::new_signed_with_payer(
        &[
            secp_instruction,
            instruction::transfer(
                &audius_reward_manager::id(),
                &reward_manager.pubkey(),
                &recipient_sol_key.derive.address,
                &token_account.pubkey(),
                &second_sender.derive.address,
                &context.payer.pubkey(),
                vec![first_sender.derive.address,],
                instruction::Transfer{amount: tokens_amount, id: String::from(transfer_id), eth_recipient: recipient_eth_key},
            ).unwrap(),
        ],
        Some(&context.payer.pubkey()),
        &[&context.payer,],
        context.last_blockhash,);
    context.banks_client.process_transaction(tx).await.unwrap();
}

fn custom_secp256k1_instruction(priv_keys: Vec<&secp256k1::SecretKey>, messages: Vec<&[u8]>) -> Instruction {
    let mut final_instruction_data: Vec<u8> = vec![];
    
    assert_eq!(priv_keys.len(), messages.len());

    final_instruction_data.push(priv_keys.len() as u8);  // set number of signatures

    for (index, key) in priv_keys.iter().enumerate() {
        let secp_pubkey = PublicKey::from_secret_key(key);
        let eth_pubkey = construct_eth_pubkey(&secp_pubkey);
        let mut hasher = sha3::Keccak256::new();
        hasher.update(messages[index]);
        let message_hash = hasher.finalize();
        let mut message_hash_arr = [0u8; 32];
        message_hash_arr.copy_from_slice(message_hash.as_slice());
        let message = Message::parse(&message_hash_arr);
        let (signature, recovery_id) = secp256k1::sign(&message, key);
        let signature_arr = signature.serialize();

        let mut instruction_data = vec![];
        instruction_data.resize(
            DATA_START
                .saturating_add(eth_pubkey.len())
                .saturating_add(signature_arr.len())
                .saturating_add(messages[index].len())
                .saturating_add(1),
            0,
        );

        let mut eth_address_offset = DATA_START;
        instruction_data[eth_address_offset..eth_address_offset.saturating_add(eth_pubkey.len())]
            .copy_from_slice(&eth_pubkey);

        let mut signature_offset = DATA_START.saturating_add(eth_pubkey.len());
        instruction_data[signature_offset..signature_offset.saturating_add(signature_arr.len())]
            .copy_from_slice(&signature_arr);
        
        instruction_data[signature_offset.saturating_add(signature_arr.len())] =
            recovery_id.serialize();
        
        let mut message_data_offset = signature_offset
            .saturating_add(signature_arr.len())
            .saturating_add(1);
        instruction_data[message_data_offset..].copy_from_slice(messages[index]);

        if index > 0 {
            signature_offset = final_instruction_data.len().saturating_add(SIGNATURE_OFFSETS_SERIALIZED_SIZE).saturating_add(eth_pubkey.len());
            eth_address_offset = final_instruction_data.len().saturating_add(SIGNATURE_OFFSETS_SERIALIZED_SIZE);
            message_data_offset = signature_offset
                .saturating_add(signature_arr.len())
                .saturating_add(1);
        }

        let offsets = SecpSignatureOffsets {
            signature_offset: signature_offset as u16,
            signature_instruction_index: index as u8,
            eth_address_offset: eth_address_offset as u16,
            eth_address_instruction_index: index as u8,
            message_data_offset: message_data_offset as u16,
            message_data_size: messages[index].len() as u16,
            message_instruction_index: index as u8,
        };

        let writer = std::io::Cursor::new(&mut instruction_data[1..DATA_START]);
        bincode::serialize_into(writer, &offsets).unwrap();

        final_instruction_data.append(&mut instruction_data);
    }

    Instruction {
        program_id: solana_sdk::secp256k1_program::id(),
        accounts: vec![],
        data: final_instruction_data,
    }
}

async fn create_sender(
    context: &mut ProgramTestContext,
    reward_manager: &Pubkey,
    manager_acc: &Keypair,
    eth_address: [u8; 20]
) {
    let tx = Transaction::new_signed_with_payer(
        &[instruction::create_sender(
            &audius_reward_manager::id(),
            reward_manager,
            &manager_acc.pubkey(),
            &context.payer.pubkey(),
            eth_address,
        )
        .unwrap()],
        Some(&context.payer.pubkey()),
        &[&context.payer, manager_acc],
        context.last_blockhash,
    );

    context.banks_client.process_transaction(tx).await.unwrap();
}

async fn init_reward_manager(
    context: &mut ProgramTestContext,
    reward_manager: &Keypair,
    token_account: &Keypair,
    mint: &Pubkey,
    manager: &Pubkey,
    min_votes: u8,
) {
    let rent = context.banks_client.get_rent().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[
            system_instruction::create_account(
                &context.payer.pubkey(),
                &reward_manager.pubkey(),
                rent.minimum_balance(audius_reward_manager::state::RewardManager::LEN),
                audius_reward_manager::state::RewardManager::LEN as _,
                &audius_reward_manager::id(),
            ),
            system_instruction::create_account(
                &context.payer.pubkey(),
                &token_account.pubkey(),
                rent.minimum_balance(spl_token::state::Account::LEN),
                spl_token::state::Account::LEN as _,
                &spl_token::id(),
            ),
            instruction::init(
                &audius_reward_manager::id(),
                &reward_manager.pubkey(),
                &token_account.pubkey(),
                mint,
                &manager,
                min_votes,
            )
            .unwrap(),
        ],
        Some(&context.payer.pubkey()),
        &[&context.payer, reward_manager, token_account],
        context.last_blockhash,
    );

    context.banks_client.process_transaction(tx).await.unwrap();
}

pub async fn create_mint(
    program_context: &mut ProgramTestContext,
    mint_account: &Keypair,
    mint_rent: u64,
    authority: &Pubkey,
) -> Result<(), TransportError> {
    let instructions = vec![
        system_instruction::create_account(
            &program_context.payer.pubkey(),
            &mint_account.pubkey(),
            mint_rent,
            spl_token::state::Mint::LEN as u64,
            &spl_token::id(),
        ),
        spl_token::instruction::initialize_mint(
            &spl_token::id(),
            &mint_account.pubkey(),
            authority,
            None,
            0,
        )
        .unwrap(),
    ];

    let mut transaction =
        Transaction::new_with_payer(&instructions, Some(&program_context.payer.pubkey()));

    transaction.sign(
        &[&program_context.payer, mint_account],
        program_context.last_blockhash,
    );
    program_context
        .banks_client
        .process_transaction(transaction)
        .await?;
    Ok(())
}

pub async fn create_token_account(
    program_context: &mut ProgramTestContext,
    account: &Keypair,
    mint: &Pubkey,
    owner: &Pubkey,
    rent: &Rent,
) -> Result<(), TransportError> {
    let account_rent = rent.minimum_balance(spl_token::state::Account::LEN);

    let instructions = vec![
        system_instruction::create_account(
            &program_context.payer.pubkey(),
            &account.pubkey(),
            account_rent,
            spl_token::state::Account::LEN as u64,
            &spl_token::id(),
        ),
        spl_token::instruction::initialize_account(
            &spl_token::id(),
            &account.pubkey(),
            mint,
            owner,
        )
        .unwrap(),
    ];

    let mut transaction =
        Transaction::new_with_payer(&instructions, Some(&program_context.payer.pubkey()));

    transaction.sign(
        &[&program_context.payer, account],
        program_context.last_blockhash,
    );
    program_context
        .banks_client
        .process_transaction(transaction)
        .await?;
    Ok(())
}

pub async fn mint_tokens_to(
    program_context: &mut ProgramTestContext,
    mint: &Pubkey,
    destination: &Pubkey,
    authority: &Keypair,
    amount: u64,
) -> Result<(), TransportError> {
    let mut transaction = Transaction::new_with_payer(
        &[spl_token::instruction::mint_to(
            &spl_token::id(),
            mint,
            destination,
            &authority.pubkey(),
            &[&authority.pubkey()],
            amount,
        )
        .unwrap()],
        Some(&program_context.payer.pubkey()),
    );
    transaction.sign(
        &[&program_context.payer, authority],
        program_context.last_blockhash,
    );
    program_context
        .banks_client
        .process_transaction(transaction)
        .await?;
    Ok(())
}

async fn create_recipient_with_claimable_program(
    program_context: &mut ProgramTestContext,
    mint: &Pubkey,
    eth_address: [u8; 20],
) {
    let mut transaction = Transaction::new_with_payer(
        &[claimable_tokens::instruction::init(
            &claimable_tokens::id(),
            &program_context.payer.pubkey(),
            mint,
            claimable_tokens::instruction::CreateTokenAccount { eth_address },
        )
        .unwrap()],
        Some(&program_context.payer.pubkey()),
    );
    transaction.sign(&[&program_context.payer], program_context.last_blockhash);
    program_context
        .banks_client
        .process_transaction(transaction)
        .await
        .unwrap();
}
