#![cfg(feature = "test-bpf")]
mod assert;
mod utils;
use std::mem::MaybeUninit;

use assert::*;
use audius_reward_manager::{
    error::AudiusProgramError,
    instruction,
    processor::{
        SENDER_SEED_PREFIX, TRANSFER_ACC_BALANCE, TRANSFER_ACC_SPACE, TRANSFER_SEED_PREFIX,
    },
    utils::{get_address_pair, EthereumAddress},
};
use num_traits::FromPrimitive;
use rand::{thread_rng, Rng};
use secp256k1::{PublicKey, SecretKey};
use solana_program::{instruction::Instruction, program_pack::Pack, pubkey::Pubkey};
use solana_program_test::*;
use solana_sdk::{
    instruction::InstructionError,
    secp256k1_instruction::*,
    signature::Keypair,
    signer::Signer,
    system_instruction::SystemError,
    transaction::{Transaction, TransactionError},
    transport::TransportError,
};
use utils::*;

#[tokio::test]
async fn transfer_test() {
    let mut program_test = program_test();
    program_test.add_program("claimable_tokens", claimable_tokens::id(), None);
    let mut rng = thread_rng();

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
        3 as u8,
    )
    .await;

    // Generate data and create oracle
    let key: [u8; 32] = rng.gen();
    let oracle_priv_key = SecretKey::parse(&key).unwrap();
    let secp_oracle_pubkey = PublicKey::from_secret_key(&oracle_priv_key);
    let eth_oracle_address = construct_eth_pubkey(&secp_oracle_pubkey);
    let oracle_operator: EthereumAddress = rng.gen();

    let oracle = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager.pubkey(),
        [SENDER_SEED_PREFIX.as_ref(), eth_oracle_address.as_ref()].concat(),
    )
    .unwrap();
    create_sender(
        &mut context,
        &reward_manager.pubkey(),
        &manager_account,
        eth_oracle_address,
        oracle_operator,
    )
    .await;

    // Generate data and create senders
    let keys: [[u8; 32]; 3] = rng.gen();
    let operators: [EthereumAddress; 3] = rng.gen();
    let mut signers: [Pubkey; 3] = unsafe { MaybeUninit::zeroed().assume_init() };
    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);

        let pair = get_address_pair(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
        )
        .unwrap();

        signers[item.0] = pair.derive.address;
    }

    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);
        create_sender(
            &mut context,
            &reward_manager.pubkey(),
            &manager_account,
            eth_address,
            operators[item.0],
        )
        .await;
    }

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
    let recipient_sol_key = claimable_tokens::utils::program::get_address_pair(
        &claimable_tokens::id(),
        &mint.pubkey(),
        recipient_eth_key,
    )
    .unwrap();
    create_recipient_with_claimable_program(&mut context, &mint.pubkey(), recipient_eth_key).await;

    let transfer_id = "4r4t23df32543f55";

    let senders_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
        b"_",
        eth_oracle_address.as_ref(),
    ]
    .concat();

    let bot_oracle_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
    ]
    .concat();

    let mut instructions = Vec::<Instruction>::new();

    let oracle_sign =
        new_secp256k1_instruction_2_0(&oracle_priv_key, bot_oracle_message.as_ref(), 0);
    instructions.push(oracle_sign);

    let iter = keys.iter().enumerate().map(|i| (i.0 + 1, i.1));
    for item in iter {
        let priv_key = SecretKey::parse(item.1).unwrap();
        let inst = new_secp256k1_instruction_2_0(&priv_key, senders_message.as_ref(), item.0 as _);
        instructions.push(inst);
    }

    instructions.push(
        instruction::transfer(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            &recipient_sol_key.derive.address,
            &token_account.pubkey(),
            &oracle.derive.address,
            &context.payer.pubkey(),
            std::array::IntoIter::new(signers),
            instruction::Transfer {
                amount: tokens_amount,
                id: String::from(transfer_id),
                eth_recipient: recipient_eth_key,
            },
        )
        .unwrap(),
    );

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );

    context.banks_client.process_transaction(tx).await.unwrap();

    let transfer_acc_created = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager.pubkey(),
        [
            TRANSFER_SEED_PREFIX.as_bytes().as_ref(),
            transfer_id.as_ref(),
        ]
        .concat(),
    )
    .unwrap();

    let transfer_acc_data = get_account(&mut context, &transfer_acc_created.derive.address)
        .await
        .unwrap();

    assert_eq!(transfer_acc_data.lamports, TRANSFER_ACC_BALANCE as u64);
    assert_eq!(transfer_acc_data.data.len() as u8, TRANSFER_ACC_SPACE);
}

#[tokio::test]
async fn secp_missing() {
    let mut program_test = program_test();
    program_test.add_program("claimable_tokens", claimable_tokens::id(), None);

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
        1 as u8,
    )
    .await;

    let mut rng = thread_rng();
    let key: [u8; 32] = rng.gen();
    let sender_priv_key = SecretKey::parse(&key).unwrap();
    let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
    let eth_address_1 = construct_eth_pubkey(&secp_pubkey);
    let operator_1: EthereumAddress = rng.gen();

    let first_sender = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager.pubkey(),
        [SENDER_SEED_PREFIX.as_ref(), eth_address_1.as_ref()].concat(),
    )
    .unwrap();
    create_sender(
        &mut context,
        &reward_manager.pubkey(),
        &manager_account,
        eth_address_1,
        operator_1,
    )
    .await;

    let mut rng = thread_rng();
    let key: [u8; 32] = rng.gen();
    let oracle_priv_key = SecretKey::parse(&key).unwrap();
    let secp_pubkey = PublicKey::from_secret_key(&oracle_priv_key);
    let eth_oracle_address = construct_eth_pubkey(&secp_pubkey);
    let oracle_operator: EthereumAddress = rng.gen();

    let second_sender = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager.pubkey(),
        [SENDER_SEED_PREFIX.as_ref(), eth_oracle_address.as_ref()].concat(),
    )
    .unwrap();
    create_sender(
        &mut context,
        &reward_manager.pubkey(),
        &manager_account,
        eth_oracle_address,
        oracle_operator,
    )
    .await;

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
    let recipient_sol_key = claimable_tokens::utils::program::get_address_pair(
        &claimable_tokens::id(),
        &mint.pubkey(),
        recipient_eth_key,
    )
    .unwrap();
    create_recipient_with_claimable_program(&mut context, &mint.pubkey(), recipient_eth_key).await;

    let transfer_id = "4r4t23df32543f55";

    let bot_oracle_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
    ]
    .concat();

    let oracle_secp256_program_instruction =
        new_secp256k1_instruction_2_0(&oracle_priv_key, bot_oracle_message.as_ref(), 0);

    let tx = Transaction::new_signed_with_payer(
        &[
            oracle_secp256_program_instruction,
            instruction::transfer(
                &audius_reward_manager::id(),
                &reward_manager.pubkey(),
                &recipient_sol_key.derive.address,
                &token_account.pubkey(),
                &second_sender.derive.address,
                &context.payer.pubkey(),
                vec![first_sender.derive.address],
                instruction::Transfer {
                    amount: tokens_amount,
                    id: String::from(transfer_id),
                    eth_recipient: recipient_eth_key,
                },
            )
            .unwrap(),
        ],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );

    assert_eq!(
        context
            .banks_client
            .process_transaction(tx)
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(
            1,
            InstructionError::Custom(AudiusProgramError::Secp256InstructionMissing as _)
        )
    );
}

#[tokio::test]
async fn different_oracles_mentiones() {
    let mut program_test = program_test();
    program_test.add_program("claimable_tokens", claimable_tokens::id(), None);
    let mut rng = thread_rng();

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
        3 as u8,
    )
    .await;

    // Generate data and create oracle
    let key: [u8; 32] = rng.gen();
    let oracle_priv_key = SecretKey::parse(&key).unwrap();
    let secp_oracle_pubkey = PublicKey::from_secret_key(&oracle_priv_key);
    let eth_oracle_address = construct_eth_pubkey(&secp_oracle_pubkey);
    let oracle_operator: EthereumAddress = rng.gen();
    let wrong_eth_oracle_address: EthereumAddress = rng.gen();

    let oracle = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager.pubkey(),
        [SENDER_SEED_PREFIX.as_ref(), eth_oracle_address.as_ref()].concat(),
    )
    .unwrap();
    create_sender(
        &mut context,
        &reward_manager.pubkey(),
        &manager_account,
        eth_oracle_address,
        oracle_operator,
    )
    .await;

    // Generate data and create senders
    let keys: [[u8; 32]; 3] = rng.gen();
    let operators: [EthereumAddress; 3] = rng.gen();
    let mut signers: [Pubkey; 3] = unsafe { MaybeUninit::zeroed().assume_init() };
    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);

        let pair = get_address_pair(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
        )
        .unwrap();

        signers[item.0] = pair.derive.address;
    }

    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);
        create_sender(
            &mut context,
            &reward_manager.pubkey(),
            &manager_account,
            eth_address,
            operators[item.0],
        )
        .await;
    }

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
    let recipient_sol_key = claimable_tokens::utils::program::get_address_pair(
        &claimable_tokens::id(),
        &mint.pubkey(),
        recipient_eth_key,
    )
    .unwrap();
    create_recipient_with_claimable_program(&mut context, &mint.pubkey(), recipient_eth_key).await;

    let transfer_id = "4r4t23df32543f55";

    let senders_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
        b"_",
        eth_oracle_address.as_ref(),
    ]
    .concat();

    let sender_with_wrong_oracle = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
        b"_",
        wrong_eth_oracle_address.as_ref(),
    ]
    .concat();

    let bot_oracle_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
    ]
    .concat();

    let mut instructions = Vec::<Instruction>::new();

    let oracle_sign =
        new_secp256k1_instruction_2_0(&oracle_priv_key, bot_oracle_message.as_ref(), 0);
    instructions.push(oracle_sign);

    let iter = keys.iter().enumerate().map(|i| (i.0 + 1, i.1));
    for item in iter {
        let priv_key = SecretKey::parse(item.1).unwrap();
        // The first message will sign with the wrong oracle mention, and all following have the correct sign
        let inst = if item.0 == 1 {
            new_secp256k1_instruction_2_0(&priv_key, sender_with_wrong_oracle.as_ref(), item.0 as _)
        } else {
            new_secp256k1_instruction_2_0(&priv_key, senders_message.as_ref(), item.0 as _)
        };
        instructions.push(inst);
    }

    instructions.push(
        instruction::transfer(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            &recipient_sol_key.derive.address,
            &token_account.pubkey(),
            &oracle.derive.address,
            &context.payer.pubkey(),
            std::array::IntoIter::new(signers),
            instruction::Transfer {
                amount: tokens_amount,
                id: String::from(transfer_id),
                eth_recipient: recipient_eth_key,
            },
        )
        .unwrap(),
    );

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );

    assert_eq!(
        context
            .banks_client
            .process_transaction(tx)
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(
            4,
            InstructionError::Custom(AudiusProgramError::SignatureVerificationFailed as _)
        )
    );
}

#[tokio::test]
async fn oracle_sign_missing() {
    let mut program_test = program_test();
    program_test.add_program("claimable_tokens", claimable_tokens::id(), None);

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
        1 as u8,
    )
    .await;

    let mut rng = thread_rng();
    let key: [u8; 32] = rng.gen();
    let sender_priv_key = SecretKey::parse(&key).unwrap();
    let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
    let eth_address_1 = construct_eth_pubkey(&secp_pubkey);
    let operator_1: EthereumAddress = rng.gen();

    let first_sender = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager.pubkey(),
        [SENDER_SEED_PREFIX.as_ref(), eth_address_1.as_ref()].concat(),
    )
    .unwrap();
    create_sender(
        &mut context,
        &reward_manager.pubkey(),
        &manager_account,
        eth_address_1,
        operator_1,
    )
    .await;

    let mut rng = thread_rng();
    let key: [u8; 32] = rng.gen();
    let oracle_priv_key = SecretKey::parse(&key).unwrap();
    let secp_pubkey = PublicKey::from_secret_key(&oracle_priv_key);
    let eth_address_2 = construct_eth_pubkey(&secp_pubkey);
    let operator_2: EthereumAddress = rng.gen();

    let second_sender = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager.pubkey(),
        [SENDER_SEED_PREFIX.as_ref(), eth_address_2.as_ref()].concat(),
    )
    .unwrap();
    create_sender(
        &mut context,
        &reward_manager.pubkey(),
        &manager_account,
        eth_address_2,
        operator_2,
    )
    .await;

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
    let recipient_sol_key = claimable_tokens::utils::program::get_address_pair(
        &claimable_tokens::id(),
        &mint.pubkey(),
        recipient_eth_key,
    )
    .unwrap();
    create_recipient_with_claimable_program(&mut context, &mint.pubkey(), recipient_eth_key).await;

    let transfer_id = "4r4t23df32543f55";

    let senders_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
        b"_",
        eth_address_2.as_ref(),
    ]
    .concat();

    let sender_secp256_program_instruction =
        new_secp256k1_instruction_2_0(&sender_priv_key, senders_message.as_ref(), 0);

    let tx = Transaction::new_signed_with_payer(
        &[
            sender_secp256_program_instruction,
            instruction::transfer(
                &audius_reward_manager::id(),
                &reward_manager.pubkey(),
                &recipient_sol_key.derive.address,
                &token_account.pubkey(),
                &second_sender.derive.address,
                &context.payer.pubkey(),
                vec![first_sender.derive.address],
                instruction::Transfer {
                    amount: tokens_amount,
                    id: String::from(transfer_id),
                    eth_recipient: recipient_eth_key,
                },
            )
            .unwrap(),
        ],
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );

    assert_eq!(
        context
            .banks_client
            .process_transaction(tx)
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(
            1,
            InstructionError::Custom(AudiusProgramError::Secp256InstructionMissing as _)
        )
    );
}

#[tokio::test]
async fn repeating_operators() {
    let mut program_test = program_test();
    program_test.add_program("claimable_tokens", claimable_tokens::id(), None);
    let mut rng = thread_rng();

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
        3 as u8,
    )
    .await;

    // Generate data and create oracle
    let key: [u8; 32] = rng.gen();
    let oracle_priv_key = SecretKey::parse(&key).unwrap();
    let secp_oracle_pubkey = PublicKey::from_secret_key(&oracle_priv_key);
    let eth_oracle_address = construct_eth_pubkey(&secp_oracle_pubkey);
    let oracle_operator: EthereumAddress = rng.gen();

    let oracle = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager.pubkey(),
        [SENDER_SEED_PREFIX.as_ref(), eth_oracle_address.as_ref()].concat(),
    )
    .unwrap();
    create_sender(
        &mut context,
        &reward_manager.pubkey(),
        &manager_account,
        eth_oracle_address,
        oracle_operator,
    )
    .await;

    // Generate data and create senders
    let keys: [[u8; 32]; 3] = rng.gen();
    let collided_operator = rng.gen();
    let mut signers: [Pubkey; 3] = unsafe { MaybeUninit::zeroed().assume_init() };
    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);

        let pair = get_address_pair(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
        )
        .unwrap();

        signers[item.0] = pair.derive.address;
    }

    for key in &keys {
        let sender_priv_key = SecretKey::parse(key).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);
        create_sender(
            &mut context,
            &reward_manager.pubkey(),
            &manager_account,
            eth_address,
            collided_operator,
        )
        .await;
    }

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
    let recipient_sol_key = claimable_tokens::utils::program::get_address_pair(
        &claimable_tokens::id(),
        &mint.pubkey(),
        recipient_eth_key,
    )
    .unwrap();
    create_recipient_with_claimable_program(&mut context, &mint.pubkey(), recipient_eth_key).await;

    let transfer_id = "4r4t23df32543f55";

    let senders_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
        b"_",
        eth_oracle_address.as_ref(),
    ]
    .concat();

    let bot_oracle_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
    ]
    .concat();

    let mut instructions = Vec::<Instruction>::new();

    let oracle_sign =
        new_secp256k1_instruction_2_0(&oracle_priv_key, bot_oracle_message.as_ref(), 0);
    instructions.push(oracle_sign);

    let iter = keys.iter().enumerate().map(|i| (i.0 + 1, i.1));
    for item in iter {
        let priv_key = SecretKey::parse(item.1).unwrap();
        let inst = new_secp256k1_instruction_2_0(&priv_key, senders_message.as_ref(), item.0 as _);
        instructions.push(inst);
    }

    instructions.push(
        instruction::transfer(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            &recipient_sol_key.derive.address,
            &token_account.pubkey(),
            &oracle.derive.address,
            &context.payer.pubkey(),
            std::array::IntoIter::new(signers),
            instruction::Transfer {
                amount: tokens_amount,
                id: String::from(transfer_id),
                eth_recipient: recipient_eth_key,
            },
        )
        .unwrap(),
    );

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );

    assert_eq!(
        context
            .banks_client
            .process_transaction(tx)
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(
            4,
            InstructionError::Custom(AudiusProgramError::OperatorCollision as _)
        )
    );
}

#[tokio::test]
async fn repeating_ids() {
    let mut program_test = program_test();
    program_test.add_program("claimable_tokens", claimable_tokens::id(), None);
    let mut rng = thread_rng();

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
        3 as u8,
    )
    .await;

    // Generate data and create oracle
    let key: [u8; 32] = rng.gen();
    let oracle_priv_key = SecretKey::parse(&key).unwrap();
    let secp_oracle_pubkey = PublicKey::from_secret_key(&oracle_priv_key);
    let eth_oracle_address = construct_eth_pubkey(&secp_oracle_pubkey);
    let oracle_operator: EthereumAddress = rng.gen();

    let oracle = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager.pubkey(),
        [SENDER_SEED_PREFIX.as_ref(), eth_oracle_address.as_ref()].concat(),
    )
    .unwrap();
    create_sender(
        &mut context,
        &reward_manager.pubkey(),
        &manager_account,
        eth_oracle_address,
        oracle_operator,
    )
    .await;

    // Generate data and create senders
    let keys: [[u8; 32]; 3] = rng.gen();
    let operators: [EthereumAddress; 3] = rng.gen();
    let mut signers: [Pubkey; 3] = unsafe { MaybeUninit::zeroed().assume_init() };
    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);

        let pair = get_address_pair(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
        )
        .unwrap();

        signers[item.0] = pair.derive.address;
    }

    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);
        create_sender(
            &mut context,
            &reward_manager.pubkey(),
            &manager_account,
            eth_address,
            operators[item.0],
        )
        .await;
    }

    let tokens_amount = 10_000;

    mint_tokens_to(
        &mut context,
        &mint.pubkey(),
        &token_account.pubkey(),
        &mint_authority,
        tokens_amount * 2,
    )
    .await
    .unwrap();

    let recipient_eth_key = [7u8; 20];
    let recipient_sol_key = claimable_tokens::utils::program::get_address_pair(
        &claimable_tokens::id(),
        &mint.pubkey(),
        recipient_eth_key,
    )
    .unwrap();
    create_recipient_with_claimable_program(&mut context, &mint.pubkey(), recipient_eth_key).await;

    let transfer_id = "4r4t23df32543f55";

    let senders_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
        b"_",
        eth_oracle_address.as_ref(),
    ]
    .concat();

    let bot_oracle_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
    ]
    .concat();

    let mut instructions = Vec::<Instruction>::new();

    let oracle_sign =
        new_secp256k1_instruction_2_0(&oracle_priv_key, bot_oracle_message.as_ref(), 0);
    instructions.push(oracle_sign);

    let iter = keys.iter().enumerate().map(|i| (i.0 + 1, i.1));
    for item in iter {
        let priv_key = SecretKey::parse(item.1).unwrap();
        let inst = new_secp256k1_instruction_2_0(&priv_key, senders_message.as_ref(), item.0 as _);
        instructions.push(inst);
    }

    instructions.push(
        instruction::transfer(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            &recipient_sol_key.derive.address,
            &token_account.pubkey(),
            &oracle.derive.address,
            &context.payer.pubkey(),
            std::array::IntoIter::new(signers),
            instruction::Transfer {
                amount: tokens_amount,
                id: String::from(transfer_id),
                eth_recipient: recipient_eth_key,
            },
        )
        .unwrap(),
    );

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );

    context
        .banks_client
        .process_transaction(tx.clone())
        .await
        .unwrap();

    context.warp_to_slot(10);

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );

    assert_eq!(
        context
            .banks_client
            .process_transaction(tx)
            .await
            .unwrap_err()
            .unwrap(),
        TransactionError::InstructionError(
            4,
            InstructionError::Custom(SystemError::AccountAlreadyInUse as _)
        )
    );
}

#[tokio::test]
async fn fail_different_amounts_in_sender_messages() {
    let mut program_test = program_test();
    program_test.add_program("claimable_tokens", claimable_tokens::id(), None);
    let mut rng = thread_rng();

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
        3 as u8,
    )
    .await;

    // Generate data and create oracle
    let key: [u8; 32] = rng.gen();
    let oracle_priv_key = SecretKey::parse(&key).unwrap();
    let secp_oracle_pubkey = PublicKey::from_secret_key(&oracle_priv_key);
    let eth_oracle_address = construct_eth_pubkey(&secp_oracle_pubkey);
    let oracle_operator: EthereumAddress = rng.gen();

    let oracle = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager.pubkey(),
        [SENDER_SEED_PREFIX.as_ref(), eth_oracle_address.as_ref()].concat(),
    )
    .unwrap();
    create_sender(
        &mut context,
        &reward_manager.pubkey(),
        &manager_account,
        eth_oracle_address,
        oracle_operator,
    )
    .await;

    // Generate data and create senders
    let keys: [[u8; 32]; 3] = rng.gen();
    let operators: [EthereumAddress; 3] = rng.gen();
    let mut signers: [Pubkey; 3] = unsafe { MaybeUninit::zeroed().assume_init() };
    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);

        let pair = get_address_pair(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
        )
        .unwrap();

        signers[item.0] = pair.derive.address;
    }

    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);
        create_sender(
            &mut context,
            &reward_manager.pubkey(),
            &manager_account,
            eth_address,
            operators[item.0],
        )
        .await;
    }

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
    let recipient_sol_key = claimable_tokens::utils::program::get_address_pair(
        &claimable_tokens::id(),
        &mint.pubkey(),
        recipient_eth_key,
    )
    .unwrap();
    create_recipient_with_claimable_program(&mut context, &mint.pubkey(), recipient_eth_key).await;

    let transfer_id = "4r4t23df32543f55";

    let bot_oracle_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
    ]
    .concat();

    let mut instructions = Vec::<Instruction>::new();

    let oracle_sign =
        new_secp256k1_instruction_2_0(&oracle_priv_key, bot_oracle_message.as_ref(), 0);
    instructions.push(oracle_sign);

    let iter = keys.iter().enumerate().map(|i| (i.0 + 1, i.1));
    for (i, item) in iter.enumerate() {
        let priv_key = SecretKey::parse(item.1).unwrap();
        let faked_sender_message = [
            recipient_eth_key.as_ref(),
            b"_",
            (tokens_amount + i as u64).to_le_bytes().as_ref(),
            b"_",
            transfer_id.as_ref(),
            b"_",
            eth_oracle_address.as_ref(),
        ]
        .concat();
        let inst =
            new_secp256k1_instruction_2_0(&priv_key, faked_sender_message.as_ref(), item.0 as _);
        instructions.push(inst);
    }

    instructions.push(
        instruction::transfer(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            &recipient_sol_key.derive.address,
            &token_account.pubkey(),
            &oracle.derive.address,
            &context.payer.pubkey(),
            std::array::IntoIter::new(signers),
            instruction::Transfer {
                amount: tokens_amount,
                id: String::from(transfer_id),
                eth_recipient: recipient_eth_key,
            },
        )
        .unwrap(),
    );

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );

    match context.banks_client.process_transaction(tx).await {
        Ok(_) => assert!(false),
        Err(error) => assert_custom_error!(error, AudiusProgramError::SignatureVerificationFailed),
    }
}

#[tokio::test]
async fn fail_different_amount_in_oracle_message() {
    let mut program_test = program_test();
    program_test.add_program("claimable_tokens", claimable_tokens::id(), None);
    let mut rng = thread_rng();

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
        3 as u8,
    )
    .await;

    // Generate data and create oracle
    let key: [u8; 32] = rng.gen();
    let oracle_priv_key = SecretKey::parse(&key).unwrap();
    let secp_oracle_pubkey = PublicKey::from_secret_key(&oracle_priv_key);
    let eth_oracle_address = construct_eth_pubkey(&secp_oracle_pubkey);
    let oracle_operator: EthereumAddress = rng.gen();

    let oracle = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager.pubkey(),
        [SENDER_SEED_PREFIX.as_ref(), eth_oracle_address.as_ref()].concat(),
    )
    .unwrap();
    create_sender(
        &mut context,
        &reward_manager.pubkey(),
        &manager_account,
        eth_oracle_address,
        oracle_operator,
    )
    .await;

    // Generate data and create senders
    let keys: [[u8; 32]; 3] = rng.gen();
    let operators: [EthereumAddress; 3] = rng.gen();
    let mut signers: [Pubkey; 3] = unsafe { MaybeUninit::zeroed().assume_init() };
    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);

        let pair = get_address_pair(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
        )
        .unwrap();

        signers[item.0] = pair.derive.address;
    }

    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);
        create_sender(
            &mut context,
            &reward_manager.pubkey(),
            &manager_account,
            eth_address,
            operators[item.0],
        )
        .await;
    }

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
    let recipient_sol_key = claimable_tokens::utils::program::get_address_pair(
        &claimable_tokens::id(),
        &mint.pubkey(),
        recipient_eth_key,
    )
    .unwrap();
    create_recipient_with_claimable_program(&mut context, &mint.pubkey(), recipient_eth_key).await;

    let transfer_id = "4r4t23df32543f55";

    let senders_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
        b"_",
        eth_oracle_address.as_ref(),
    ]
    .concat();

    let bot_oracle_message = [
        recipient_eth_key.as_ref(),
        b"_",
        (tokens_amount / 2).to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
    ]
    .concat();

    let mut instructions = Vec::<Instruction>::new();

    let oracle_sign =
        new_secp256k1_instruction_2_0(&oracle_priv_key, bot_oracle_message.as_ref(), 0);
    instructions.push(oracle_sign);

    let iter = keys.iter().enumerate().map(|i| (i.0 + 1, i.1));
    for item in iter {
        let priv_key = SecretKey::parse(item.1).unwrap();
        let inst = new_secp256k1_instruction_2_0(&priv_key, senders_message.as_ref(), item.0 as _);
        instructions.push(inst);
    }

    instructions.push(
        instruction::transfer(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            &recipient_sol_key.derive.address,
            &token_account.pubkey(),
            &oracle.derive.address,
            &context.payer.pubkey(),
            std::array::IntoIter::new(signers),
            instruction::Transfer {
                amount: tokens_amount,
                id: String::from(transfer_id),
                eth_recipient: recipient_eth_key,
            },
        )
        .unwrap(),
    );

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );

    match context.banks_client.process_transaction(tx).await {
        Ok(_) => assert!(false),
        Err(error) => assert_custom_error!(error, AudiusProgramError::SignatureVerificationFailed),
    }
}

#[tokio::test]
async fn fail_different_bot_oracle_in_sender_messages() {
    let mut program_test = program_test();
    program_test.add_program("claimable_tokens", claimable_tokens::id(), None);
    let mut rng = thread_rng();

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
        3 as u8,
    )
    .await;

    // Generate data and create oracle
    let key: [u8; 32] = rng.gen();
    let oracle_priv_key = SecretKey::parse(&key).unwrap();
    let secp_oracle_pubkey = PublicKey::from_secret_key(&oracle_priv_key);
    let eth_oracle_address = construct_eth_pubkey(&secp_oracle_pubkey);
    let oracle_operator: EthereumAddress = rng.gen();

    // Generate fake oracle address
    let fake_key: [u8; 32] = rng.gen();
    let fake_oracle_priv_key = SecretKey::parse(&fake_key).unwrap();
    let fake_secp_oracle_pubkey = PublicKey::from_secret_key(&fake_oracle_priv_key);
    let fake_eth_oracle_address = construct_eth_pubkey(&fake_secp_oracle_pubkey);
    let fake_oracle_operator: EthereumAddress = rng.gen();

    let oracle = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager.pubkey(),
        [SENDER_SEED_PREFIX.as_ref(), eth_oracle_address.as_ref()].concat(),
    )
    .unwrap();
    create_sender(
        &mut context,
        &reward_manager.pubkey(),
        &manager_account,
        eth_oracle_address,
        oracle_operator,
    )
    .await;

    // Generate data and create senders
    let keys: [[u8; 32]; 3] = rng.gen();
    let operators: [EthereumAddress; 3] = rng.gen();
    let mut signers: [Pubkey; 3] = unsafe { MaybeUninit::zeroed().assume_init() };
    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);

        let pair = get_address_pair(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
        )
        .unwrap();

        signers[item.0] = pair.derive.address;
    }

    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);
        create_sender(
            &mut context,
            &reward_manager.pubkey(),
            &manager_account,
            eth_address,
            operators[item.0],
        )
        .await;
    }

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
    let recipient_sol_key = claimable_tokens::utils::program::get_address_pair(
        &claimable_tokens::id(),
        &mint.pubkey(),
        recipient_eth_key,
    )
    .unwrap();
    create_recipient_with_claimable_program(&mut context, &mint.pubkey(), recipient_eth_key).await;

    let transfer_id = "4r4t23df32543f55";

    let senders_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
        b"_",
        fake_eth_oracle_address.as_ref(),
    ]
    .concat();

    let bot_oracle_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
    ]
    .concat();

    let mut instructions = Vec::<Instruction>::new();

    let oracle_sign =
        new_secp256k1_instruction_2_0(&oracle_priv_key, bot_oracle_message.as_ref(), 0);
    instructions.push(oracle_sign);

    let iter = keys.iter().enumerate().map(|i| (i.0 + 1, i.1));
    for item in iter {
        let priv_key = SecretKey::parse(item.1).unwrap();
        let inst = new_secp256k1_instruction_2_0(&priv_key, senders_message.as_ref(), item.0 as _);
        instructions.push(inst);
    }

    instructions.push(
        instruction::transfer(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            &recipient_sol_key.derive.address,
            &token_account.pubkey(),
            &oracle.derive.address,
            &context.payer.pubkey(),
            std::array::IntoIter::new(signers),
            instruction::Transfer {
                amount: tokens_amount,
                id: String::from(transfer_id),
                eth_recipient: recipient_eth_key,
            },
        )
        .unwrap(),
    );

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );

    match context.banks_client.process_transaction(tx).await {
        Ok(_) => assert!(false),
        Err(error) => assert_custom_error!(error, AudiusProgramError::SignatureVerificationFailed),
    }
}

#[tokio::test]
async fn fail_bot_oracle_is_one_of_the_senders() {
    let mut program_test = program_test();
    program_test.add_program("claimable_tokens", claimable_tokens::id(), None);
    let mut rng = thread_rng();

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
        3 as u8,
    )
    .await;

    // Generate data and create oracle
    let key: [u8; 32] = rng.gen();
    let oracle_priv_key = SecretKey::parse(&key).unwrap();
    let secp_oracle_pubkey = PublicKey::from_secret_key(&oracle_priv_key);
    let eth_oracle_address = construct_eth_pubkey(&secp_oracle_pubkey);
    let oracle_operator: EthereumAddress = rng.gen();

    let oracle = get_address_pair(
        &audius_reward_manager::id(),
        &reward_manager.pubkey(),
        [SENDER_SEED_PREFIX.as_ref(), eth_oracle_address.as_ref()].concat(),
    )
    .unwrap();
    create_sender(
        &mut context,
        &reward_manager.pubkey(),
        &manager_account,
        eth_oracle_address,
        oracle_operator,
    )
    .await;

    // Generate data and create senders
    let mut keys: [[u8; 32]; 3] = rng.gen();

    // Change last `sender` to bot-oracle secp private key
    keys[2] = key;

    // Add last sender operator to self bot-oracle operator
    let mut operators: [EthereumAddress; 3] = rng.gen();
    operators[2] = oracle_operator;

    let mut signers: [Pubkey; 3] = unsafe { MaybeUninit::zeroed().assume_init() };
    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);

        let pair = get_address_pair(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            [SENDER_SEED_PREFIX.as_ref(), eth_address.as_ref()].concat(),
        )
        .unwrap();

        signers[item.0] = pair.derive.address;
    }

    for item in keys.iter().enumerate() {
        let sender_priv_key = SecretKey::parse(item.1).unwrap();
        let secp_pubkey = PublicKey::from_secret_key(&sender_priv_key);
        let eth_address = construct_eth_pubkey(&secp_pubkey);
        create_sender(
            &mut context,
            &reward_manager.pubkey(),
            &manager_account,
            eth_address,
            operators[item.0],
        )
        .await;
    }

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
    let recipient_sol_key = claimable_tokens::utils::program::get_address_pair(
        &claimable_tokens::id(),
        &mint.pubkey(),
        recipient_eth_key,
    )
    .unwrap();
    create_recipient_with_claimable_program(&mut context, &mint.pubkey(), recipient_eth_key).await;

    let transfer_id = "4r4t23df32543f55";

    let senders_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
        b"_",
        eth_oracle_address.as_ref(),
    ]
    .concat();

    let bot_oracle_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
    ]
    .concat();

    let mut instructions = Vec::<Instruction>::new();

    let oracle_sign =
        new_secp256k1_instruction_2_0(&oracle_priv_key, bot_oracle_message.as_ref(), 0);
    instructions.push(oracle_sign);

    let iter = keys.iter().enumerate().map(|i| (i.0 + 1, i.1));
    for item in iter {
        let priv_key = SecretKey::parse(item.1).unwrap();
        let inst = new_secp256k1_instruction_2_0(&priv_key, senders_message.as_ref(), item.0 as _);
        instructions.push(inst);
    }

    instructions.push(
        instruction::transfer(
            &audius_reward_manager::id(),
            &reward_manager.pubkey(),
            &recipient_sol_key.derive.address,
            &token_account.pubkey(),
            &oracle.derive.address,
            &context.payer.pubkey(),
            std::array::IntoIter::new(signers),
            instruction::Transfer {
                amount: tokens_amount,
                id: String::from(transfer_id),
                eth_recipient: recipient_eth_key,
            },
        )
        .unwrap(),
    );

    let tx = Transaction::new_signed_with_payer(
        &instructions,
        Some(&context.payer.pubkey()),
        &[&context.payer],
        context.last_blockhash,
    );

    match context.banks_client.process_transaction(tx).await {
        Ok(_) => assert!(false),
        Err(error) => assert_custom_error!(error, AudiusProgramError::OperatorCollision),
    }
}
