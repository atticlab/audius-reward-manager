#![cfg(feature = "test-bpf")]
mod utils;
use audius_reward_manager::{
    instruction,
    processor::{
        SENDER_SEED_PREFIX, TRANSFER_ACC_BALANCE, TRANSFER_ACC_SPACE, TRANSFER_SEED_PREFIX,
    },
    utils::{get_address_pair, EthereumAddress},
};
use rand::{thread_rng, Rng};
use secp256k1::{PublicKey, SecretKey};
use solana_program::{program_pack::Pack};
use solana_program_test::*;
use solana_sdk::{
    secp256k1_instruction::*, signature::Keypair, signer::Signer, transaction::Transaction,
};
use utils::*;

#[tokio::test]
async fn transfer_test() {
    let mut program_test = program_test();
    // program_test.prefer_bpf(false);
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

    let bot_oracle_message = [
        recipient_eth_key.as_ref(),
        b"_",
        tokens_amount.to_le_bytes().as_ref(),
        b"_",
        transfer_id.as_ref(),
    ]
    .concat();

    let sender_secp256_program_instruction =
        new_secp256k1_instruction_2_0(&sender_priv_key, senders_message.as_ref(), 0);
    let oracle_secp256_program_instruction =
        new_secp256k1_instruction_2_0(&oracle_priv_key, bot_oracle_message.as_ref(), 1);

    let tx = Transaction::new_signed_with_payer(
        &[
            sender_secp256_program_instruction,
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
