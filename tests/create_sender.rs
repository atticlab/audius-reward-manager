#![cfg(feature = "test-bpf")]
mod utils;
use audius_reward_manager::{instruction, state::{RewardManager, SenderAccount}};
use borsh::BorshSerialize;
use solana_program::pubkey::Pubkey;
use solana_program_test::*;
use solana_sdk::{account::Account, signature::Keypair, signer::Signer, transaction::Transaction };
use utils::program_test;
use std::str;

#[tokio::test]
async fn success() {
    let mut program_test = program_test();

    let reward_manager = Pubkey::new_unique();
    let token_account = Pubkey::new_unique();
    let manager_account = Keypair::new();
    let eth_address = [0u8; 20];

    let reward_manager_data = RewardManager::new(token_account, manager_account.pubkey(), 3);
    program_test.add_account(
        reward_manager,
        Account {
            lamports: 9000,
            data: reward_manager_data.try_to_vec().unwrap(),
            owner: audius_reward_manager::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    let mut context = program_test.start_with_context().await;
    let tx = Transaction::new_signed_with_payer(
        &[
            instruction::create_sender(
            &audius_reward_manager::id(),
            &reward_manager,
            &manager_account.pubkey(),
            &context.payer.pubkey(),
            eth_address,
        )
        .unwrap()],
        Some(&context.payer.pubkey()),
        &[&context.payer, &manager_account],
        context.last_blockhash,
    );

    context.banks_client.process_transaction(tx).await.unwrap();

    let (authority, base_seed) = Pubkey::find_program_address(&[&reward_manager.to_bytes()[..32]], &audius_reward_manager::id());
    let mut seed = Vec::new();
    seed.extend_from_slice(b"S_");
    seed.extend_from_slice(&eth_address.as_ref());
    let s_seed = str::from_utf8(seed.as_ref()).unwrap();
    let sender_address = Pubkey::create_with_seed(&authority, s_seed, &audius_reward_manager::id()).unwrap();

    assert_eq!(
        SenderAccount::new(manager_account.pubkey(), eth_address),
        context
            .banks_client
            .get_account_data_with_borsh(sender_address)
            .await
            .unwrap()
    );
}
