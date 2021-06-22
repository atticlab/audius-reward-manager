#![cfg(feature = "test-bpf")]
mod utils;
use audius_reward_manager::{instruction, state::RewardManager};
use borsh::BorshSerialize;
use solana_program::pubkey::Pubkey;
use solana_program_test::*;
use solana_sdk::{account::Account, signature::Keypair, signer::Signer, transaction::Transaction };
use utils::program_test;

#[tokio::test]
async fn success() {
    let mut program_test = program_test();

    let reward_manager = Pubkey::new_unique();
    let token_account = Pubkey::new_unique();
    let manager_account = Keypair::new();
    let eth_address = [0u8; 20];

    let (authority, _) = Pubkey::find_program_address(&[manager_account.pubkey().as_ref()], &audius_reward_manager::id());
    let (sender, _) = Pubkey::find_program_address(&[&authority.to_bytes(), b"S_", eth_address.as_ref()], &audius_reward_manager::id());

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

    assert_eq!(
        reward_manager_data,
        context
            .banks_client
            .get_account_data_with_borsh(sender)
            .await
            .unwrap()
    );
}