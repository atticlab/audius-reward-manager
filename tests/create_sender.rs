#![cfg(feature = "test-bpf")]
mod utils;
use audius_reward_manager::{instruction, state::RewardManager};
use borsh::BorshSerialize;
use solana_program::pubkey::Pubkey;
use solana_program_test::*;
use solana_sdk::{account::Account, signature::Keypair, signer::Signer, transaction::Transaction, system_instruction::create_account};
use utils::program_test;

#[tokio::test]
async fn success() {
    let mut program_test = program_test();

    let reward_manager = Pubkey::new_unique();
    let token_account = Pubkey::new_unique();
    let manager_account = Keypair::new();
    let sender = Keypair::new();

    let mut data = Vec::with_capacity(RewardManager::LEN);
    let reward_manager_data = RewardManager::new(token_account, manager_account.pubkey(), 3);
    reward_manager_data.serialize(&mut data).unwrap();
    program_test.add_account(
        reward_manager,
        Account {
            lamports: 9000,
            data,
            owner: audius_reward_manager::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    let mut context = program_test.start_with_context().await;
    let rent = context.banks_client.get_rent().await.unwrap();
    let tx = Transaction::new_signed_with_payer(
        &[
            create_account(
                &context.payer.pubkey(),
                &sender.pubkey(),
                rent.minimum_balance(audius_reward_manager::state::SenderAccount::LEN),
                audius_reward_manager::state::SenderAccount::LEN as _,
                &audius_reward_manager::id(),
            ),
            instruction::create_sender(
            &audius_reward_manager::id(),
            &reward_manager,
            &manager_account.pubkey(),
            &context.payer.pubkey(),
            &sender.pubkey(),
        )
        .unwrap()],
        Some(&context.payer.pubkey()),
        &[&context.payer, &sender, &manager_account],
        context.last_blockhash,
    );

    context.banks_client.process_transaction(tx).await.unwrap();

    assert_eq!(
        reward_manager_data,
        context
            .banks_client
            .get_account_data_with_borsh(sender.pubkey())
            .await
            .unwrap()
    );
}
