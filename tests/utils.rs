use audius_reward_manager::{id, processor::Processor};
use solana_program::pubkey::Pubkey;
use solana_program_test::{processor, ProgramTest};

pub fn program_test() -> ProgramTest {
    ProgramTest::new(
        "audius_reward_manager",
        id(),
        processor!(Processor::process_instruction),
    )
}
