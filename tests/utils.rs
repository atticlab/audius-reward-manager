use audius_reward_manager::{id, processor::Processor};
use solana_program::pubkey::Pubkey;
use solana_program_test::{processor, ProgramTest};

pub fn program_test() -> ProgramTest {
    let mut program = ProgramTest::new(
        "audius_reward_manager",
        id(),
        processor!(Processor::process_instruction),
    );
    program.add_program("claimable_tokens", claimable_tokens::id(), None);
    program
}
