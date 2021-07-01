//! Extended functionality
use crate::{Config, Error};
use borsh::BorshDeserialize;
use solana_program::{
    instruction::Instruction,
    program_pack::Pack,
    pubkey::{Pubkey, PubkeyError},
};
use solana_sdk::{
    native_token::lamports_to_sol,
    signature::{Signature, Signer},
    transaction::Transaction as OnchainTransaction,
};
use spl_token::state::Account;

pub fn is_hex(s: String) -> Result<(), String> {
    if hex::decode(s).is_err() {
        Err(String::from("Wrong address format"))
    } else {
        Ok(())
    }
}

fn check_fee_payer_balance(config: &Config, required_balance: u64) -> Result<(), Error> {
    let balance = config.rpc_client.get_balance(&config.fee_payer.pubkey())?;
    if balance < required_balance {
        Err(format!(
            "Fee payer, {}, has insufficient balance: {} required, {} available",
            config.fee_payer.pubkey(),
            lamports_to_sol(required_balance),
            lamports_to_sol(balance)
        )
        .into())
    } else {
        Ok(())
    }
}

/// Transaction
pub struct Transaction<'a> {
    ///
    pub instructions: Vec<Instruction>,
    ///
    pub signers: Vec<&'a dyn Signer>,
}

impl<'a> Transaction<'a> {
    pub fn sign(
        self,
        config: &Config,
        additional_balance_required: u64,
    ) -> Result<Option<OnchainTransaction>, Error> {
        let mut transaction = OnchainTransaction::new_with_payer(
            self.instructions.as_ref(),
            Some(&config.fee_payer.pubkey()),
        );

        let (recent_blockhash, fee_calculator) = config.rpc_client.get_recent_blockhash()?;
        check_fee_payer_balance(
            config,
            fee_calculator.calculate_fee(&transaction.message()) + additional_balance_required,
        )?;

        transaction.sign(&self.signers, recent_blockhash);

        Ok(Some(transaction))
    }

    pub fn sign_and_send(
        self,
        config: &Config,
        additional_balance_required: u64,
    ) -> Result<Signature, Error> {
        let signed_transaction = self.sign(config, additional_balance_required)?.unwrap();
        Ok(config
            .rpc_client
            .send_and_confirm_transaction_with_spinner_and_commitment(
                &signed_transaction,
                config.commitment_config,
            )?)
    }
}
