//! Error types

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use solana_program::{
    decode_error::DecodeError,
    msg,
    program_error::{PrintProgramError, ProgramError},
};
use thiserror::Error;

/// Errors that may be returned by the Template program.
#[derive(Clone, Debug, Eq, Error, FromPrimitive, PartialEq)]
pub enum AudiusRewardError {
    #[error("Incorect reward manager")]
    IncorectRewardManager,
    #[error("Incorect account manager")]
    IncorectManagerAccount,
    #[error("Incorect sender account")]
    IncorectSenderAccount,
}
impl From<AudiusRewardError> for ProgramError {
    fn from(e: AudiusRewardError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
impl<T> DecodeError<T> for AudiusRewardError {
    fn type_of() -> &'static str {
        "AudiusRewardError"
    }
}

impl PrintProgramError for AudiusRewardError {
    fn print<E>(&self)
    where
        E: 'static + std::error::Error + DecodeError<E> + PrintProgramError + FromPrimitive,
    {
        msg!(&self.to_string())
    }
}
