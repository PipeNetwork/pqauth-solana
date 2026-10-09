pub mod crypto;
pub mod error;
pub mod processor;

use solana_program::declare_id;

declare_id!("8RRuQaeSmnYJJkkC2qAYNnNbzjW3eCexQSUbpHZVJv9U");

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    use solana_program::{
        account_info::AccountInfo,
        entrypoint,
        entrypoint::ProgramResult,
        pubkey::Pubkey,
    };

    use crate::{error::log_error, processor::Processor};

    entrypoint!(process_instruction);

    fn process_instruction(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        instruction_data: &[u8],
    ) -> ProgramResult {
        let result = Processor::process(program_id, accounts, instruction_data);
        if let Err(ref error) = result {
            log_error(error);
        }
        result
    }
}
