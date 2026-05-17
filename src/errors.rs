use pinocchio::program_error::ProgramError;

// Mirrors the Anchor EscrowError enum numeric values (6000+) so existing
// client-side error decoders don't break.
pub const ERR_ZERO_AMOUNT:          ProgramError = ProgramError::Custom(6000);
pub const ERR_INVALID_CANCEL_AFTER: ProgramError = ProgramError::Custom(6001);
pub const ERR_CANCEL_AFTER_TOO_FAR: ProgramError = ProgramError::Custom(6002);
pub const ERR_TOO_EARLY_TO_CANCEL:  ProgramError = ProgramError::Custom(6003);
pub const ERR_UNAUTHORIZED:         ProgramError = ProgramError::Custom(6004);
