//! Moonvalve Fair-Launch Escrow — pinocchio 0.9 build.
//!
//! Changes from the original Anchor build that the Node.js backend must adopt:
//!
//!   1. Instruction discriminant: 1 byte (0/1/2) instead of Anchor's 8-byte sighash.
//!
//!   2. `create_escrow` instruction data layout (58 bytes total, little-endian):
//!        [disc(1)] [amount(8)] [cancel_after(8)] [launch_id(32)] [nonce(8)] [bump(1)]
//!      bump = canonical PDA bump from findProgramAddress — client must pre-compute it.
//!
//!   3. `finish_escrow` / `cancel_escrow` carry no extra args; the program reads
//!      vault fields from the on-chain account.
//!
//! Build targets (platform authority pubkey is baked in at compile time):
//!   cargo build-sbf --features devnet
//!   cargo build-sbf --features mainnet
//!
//! PDA seeds and on-chain account layout are unchanged from the Anchor version.

use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use pinocchio_pubkey::pubkey;
use pinocchio_system::instructions::CreateAccount;

pub mod errors;
pub mod events;
pub mod state;

use errors::*;
use events::*;
use state::EscrowVault;

// ── Platform authority (baked in at compile time) ─────────────────────────────
//
// Exactly one of `devnet` or `mainnet` must be passed as a feature flag.
// The authority is the platform server keypair that co-signs create_escrow
// and is the only account allowed to finish_escrow or early-cancel.

#[cfg(feature = "devnet")]
const PLATFORM_AUTHORITY: [u8; 32] =
    pubkey!("52RHXiHAYWUyWTkp1dy5n3n865v8Ucg958W424ugzGgT");

#[cfg(feature = "mainnet")]
const PLATFORM_AUTHORITY: [u8; 32] =
    pubkey!("MoonXX2SGoArAkDYUfgrs4WMFwg5cLFczaJcKjcbrGw");

#[cfg(not(any(feature = "devnet", feature = "mainnet")))]
compile_error!(
    "Must specify a network feature flag: cargo build-sbf --features devnet  OR  --features mainnet"
);

// ── Constants ─────────────────────────────────────────────────────────────────

const MAX_ESCROW_DURATION: i64 = 60 * 24 * 60 * 60;

// Rent-exempt lamports per byte of account space:
//   lamports_per_byte_year (3480) × exemption_threshold (2.0)
// These are the fixed Solana mainnet/testnet constants and have not changed.
const RENT_PER_BYTE: u64 = 6960;

// ── Entrypoint ────────────────────────────────────────────────────────────────

#[cfg(not(feature = "no-entrypoint"))]
use pinocchio::entrypoint;

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &[u8; 32],
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let (&disc, rest) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match disc {
        0 => create_escrow(program_id, accounts, rest),
        1 => finish_escrow(program_id, accounts),
        2 => cancel_escrow(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

// ── create_escrow ─────────────────────────────────────────────────────────────
//
// Instruction data (57 bytes after disc, little-endian):
//   [0..8]   amount       u64  — SOL to lock, in lamports (excluding rent)
//   [8..16]  cancel_after i64  — unix timestamp after which anyone may cancel
//   [16..48] launch_id   [u8;32]
//   [48..56] nonce        u64  — unique per (buyer, launch)
//   [56]     bump         u8   — PDA canonical bump (client pre-computes)
//
// Accounts:
//   0  buyer         [signer, writable]
//   1  destination   []
//   2  authority     [signer]  — MUST be PLATFORM_AUTHORITY
//   3  escrow        [writable]
//   4  system_program

fn create_escrow(
    program_id: &[u8; 32],
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() < 57 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount: u64         = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let cancel_after: i64   = i64::from_le_bytes(data[8..16].try_into().unwrap());
    let launch_id: [u8; 32] = data[16..48].try_into().unwrap();
    let nonce: u64          = u64::from_le_bytes(data[48..56].try_into().unwrap());
    let bump: u8            = data[56];

    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let buyer       = &accounts[0];
    let destination = &accounts[1];
    let authority   = &accounts[2];
    let escrow      = &accounts[3];

    // Both buyer and authority must sign.
    if !buyer.is_signer() || !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !buyer.is_writable() || !escrow.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Authority MUST be the platform keypair — prevents unauthorized escrow creation.
    if *authority.key() != PLATFORM_AUTHORITY {
        return Err(ERR_UNAUTHORIZED);
    }

    let clock = Clock::get()?;
    if amount == 0 {
        return Err(ERR_ZERO_AMOUNT);
    }
    if cancel_after <= clock.unix_timestamp {
        return Err(ERR_INVALID_CANCEL_AFTER);
    }
    if cancel_after > clock.unix_timestamp + MAX_ESCROW_DURATION {
        return Err(ERR_CANCEL_AFTER_TOO_FAR);
    }

    // invoke_signed rejects the CPI if bump+seeds don't derive escrow.key().
    let rent_lamports: u64 = (EscrowVault::LEN as u64 + 128) * RENT_PER_BYTE;
    let total_lamports = rent_lamports
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    let nonce_bytes = nonce.to_le_bytes();
    let bump_seed   = [bump];
    let seeds = [
        Seed::from(b"escrow".as_ref()),
        Seed::from(buyer.key().as_ref()),
        Seed::from(launch_id.as_ref()),
        Seed::from(nonce_bytes.as_ref()),
        Seed::from(bump_seed.as_ref()),
    ];
    let signer = Signer::from(&seeds[..]);

    CreateAccount {
        from: buyer,
        to:   escrow,
        lamports: total_lamports,
        space:    EscrowVault::LEN as u64,
        owner:    program_id,
    }
    .invoke_signed(&[signer])?;

    // SAFETY: we just created the account with exactly EscrowVault::LEN bytes.
    let vault = unsafe { EscrowVault::load_mut(escrow.borrow_mut_data_unchecked()) };
    vault._discriminator = [0u8; 8];
    vault.buyer        = *buyer.key();
    vault.destination  = *destination.key();
    vault.authority    = *authority.key();
    vault.amount       = amount;
    vault.cancel_after = cancel_after;
    vault.launch_id    = launch_id;
    vault.nonce        = nonce;
    vault.bump         = bump;

    emit_escrow_event(
        EVENT_ESCROW_CREATED,
        0,
        buyer.key(),
        escrow.key(),
        destination.key(),
        amount,
        cancel_after,
        &launch_id,
        nonce,
        bump,
    );

    Ok(())
}

// ── finish_escrow ─────────────────────────────────────────────────────────────
//
// Called by the platform server when the launch goal is reached.
// Sends escrowed SOL to destination and returns rent to authority.
// Only vault.authority (= PLATFORM_AUTHORITY) may call this.
//
// Accounts:
//   0  authority   [signer, writable]  — must be PLATFORM_AUTHORITY & vault.authority
//   1  escrow      [writable]
//   2  destination [writable]          — must match vault.destination; must ≠ authority

fn finish_escrow(program_id: &[u8; 32], accounts: &[AccountInfo]) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let authority   = &accounts[0];
    let escrow      = &accounts[1];
    let destination = &accounts[2];

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !authority.is_writable() || !escrow.is_writable() || !destination.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }

    // Guard against authority == destination aliasing (same account in two slots
    // would corrupt lamport accounting and violate runtime conservation checks).
    if *authority.key() == *destination.key() {
        return Err(ProgramError::InvalidAccountData);
    }

    if escrow.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // SAFETY: owner check above guarantees this is our account with our layout.
    let (escrowed_amount, vault_authority, vault_destination, vault_buyer, vault_launch_id, vault_nonce, vault_bump) = {
        let data = unsafe { escrow.borrow_data_unchecked() };
        if data.len() < EscrowVault::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let vault = unsafe { EscrowVault::load(data) };
        (
            vault.amount,
            vault.authority,
            vault.destination,
            vault.buyer,
            vault.launch_id,
            vault.nonce,
            vault.bump,
        )
    };

    // Only PLATFORM_AUTHORITY (stored at escrow creation) may finish.
    if *authority.key() != vault_authority {
        return Err(ERR_UNAUTHORIZED);
    }
    if *destination.key() != vault_destination {
        return Err(ERR_UNAUTHORIZED);
    }

    // Compute all new balances before touching any account.
    let total        = escrow.lamports();
    let rent_portion = total
        .checked_sub(escrowed_amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let new_dest = destination.lamports()
        .checked_add(escrowed_amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let new_auth = authority.lamports()
        .checked_add(rent_portion)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let clock = Clock::get()?;

    unsafe {
        *escrow.borrow_mut_lamports_unchecked()      = 0;
        *destination.borrow_mut_lamports_unchecked() = new_dest;
        *authority.borrow_mut_lamports_unchecked()   = new_auth;
    }

    emit_escrow_event(
        EVENT_ESCROW_FINISHED,
        0,
        &vault_buyer,
        escrow.key(),
        destination.key(),
        escrowed_amount,
        clock.unix_timestamp,
        &vault_launch_id,
        vault_nonce,
        vault_bump,
    );

    unsafe { escrow.borrow_mut_data_unchecked() }.fill(0);

    Ok(())
}

// ── cancel_escrow ─────────────────────────────────────────────────────────────
//
// Returns escrowed SOL to the buyer.  Two authorised paths:
//   1. PLATFORM_AUTHORITY at any time (early / emergency cancel)
//   2. Anyone at all after cancel_after has passed (permissionless)
//      — buyer gets the escrowed SOL regardless of who triggers this
//      — the canceller (if different from buyer) receives the rent as incentive
//      — if canceller == buyer, buyer receives everything in a single write
//        (avoids lamport aliasing when the same account occupies two slots)
//
// Accounts:
//   0  canceller  [signer, writable]  — any signer after expiry; platform before
//   1  escrow     [writable]
//   2  buyer      [writable]          — must match vault.buyer; always receives SOL

fn cancel_escrow(program_id: &[u8; 32], accounts: &[AccountInfo]) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let canceller = &accounts[0];
    let escrow    = &accounts[1];
    let buyer     = &accounts[2];

    if !canceller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !canceller.is_writable() || !escrow.is_writable() || !buyer.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    if escrow.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // SAFETY: owner check above guarantees this is our account with our layout.
    let (escrowed_amount, vault_authority, vault_buyer, vault_cancel_after, vault_launch_id, vault_nonce, vault_bump) = {
        let data = unsafe { escrow.borrow_data_unchecked() };
        if data.len() < EscrowVault::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let vault = unsafe { EscrowVault::load(data) };
        (
            vault.amount,
            vault.authority,
            vault.buyer,
            vault.cancel_after,
            vault.launch_id,
            vault.nonce,
            vault.bump,
        )
    };

    // The buyer account passed by the caller must match the one stored in the vault.
    if *buyer.key() != vault_buyer {
        return Err(ERR_UNAUTHORIZED);
    }

    let clock        = Clock::get()?;
    let is_authority = *canceller.key() == vault_authority;
    let is_expired   = clock.unix_timestamp > vault_cancel_after;
    if !is_authority && !is_expired {
        return Err(ERR_TOO_EARLY_TO_CANCEL);
    }

    let total        = escrow.lamports();
    let rent_portion = total
        .checked_sub(escrowed_amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // When canceller == buyer (self-cancel), both slots point to the same underlying
    // account. A two-step write would alias: the second write overwrites the first,
    // making the escrowed SOL disappear and failing Solana's lamport conservation check.
    // Fix: detect aliasing and pre-compute a single combined value; one write covers both.
    //
    // All new balances are pre-computed before any write so that a hypothetical overflow
    // error cannot leave the accounts in a partially-updated state.
    let is_self_cancel = *canceller.key() == *buyer.key();

    let new_buyer = buyer
        .lamports()
        .checked_add(if is_self_cancel { total } else { escrowed_amount })
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let new_canceller = if is_self_cancel {
        0 // unused — only one write happens
    } else {
        canceller
            .lamports()
            .checked_add(rent_portion)
            .ok_or(ProgramError::ArithmeticOverflow)?
    };

    unsafe {
        *escrow.borrow_mut_lamports_unchecked()    = 0;
        *buyer.borrow_mut_lamports_unchecked()     = new_buyer;
        if !is_self_cancel {
            *canceller.borrow_mut_lamports_unchecked() = new_canceller;
        }
    }

    emit_escrow_event(
        EVENT_ESCROW_CANCELLED,
        if is_authority {
            FLAG_CANCEL_AUTHORITY
        } else {
            FLAG_CANCEL_PERMISSIONLESS
        },
        &vault_buyer,
        escrow.key(),
        canceller.key(),
        escrowed_amount,
        clock.unix_timestamp,
        &vault_launch_id,
        vault_nonce,
        vault_bump,
    );

    unsafe { escrow.borrow_mut_data_unchecked() }.fill(0);

    Ok(())
}
