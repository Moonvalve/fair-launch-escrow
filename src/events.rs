use core::ptr::copy_nonoverlapping;

use pinocchio::syscalls::sol_log_data;

pub const EVENT_VERSION: u8 = 1;
pub const EVENT_ESCROW_CREATED: u8 = 0;
pub const EVENT_ESCROW_FINISHED: u8 = 1;
pub const EVENT_ESCROW_CANCELLED: u8 = 2;

pub const FLAG_CANCEL_PERMISSIONLESS: u8 = 1;
pub const FLAG_CANCEL_AUTHORITY: u8 = 2;

pub const EVENT_LEN: usize = 156;

#[repr(C)]
struct SolBytes {
    addr: *const u8,
    len: u64,
}

#[inline(always)]
fn put<const N: usize>(data: &mut [u8; EVENT_LEN], offset: usize, bytes: &[u8; N]) {
    unsafe {
        copy_nonoverlapping(bytes.as_ptr(), data.as_mut_ptr().add(offset), N);
    }
}

#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn emit_escrow_event(
    event_type: u8,
    flags: u8,
    buyer: &[u8; 32],
    escrow_pda: &[u8; 32],
    counterparty: &[u8; 32],
    amount: u64,
    timestamp_or_cancel_after: i64,
    launch_id: &[u8; 32],
    nonce: u64,
    bump: u8,
) {
    let mut data = [0u8; EVENT_LEN];

    data[0] = EVENT_VERSION;
    data[1] = event_type;
    data[2] = flags;
    put(&mut data, 3, buyer);
    put(&mut data, 35, escrow_pda);
    put(&mut data, 67, counterparty);

    let amount_bytes = amount.to_le_bytes();
    let timestamp_bytes = timestamp_or_cancel_after.to_le_bytes();
    let nonce_bytes = nonce.to_le_bytes();

    put(&mut data, 99, &amount_bytes);
    put(&mut data, 107, &timestamp_bytes);
    put(&mut data, 115, launch_id);
    put(&mut data, 147, &nonce_bytes);
    data[155] = bump;

    let fields = [SolBytes {
        addr: data.as_ptr(),
        len: EVENT_LEN as u64,
    }];

    unsafe {
        sol_log_data(fields.as_ptr() as *const u8, fields.len() as u64);
    }
}
