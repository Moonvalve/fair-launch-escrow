/// PDA seeds: [b"escrow", buyer (32), launch_id (32), nonce_le (8)]
///
/// On-disk layout (161 bytes) is identical to the Anchor version so that
/// existing off-chain code reading account data does not need changes:
///   offset  0 –   7 :  discriminator [u8; 8]  (zeros in pinocchio builds)
///   offset  8 –  39 :  buyer       Pubkey
///   offset 40 –  71 :  destination Pubkey
///   offset 72 – 103 :  authority   Pubkey
///   offset 104 – 111:  amount      u64 (le)
///   offset 112 – 119:  cancel_after i64 (le)
///   offset 120 – 151:  launch_id  [u8; 32]
///   offset 152 – 159:  nonce       u64 (le)
///   offset 160      :  bump        u8
///
/// `repr(C, packed)` keeps sizeof == 161 with no end-padding.
#[repr(C, packed)]
pub struct EscrowVault {
    pub _discriminator: [u8; 8],
    pub buyer:          [u8; 32],
    pub destination:    [u8; 32],
    pub authority:      [u8; 32],
    pub amount:         u64,
    pub cancel_after:   i64,
    pub launch_id:      [u8; 32],
    pub nonce:          u64,
    pub bump:           u8,
}

impl EscrowVault {
    /// Byte length of the on-chain account (discriminator + fields, no padding).
    pub const LEN: usize = 8 + 32 + 32 + 32 + 8 + 8 + 32 + 8 + 1; // 161

    /// Zero-copy borrow of account data as `EscrowVault`.
    ///
    /// # Safety
    /// Caller must ensure `data.len() >= EscrowVault::LEN`.
    #[inline(always)]
    pub unsafe fn load(data: &[u8]) -> &Self {
        &*(data.as_ptr() as *const Self)
    }

    /// Zero-copy mutable borrow of account data as `EscrowVault`.
    ///
    /// # Safety
    /// Caller must ensure `data.len() >= EscrowVault::LEN` and exclusive access.
    #[inline(always)]
    pub unsafe fn load_mut(data: &mut [u8]) -> &mut Self {
        &mut *(data.as_mut_ptr() as *mut Self)
    }
}
