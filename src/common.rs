use core::ops::Range;

/// Frame is untrusted
pub(crate) struct Untrusted;

/// Frame is validated.
pub(crate) struct Validated;

#[cfg(all(feature = "serial", not(feature = "tcp")))]
pub(crate) const MB_MAX_SIZE: usize = crate::serial::ADU;
#[cfg(all(not(feature = "serial"), feature = "tcp"))]
pub(crate) const MB_MAX_SIZE: usize = crate::tcp::ADU;
#[cfg(all(feature = "serial", feature = "tcp"))]
pub(crate) const MB_MAX_SIZE: usize = if crate::tcp::ADU > 6 + crate::serial::ADU {
    crate::tcp::ADU
} else {
    6 + crate::serial::ADU
};

pub(crate) type MbBuf = [u8; MB_MAX_SIZE];

pub struct ModBusBuffer {
    pub(crate) buf: MbBuf,
}

impl Default for ModBusBuffer {
    fn default() -> Self {
        Self {
            buf: [0; MB_MAX_SIZE],
        }
    }
}

impl ModBusBuffer {
    /// Location Unit Unit ID
    pub(crate) const IDX_UID: u16 = 6;

    #[expect(dead_code)]
    pub(crate) const PDU_STAT: u16 = 7;
    #[expect(dead_code)]
    /// Transaction Identifier
    pub(crate) const MBAP_TID: Range<usize> = 0..2;
    /// Protocol Identifier
    pub(crate) const MBAP_PID: Range<usize> = 2..4;
    /// Protocol Identifier
    pub(crate) const MBAP_LEN: Range<usize> = 4..6;
    #[expect(dead_code)]
    /// Unit Identifier
    pub(crate) const MBAP_UID: usize = 6;

    /// Size of the CRC
    pub(crate) const CRC_LEN: usize = 2;

    /// Function Code
    pub(crate) const IDX_FUNCCODE: usize = 7;

    #[expect(dead_code)]
    /// PDU Data
    pub(crate) const IDX_PDU_DATA: usize = 8;

    // pub fn validate(&mut self, len: usize) -> Result<(), MBErr> {
    //     if len < 8 {
    //         return Err(MBErr::SizeToBig);
    //     }

    //     let new_len = PacketLen::try_from(len)?;

    //     if self
    //         .buf
    //         .get(Self::MBAP_PID)
    //         .and_then(|val| val.try_into().ok())
    //         .map(|val| usize::from(u16::from_ne_bytes(val)))
    //         != Some(0x0000)
    //     {
    //         return Err(MBErr::MBAPInvalidLength);
    //     }

    //     if self
    //         .buf
    //         .get(Self::MBAP_LEN)
    //         .and_then(|val| val.try_into().ok())
    //         .map(|val| usize::from(u16::from_ne_bytes(val)))
    //         != Some(len - usize::from(Self::PDU_STAT))
    //     {
    //         return Err(MBErr::SizeToBig);
    //     }

    //     Ok(())
    // }
}
