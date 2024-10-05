/// CRC-16-IBM/CRC-16-ANSI
#[allow(clippy::module_name_repetitions)]
#[must_use]
pub(crate) fn crc16(data: &[u8]) -> u16 {
    data.iter().fold(0xFFFF_u16, |mut crc, &byte| {
        crc ^= u16::from(byte);
        for _ in 0..u8::BITS {
            let is_lsb_set = (crc & 0x0001) != 0;
            crc >>= 1;
            if is_lsb_set {
                crc ^= 0xA001;
            }
        }
        crc
    })
}
