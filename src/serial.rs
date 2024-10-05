/// Maximum Modbus Frame Size
pub(super) const ADU: usize = 256;

use crate::{
    common::{MbBuf, ModBusBuffer, Untrusted, Validated},
    crc::crc16,
    errors::MBErr,
    tcp::Tcp,
    INVALID, VALID,
};
use core::marker::PhantomData;

pub struct Serial<'a, S> {
    pub(crate) buf: &'a mut MbBuf,
    pub(crate) len: u16,
    pub(crate) ty: PhantomData<S>,
}

impl<'a> INVALID<'a> for Serial<'a, Untrusted> {
    type Output = Serial<'a, Validated>;

    fn validate(self, size: usize) -> Result<Self::Output, MBErr> {
        if size < 4 {
            return Err(MBErr::InputDataTooShort);
        }

        if size > ADU {
            return Err(MBErr::InputDataTooBig);
        }

        let ser_start = usize::from(ModBusBuffer::IDX_UID);
        let ser_end = ser_start + size;

        let Ok(len) = u16::try_from(ser_end) else {
            return Err(MBErr::InputDataTooBig);
        };

        // Validate CRC
        let Some((calc_crc, crc)) = self
            .buf
            .get(ser_start..ser_end)
            .and_then(|val| val.split_at_checked(size - ModBusBuffer::CRC_LEN))
            .and_then(|(data, crc)| {
                let crc_calc = crc16(data);

                crc.try_into()
                    .ok()
                    .map(|val| (crc_calc, u16::from_be_bytes(val)))
            })
        else {
            return Err(MBErr::InputDataTooBig);
        };

        if crc != calc_crc {
            #[cfg(test)]
            {
                extern crate std;
                std::println!("CRC: CALC: {calc_crc:04x} PROVIDES: {crc:04x}");
            }
            return Err(MBErr::CRC);
        }

        // Validate supported functioncodes
        if self
            .buf
            .get(ModBusBuffer::IDX_FUNCCODE)
            .filter(|fc| [3, 4, 15, 16].contains(fc))
            .is_none()
        {
            return Err(MBErr::UnsupportedFunctionCode);
        }

        Ok(Serial {
            buf: self.buf,
            len,
            ty: PhantomData,
        })
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buf
            .get_mut(usize::from(ModBusBuffer::IDX_UID)..usize::from(ModBusBuffer::IDX_UID) + ADU)
            .expect("Should never fail")
    }
}

impl<'a> Serial<'a, Untrusted> {
    pub fn new(buffer: &'a mut ModBusBuffer) -> Self {
        Self {
            buf: &mut buffer.buf,
            len: 0,
            ty: PhantomData,
        }
    }
}

impl<'a> VALID<'a> for Serial<'a, Validated> {
    type ConvertType = Tcp<'a, Validated>;

    fn convert(self) -> Self::ConvertType {
        todo!()
    }

    fn as_slice(&self) -> &[u8] {
        self.buf
            .get(usize::from(ModBusBuffer::IDX_UID)..usize::from(self.len))
            .expect("Should never fail, length was validated")
    }
}

#[cfg(test)]
mod tests {
    use core::panic;

    use super::*;
    use crate::common::ModBusBuffer;
    extern crate std;

    fn create_copy_validate_frame<'a>(
        mbb: &'a mut ModBusBuffer,
        data: &[u8],
    ) -> Result<Serial<'a, Validated>, MBErr> {
        let mut serial = Serial::new(mbb);

        let serial_buf = serial.as_mut_slice();

        let data_len = data.len();

        if data_len <= ADU {
            serial_buf
                .get_mut(..data_len)
                .expect("Should fit")
                .copy_from_slice(data);
        }

        serial.validate(data_len)
    }

    #[test]
    fn inner_buffer_size() {
        let mut mbb = ModBusBuffer::default();
        let mut tcp = Serial::new(&mut mbb);
        let tcp_buf = tcp.as_mut_slice();
        assert_eq!(tcp_buf.len(), 256);
    }

    #[test]
    fn basic_validation() {
        let mut mbb = ModBusBuffer::default();

        // Input: Too little
        match create_copy_validate_frame(&mut mbb, &[]) {
            Ok(_) => panic!("Frame has passed validation!"),
            Err(mb_err) => assert_eq!(mb_err, MBErr::InputDataTooShort),
        }

        // Input: Min(8)
        match create_copy_validate_frame(
            &mut mbb,
            &[0xFF, 0x04, 0x00, 0x00, 0x00, 0x01, 0x14, 0x24],
        ) {
            Ok(_) => (),
            Err(mb_err) => panic!("Frame Should be valid! {mb_err:?}"),
        }

        // Input: Too much (MAX(260) + 1)
        match create_copy_validate_frame(&mut mbb, &std::vec![0; 257]) {
            Ok(_) => panic!("Frame has passed validation!"),
            Err(mb_err) => assert_eq!(mb_err, MBErr::InputDataTooBig),
        }

        // Input: Max MAX(260)
        let mut frame = std::vec![0xFF, 0x04, 0x01, 0x01];
        frame.extend(std::vec![0; 250]);
        frame.extend(std::vec![0x3f, 0x1f]);
        assert_eq!(frame.len(), 256);
        match create_copy_validate_frame(&mut mbb, &frame) {
            Ok(_) => (),
            Err(mb_err) => panic!("Frame Should be valid! {mb_err:?}"),
        }

        // Input: Invalid function code
        match create_copy_validate_frame(&mut mbb, &[0x01, 0x01, 0xe0, 0xc1]) {
            Ok(_) => panic!("Frame has passed validation!"),
            Err(mb_err) => assert_eq!(mb_err, MBErr::UnsupportedFunctionCode),
        }

        // Input: Faulty crc LSB
        match create_copy_validate_frame(&mut mbb, &[0x01, 0x01, 0xe0, 0xc0]) {
            Ok(_) => panic!("Frame has passed validation!"),
            Err(mb_err) => assert_eq!(mb_err, MBErr::CRC),
        }
        // Input: Faulty crc MSB
        match create_copy_validate_frame(&mut mbb, &[0x01, 0x01, 0xe1, 0xc1]) {
            Ok(_) => panic!("Frame has passed validation!"),
            Err(mb_err) => assert_eq!(mb_err, MBErr::CRC),
        }
    }
}
