use crate::{
    common::{MbBuf, ModBusBuffer, Untrusted, Validated},
    errors::MBErr,
    serial::Serial,
    INVALID, VALID,
};
use core::marker::PhantomData;

/// Maximum Modbus Frame Size
pub(crate) const ADU: usize = 260;

pub struct Tcp<'a, S> {
    buf: &'a mut MbBuf,
    len: u16,
    ty: PhantomData<S>,
}

impl<'a> INVALID<'a> for Tcp<'a, Untrusted> {
    type Output = Tcp<'a, Validated>;

    fn validate(self, size: usize) -> Result<Self::Output, MBErr> {
        if size < 8 {
            return Err(MBErr::InputDataTooShort);
        }

        if size > ADU {
            return Err(MBErr::InputDataTooBig);
        }

        // Validate protocol bytes
        if self
            .buf
            .get(ModBusBuffer::MBAP_PID)
            .and_then(|val| val.try_into().ok())
            .map(u16::from_be_bytes)
            != Some(0x0000)
        {
            return Err(MBErr::MBAPInvalidProtocol);
        }

        // Validate MBAP Length bytes
        let Some(len) = self
            .buf
            .get(ModBusBuffer::MBAP_LEN)
            .and_then(|val| val.try_into().ok())
            .map(|val| u16::from_be_bytes(val) + ModBusBuffer::IDX_UID)
            .filter(|val| usize::from(*val) == size)
        else {
            return Err(MBErr::MBAPInvalidLength);
        };

        // Validate supported functioncodes
        if self
            .buf
            .get(ModBusBuffer::IDX_FUNCCODE)
            .filter(|fc| [3, 4, 16].contains(fc))
            .is_none()
        {
            return Err(MBErr::UnsupportedFunctionCode);
        }

        Ok(Tcp {
            buf: self.buf,
            len,
            ty: PhantomData,
        })
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf[..ADU]
    }
}

impl<'a> Tcp<'a, Untrusted> {
    pub fn new(buffer: &'a mut ModBusBuffer) -> Self {
        Self {
            buf: &mut buffer.buf,
            len: 0,
            ty: PhantomData,
        }
    }
}

impl<'a> VALID<'a> for Tcp<'a, Validated> {
    type ConvertType = Serial<'a, Validated>;

    fn convert(self) -> Self::ConvertType {
        Self::ConvertType {
            buf: self.buf,
            len: self.len + 2,
            ty: PhantomData,
        }
    }

    fn as_slice(&self) -> &[u8] {
        self.buf
            .get(..usize::from(self.len))
            .expect("This should never fail")
    }
}

#[cfg(test)]
mod tests {
    use core::panic;

    use super::*;
    use crate::common::ModBusBuffer;
    extern crate std;

    pub(super) fn create_copy_validate_frame<'a>(
        mbb: &'a mut ModBusBuffer,
        data: &[u8],
    ) -> Result<Tcp<'a, Validated>, MBErr> {
        let mut tcp = Tcp::new(mbb);

        let tcp_buf = tcp.as_mut_slice();

        let data_len = data.len();

        if data_len <= ADU {
            tcp_buf
                .get_mut(..data_len)
                .expect("Should fit")
                .copy_from_slice(data);
        }

        tcp.validate(data_len)
    }

    #[test]
    fn inner_buffer_size() {
        let mut mbb = ModBusBuffer::default();
        let mut tcp = Tcp::new(&mut mbb);
        let tcp_buf = tcp.as_mut_slice();
        assert_eq!(tcp_buf.len(), 260);
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
            &[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x02, 0xFF, 0x04],
        ) {
            Ok(_) => (),
            Err(mb_err) => panic!("Frame Should be valid! {mb_err:?}"),
        }

        // Input: Too much (MAX(260) + 1)
        match create_copy_validate_frame(&mut mbb, &std::vec![0; 261]) {
            Ok(_) => panic!("Frame has passed validation!"),
            Err(mb_err) => assert_eq!(mb_err, MBErr::InputDataTooBig),
        }

        // Input: Max MAX(260)
        let mut frame = std::vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 254, 0xFF, 0x04, 0x00, 0x00];
        frame.extend(std::vec![0; 250]);
        assert_eq!(frame.len(), 260);
        match create_copy_validate_frame(&mut mbb, &frame) {
            Ok(_) => (),
            Err(mb_err) => panic!("Frame Should be valid! {mb_err:?}"),
        }

        // Input: Invalid protocol header
        match create_copy_validate_frame(
            &mut mbb,
            &[0xAA, 0xAA, 0x11, 0x11, 0x00, 0x01, 0xFF, 0x04],
        ) {
            Ok(_) => panic!("Frame has passed validation!"),
            Err(mb_err) => assert_eq!(mb_err, MBErr::MBAPInvalidProtocol),
        }

        // Input: Invalid MBAP Length
        match create_copy_validate_frame(
            &mut mbb,
            &[0xAA, 0xAA, 0x00, 0x00, 0x00, 0x01, 0xFF, 0x01],
        ) {
            Ok(_) => panic!("Frame has passed validation!"),
            Err(mb_err) => assert_eq!(mb_err, MBErr::MBAPInvalidLength),
        }

        // Input: Invalid function code
        match create_copy_validate_frame(
            &mut mbb,
            &[0xAA, 0xAA, 0x00, 0x00, 0x00, 0x02, 0xFF, 0x01],
        ) {
            Ok(_) => panic!("Frame has passed validation!"),
            Err(mb_err) => assert_eq!(mb_err, MBErr::UnsupportedFunctionCode),
        }
    }

    #[test]
    fn validation() {
        let mut mbb = ModBusBuffer::default();

        let tcp = match create_copy_validate_frame(
            &mut mbb,
            &[
                0xFF, 0xFF, 0x00, 0x00, 0x00, 0x06, 0xFF, 0x04, 0x12, 0x34, 0xab, 0xcd,
            ],
        ) {
            Ok(tcp) => tcp,
            Err(mb_err) => panic!("Frame Should be valid! {mb_err:?}"),
        };

        assert_eq!(
            tcp.as_slice(),
            &[0xFF, 0xFF, 0x00, 0x00, 0x00, 0x06, 0xFF, 0x04, 0x12, 0x34, 0xab, 0xcd]
        );
    }

    #[test]
    fn validation_max_input() {
        let mut mbb = ModBusBuffer::default();

        let mut frame = std::vec![0xFF, 0xFF, 0x00, 0x00, 0x00, 254, 0xFF, 0x04, 0x00, 0x00];
        frame.extend(std::vec![0; 250]);

        assert_eq!(frame.len(), 260);

        let tcp = match create_copy_validate_frame(&mut mbb, &frame) {
            Ok(tcp) => tcp,
            Err(mb_err) => panic!("Frame Should be valid! {mb_err:?}"),
        };

        assert_eq!(tcp.as_slice(), &frame);
    }
}

#[cfg_attr(feature = "serial", cfg(test))]
mod converttests {
    use super::*;

    extern crate std;

    #[test]
    fn to_serial() {
        let mut mbb = ModBusBuffer::default();

        let frame = [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x04, 0xFF, 0x04, 0x00, 0x00];

        let tcp = match tests::create_copy_validate_frame(&mut mbb, &frame) {
            Ok(tcp) => tcp,
            Err(mb_err) => panic!("Frame Should be valid! {mb_err:?}"),
        };

        assert_eq!(tcp.as_slice(), &frame);

        let serial = tcp.convert();

        assert_eq!(serial.as_slice(), [0xFF, 0x04, 0x00, 0x00, 0x00, 0x00]);
    }
}
