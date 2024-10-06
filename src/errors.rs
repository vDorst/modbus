/// Mobus Errors
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    #[cfg(feature = "tcp")]
    MBAPInvalidProtocol,
    #[cfg(feature = "tcp")]
    MBAPInvalidLength,
    InputDataTooShort,
    InputDataTooBig,
    UnsupportedFunctionCode,
    #[cfg(feature = "serial")]
    CRC,
    UnwrapIssue,
}
