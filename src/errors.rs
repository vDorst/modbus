#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MBErr {
    MBAPInvalidProtocol,
    MBAPInvalidLength,
    UnwrapIssue,
    InputDataTooShort,
    InputDataTooBig,
    UnsupportedFunctionCode,
    CRC,
}
