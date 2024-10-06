#![no_std]
#![deny(
    clippy::unwrap_used,
    clippy::should_panic_without_expect,
    clippy::indexing_slicing,
    clippy::pedantic
)]
#![warn(clippy::nursery)]
#![allow(clippy::redundant_pub_crate)]
#![allow(clippy::missing_errors_doc)]

mod common;
#[cfg(feature = "serial")]
mod crc;
mod errors;
#[cfg(feature = "serial")]
mod serial;
#[cfg(feature = "tcp")]
mod tcp;

pub use common::ModBusBuffer;
pub use errors::Error;
#[cfg(feature = "serial")]
pub use serial::Serial;
#[cfg(feature = "tcp")]
pub use tcp::Tcp;

/// `INVALID` value
pub trait UntrustedData<'mbb> {
    type Output;

    /// Validate the raw frame
    fn validate(self, size: usize) -> Result<Self::Output, Error>;

    /// give the raw buffer to store the raw frame
    fn as_mut_slice(&mut self) -> &mut [u8];
}

pub trait ValidatedData<'mbb> {
    fn as_slice(&self) -> &[u8];
}

#[cfg(feature = "gateway")]
pub trait ConvertData<'mbb> {
    type ConvertType;

    fn convert(self) -> Self::ConvertType;
}
