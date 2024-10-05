//! Some docs

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

pub use errors::MBErr;
pub use serial::Serial;
pub use tcp::Tcp;

/// `INVALID` value
pub trait INVALID<'mbb> {
    type Output;

    /// Validate the raw frame
    fn validate(self, size: usize) -> Result<Self::Output, MBErr>;

    /// give the raw buffer to store the raw frame
    fn as_mut_slice(&mut self) -> &mut [u8];
}

pub trait VALID<'mbb> {
    type ConvertType;

    fn convert(self) -> Self::ConvertType;

    fn as_slice(&self) -> &[u8];
}
