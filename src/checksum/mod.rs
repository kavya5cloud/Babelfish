pub mod algorithms;
pub mod crc;
pub mod crc8;
pub mod search;
pub mod simple;

pub use algorithms::{Checksum, XorChecksum};
pub use crc::Crc16Modbus;
pub use crc8::Crc8;
pub use simple::{Sum8, Sum16};
