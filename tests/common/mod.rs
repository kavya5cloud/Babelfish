use babelfish::{Checksum, Crc16Modbus};

pub fn make_crc16_modbus_frame(data: &[u8]) -> Vec<u8> {
    let crc = Crc16Modbus;
    let checksum = crc.calculate(data);

    let mut frame = data.to_vec();
    frame.extend_from_slice(&(checksum as u16).to_le_bytes());

    frame
}