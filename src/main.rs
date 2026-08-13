use babelfish::{Checksum, Crc16Modbus};

fn main() {
    let crc = Crc16Modbus;

    let data = b"123456789";
    let result = crc.calculate(data);

    println!("Algorithm: {}", crc.name());
    println!("Input: 123456789");
    println!("CRC: 0x{:04X}", result);
}