use std::time::SystemTime;

// Reuse core logic between different seed sources
pub trait IntoSeed {
    fn into_seed(self) -> u32;
}

impl IntoSeed for u16 {
    fn into_seed(self) -> u32 {
        let first_byte = (self & 0xFF00) >> 8;
        let second_byte = self & 0x00FF;

        u32::from_be_bytes([0, 0, first_byte as u8, second_byte as u8])
    }
}

impl IntoSeed for u32 {
    fn into_seed(self) -> u32 {
        self
    }
}

// Simplify using timestamp as seed
impl IntoSeed for SystemTime {
    fn into_seed(self) -> u32 {
        let secs = self
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        secs as u32
    }
}
