pub use generic_array::typenum::*;

/// Turn a sequence of bits into a typenum Unsigned.
///
/// Note that the macro argument is sequenced LSB -> MSB
///
/// # Usage
///
/// ```rustdoc_cannot_access_non-pub
/// // 13 (0b1101)
/// type U13 = u_from_bits!(1 0 1 1);
/// assert_eq!(U13::USIZE, 13);
/// ```
macro_rules! u_from_bits {
    () => { UTerm };
    (0 $($rest:tt)*) => { UInt<u_from_bits!($($rest)*), B0> };
    (1 $($rest:tt)*) => { UInt<u_from_bits!($($rest)*), B1> };
}

// 7856 (0b1111010110000)
pub type U7856 = u_from_bits!(0 0 0 0 1 1 0 1 0 1 1 1 1);
// 16224 (0b11111101100000)
pub type U16224 = u_from_bits!(0 0 0 0 0 1 1 0 1 1 1 1 1 1);
// 17088 (0b100001011000000)
pub type U17088 = u_from_bits!(0 0 0 0 0 0 1 1 0 1 0 0 0 0 1);
// 29792 (0b111010001100000)
pub type U29792 = u_from_bits!(0 0 0 0 0 1 1 0 0 0 1 0 1 1 1);
// 35664 (0b1000101101010000)
pub type U35664 = u_from_bits!(0 0 0 0 1 0 1 0 1 1 0 1 0 0 0 1);
// 49856 (0b1100001011000000)
pub type U49856 = u_from_bits!(0 0 0 0 0 0 1 1 0 1 0 0 0 0 1 1);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_custom_typenums() {
        assert_eq!(U7856::USIZE, 7856);
        assert_eq!(U16224::USIZE, 16224);
        assert_eq!(U17088::USIZE, 17088);
        assert_eq!(U29792::USIZE, 29792);
        assert_eq!(U35664::USIZE, 35664);
        assert_eq!(U49856::USIZE, 49856);
    }
}
