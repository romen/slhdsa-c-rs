use core::convert::TryFrom;

/// Error type for transcoding operations.
#[derive(Debug)]
pub struct TranscodingError;

impl core::error::Error for TranscodingError {}

impl core::fmt::Display for TranscodingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Transcoding error")
    }
}

/// Trait for types that can be represented as a byte slice.
pub trait AsBytes: AsRef<[u8]> {
    /// Returns a reference to the underlying byte slice.
    #[inline]
    fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }
}

// Anything that is `AsRef<[u8]>` gets `ToBytes` for free.
impl<T> AsBytes for T where T: AsRef<[u8]> {}

/// Fallible parse from a byte slice.
pub trait FromBytes: Sized {
    /// The error type returned when parsing from bytes fails.
    type Error;

    /// Try to build an instance of this object from a byte slice.
    ///
    /// # Errors
    ///
    /// This function will return [`Self::Error`] on failure.
    fn from_bytes(input: &[u8]) -> Result<Self, Self::Error>;
}

// Blanket impl: any `T` that can `TryFrom<&[u8]>` with a *single* error type `E`
// (independent of the slice lifetime) implements `FromBytes`.
impl<T, E> FromBytes for T
where
    for<'a> T: TryFrom<&'a [u8], Error = E>,
{
    type Error = E;

    #[inline]
    fn from_bytes(input: &[u8]) -> Result<Self, Self::Error> {
        <T as TryFrom<&[u8]>>::try_from(input)
    }
}
