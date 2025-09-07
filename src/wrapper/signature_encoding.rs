use generic_array::GenericArray;

use super::ParameterSet;

/// Represents a signature using the specified parameter set.
#[derive(Clone, Debug)]
pub struct Signature<P: ParameterSet> {
    pub(super) sig: GenericArray<u8, <P as crate::SignatureLen>::LEN>,
}
