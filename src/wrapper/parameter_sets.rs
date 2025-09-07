//! This module defines the concrete parameter sets for the SLH-DSA standard

pub use pure_slhdsa::*;

/// This module defines concrete parameter sets for Pure SLH-DSA schemes
pub mod pure_slhdsa {

    /// SHA2-based Pure SLH-DSA parameters
    pub mod sha2_based {
        use crate::wrapper;
        use wrapper::{
            ffi, typenum, utils::macros::define_param_set, FFIParams, ParameterSet, SignatureLen,
            SigningKeyLen, VerifyingKeyLen,
        };

        define_param_set!(
            "SLH-DSA-SHA2-128s",
            "2.16.840.1.101.3.4.3.20", // From https://www.ietf.org/archive/id/draft-ietf-lamps-x509-slhdsa-09.html#section-3-7
            32,
            typenum::U32,
            64,
            typenum::U64,
            7856,
            typenum::U7856,
            SLH_DSA_SHA2_128s,
            crate::ffi::slh_dsa_sha2_128s
        );
        define_param_set!(
            "SLH-DSA-SHA2-128f",
            "2.16.840.1.101.3.4.3.21", // From https://www.ietf.org/archive/id/draft-ietf-lamps-x509-slhdsa-09.html#section-3-7
            32,
            typenum::U32,
            64,
            typenum::U64,
            17088,
            typenum::U17088,
            SLH_DSA_SHA2_128f,
            crate::ffi::slh_dsa_sha2_128f
        );
        define_param_set!(
            "SLH-DSA-SHA2-192s",
            "2.16.840.1.101.3.4.3.22", // From https://www.ietf.org/archive/id/draft-ietf-lamps-x509-slhdsa-09.html#section-3-7
            48,
            typenum::U48,
            96,
            typenum::U96,
            16224,
            typenum::U16224,
            SLH_DSA_SHA2_192s,
            crate::ffi::slh_dsa_sha2_192s
        );
        define_param_set!(
            "SLH-DSA-SHA2-192f",
            "2.16.840.1.101.3.4.3.23", // From https://www.ietf.org/archive/id/draft-ietf-lamps-x509-slhdsa-09.html#section-3-7
            48,
            typenum::U48,
            96,
            typenum::U96,
            35664,
            typenum::U35664,
            SLH_DSA_SHA2_192f,
            crate::ffi::slh_dsa_sha2_192f
        );
        define_param_set!(
            "SLH-DSA-SHA2-256s",
            "2.16.840.1.101.3.4.3.24", // From https://www.ietf.org/archive/id/draft-ietf-lamps-x509-slhdsa-09.html#section-3-7
            64,
            typenum::U64,
            128,
            typenum::U128,
            29792,
            typenum::U29792,
            SLH_DSA_SHA2_256s,
            crate::ffi::slh_dsa_sha2_256s
        );
        define_param_set!(
            "SLH-DSA-SHA2-256f",
            "2.16.840.1.101.3.4.3.25", // From https://www.ietf.org/archive/id/draft-ietf-lamps-x509-slhdsa-09.html#section-3-7
            64,
            typenum::U64,
            128,
            typenum::U128,
            49856,
            typenum::U49856,
            SLH_DSA_SHA2_256f,
            crate::ffi::slh_dsa_sha2_256f
        );
    }

    /// SHAKE-based Pure SLH-DSA parameters
    pub mod shake_based {
        use crate::wrapper;
        use wrapper::{
            ffi, typenum, utils::macros::define_param_set, FFIParams, ParameterSet, SignatureLen,
            SigningKeyLen, VerifyingKeyLen,
        };

        define_param_set!(
            "SLH-DSA-SHAKE-128s",
            "2.16.840.1.101.3.4.3.26", // From https://www.ietf.org/archive/id/draft-ietf-lamps-x509-slhdsa-09.html#section-3-7
            32,
            typenum::U32,
            64,
            typenum::U64,
            7856,
            typenum::U7856,
            SLH_DSA_SHAKE_128s,
            crate::ffi::slh_dsa_shake_128s
        );

        define_param_set!(
            "SLH-DSA-SHAKE-128f",
            "2.16.840.1.101.3.4.3.27", // From https://www.ietf.org/archive/id/draft-ietf-lamps-x509-slhdsa-09.html#section-3-7
            32,
            typenum::U32,
            64,
            typenum::U64,
            17088,
            typenum::U17088,
            SLH_DSA_SHAKE_128f,
            crate::ffi::slh_dsa_shake_128f
        );
        define_param_set!(
            "SLH-DSA-SHAKE-192s",
            "2.16.840.1.101.3.4.3.28", // From https://www.ietf.org/archive/id/draft-ietf-lamps-x509-slhdsa-09.html#section-3-7
            48,
            typenum::U48,
            96,
            typenum::U96,
            16224,
            typenum::U16224,
            SLH_DSA_SHAKE_192s,
            crate::ffi::slh_dsa_shake_192s
        );
        define_param_set!(
            "SLH-DSA-SHAKE-192f",
            "2.16.840.1.101.3.4.3.29", // From https://www.ietf.org/archive/id/draft-ietf-lamps-x509-slhdsa-09.html#section-3-7
            48,
            typenum::U48,
            96,
            typenum::U96,
            35664,
            typenum::U35664,
            SLH_DSA_SHAKE_192f,
            crate::ffi::slh_dsa_shake_192f
        );
        define_param_set!(
            "SLH-DSA-SHAKE-256s",
            "2.16.840.1.101.3.4.3.30", // From https://www.ietf.org/archive/id/draft-ietf-lamps-x509-slhdsa-09.html#section-3-7
            64,
            typenum::U64,
            128,
            typenum::U128,
            29792,
            typenum::U29792,
            SLH_DSA_SHAKE_256s,
            crate::ffi::slh_dsa_shake_256s
        );
        define_param_set!(
            "SLH-DSA-SHAKE-256f",
            "2.16.840.1.101.3.4.3.31", // From https://www.ietf.org/archive/id/draft-ietf-lamps-x509-slhdsa-09.html#section-3-7
            64,
            typenum::U64,
            128,
            typenum::U128,
            49856,
            typenum::U49856,
            SLH_DSA_SHAKE_256f,
            crate::ffi::slh_dsa_shake_256f
        );
    }

    pub use sha2_based::*;
    pub use shake_based::*;
}
