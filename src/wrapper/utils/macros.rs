macro_rules! define_param_set {
    // name, oid, sizes + their typenum types, chosen struct ident, chosen ffi ident
    ($name:literal, $oid:literal,
     $vk_len:literal, $vk_len_ty:ty,
     $sk_len:literal, $sk_len_ty:ty,
     $sig_len:literal, $sig_len_ty:ty,
     $TypeIdent:ident, $ffi_path:path) => {
        #[allow(non_camel_case_types)]
        #[derive(PartialEq, Eq, Clone, Debug)]
        #[doc = concat!("Implements ", $name, " as described in NIST [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).")]
        pub struct $TypeIdent {}
        impl FFIParams for $TypeIdent {
            fn prm() -> &'static ffi::slh_param_s {
                unsafe { &$ffi_path }
            }
        }
        impl SignatureLen for $TypeIdent {
            const SIGNATURE_LEN: usize = $sig_len;
            type LEN = $sig_len_ty;
        }
        impl SigningKeyLen for $TypeIdent {
            const SIGNING_KEY_LEN: usize = $sk_len;
            type LEN = $sk_len_ty;
        }
        impl VerifyingKeyLen for $TypeIdent {
            const VERIFYING_KEY_LEN: usize = $vk_len;
            type LEN = $vk_len_ty;
        }
        impl ParameterSet for $TypeIdent {
            const NAME: &'static str = $name;
            const ALGORITHM_OID_STR: &'static str = $oid;
        }
    };
}
pub(crate) use define_param_set;

#[cfg(test)]
pub(crate) mod macros_for_tests {
    /// Generate a test case
    macro_rules! gen_test {
        ($name:ident, $t:ty) => {
            paste::paste! {
            #[test]
            fn [<$name _ $t:lower>]() {
                $name::<$t>()
            }
            }
        };
    }
    pub(crate) use gen_test;

    macro_rules! test_parameter_sets {
        ($name:ident) => {
            gen_test!($name, SLH_DSA_SHA2_128s);
            gen_test!($name, SLH_DSA_SHA2_128f);
            gen_test!($name, SLH_DSA_SHA2_192s);
            gen_test!($name, SLH_DSA_SHA2_192f);
            gen_test!($name, SLH_DSA_SHA2_256s);
            gen_test!($name, SLH_DSA_SHA2_256f);

            gen_test!($name, SLH_DSA_SHAKE_128s);
            gen_test!($name, SLH_DSA_SHAKE_128f);
            gen_test!($name, SLH_DSA_SHAKE_192s);
            gen_test!($name, SLH_DSA_SHAKE_192f);
            gen_test!($name, SLH_DSA_SHAKE_256s);
            gen_test!($name, SLH_DSA_SHAKE_256f);
        };
    }
    pub(crate) use test_parameter_sets;
}
#[cfg(test)]
pub(crate) use macros_for_tests::*;
