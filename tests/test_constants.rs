#![cfg(feature = "wrapper")]

mod common;

use slhdsa_c_rs::{ParameterSet, SLH_DSA_SHAKE_128s};

fn test_constants<P: ParameterSet>() {
    assert_eq!(P::SIGNATURE_LEN, P::signature_len());
    assert_eq!(P::SIGNING_KEY_LEN, P::signing_key_len());
    assert_eq!(P::SIGNING_KEY_LEN, P::SECRET_KEY_LEN);
    assert_eq!(P::VERIFYING_KEY_LEN, P::verifying_key_len());
    assert_eq!(P::VERIFYING_KEY_LEN, P::PUBLIC_KEY_LEN);
    assert_eq!(P::NAME, P::algorithm_name());
}

macro_rules! gen_constants_tests {
    ( $( $ty:ident ),+ $(,)? ) => {
        $(
            paste::paste! {
                #[test]
                fn [<constants_test_ $ty:lower>]() {
                    common::setup().expect("Failed during initial setup");

                    test_constants::<$ty>();
                }
            }
        )+
    };
}

gen_constants_tests!(
    SLH_DSA_SHAKE_128s,
    //    SLH_DSA_SHAKE_128f,
    //    SLH_DSA_SHAKE_192s,
    //    SLH_DSA_SHAKE_192f,
    //    SLH_DSA_SHAKE_256s,
    //    SLH_DSA_SHAKE_256f,
    //    SLH_DSA_SHA2_128s,
    //    SLH_DSA_SHA2_128f,
    //    SLH_DSA_SHA2_192s,
    //    SLH_DSA_SHA2_192f,
    //    SLH_DSA_SHA2_256s,
    //    SLH_DSA_SHA2_256f,
);
