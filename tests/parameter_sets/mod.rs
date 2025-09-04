use slhdsa_c_rs::bindings;

pub(crate) trait ParameterSet {
    fn ptr() -> &'static bindings::slh_param_s;
}

macro_rules! define_param_set {
    ( $( $name:ident => $binding:ident ),+ $(,)? ) => {
        $(
            #[expect(non_camel_case_types)]
            pub(crate) struct $name;

            impl ParameterSet for $name {
                fn ptr() -> &'static bindings::slh_param_s {
                    unsafe { &bindings::$binding }
                }
            }
        )+
    };
}

define_param_set! {
    SLH_DSA_SHAKE_128s => slh_dsa_shake_128s,
    SLH_DSA_SHAKE_128f => slh_dsa_shake_128f,
    SLH_DSA_SHAKE_192s => slh_dsa_shake_192s,
    SLH_DSA_SHAKE_192f => slh_dsa_shake_192f,
    SLH_DSA_SHAKE_256s => slh_dsa_shake_256s,
    SLH_DSA_SHAKE_256f => slh_dsa_shake_256f,

    SLH_DSA_SHA2_128s => slh_dsa_sha2_128s,
    SLH_DSA_SHA2_128f => slh_dsa_sha2_128f,
    SLH_DSA_SHA2_192s => slh_dsa_sha2_192s,
    SLH_DSA_SHA2_192f => slh_dsa_sha2_192f,
    SLH_DSA_SHA2_256s => slh_dsa_sha2_256s,
    SLH_DSA_SHA2_256f => slh_dsa_sha2_256f,
}
