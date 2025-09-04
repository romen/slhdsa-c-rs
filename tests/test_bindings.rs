mod common;
mod helpers;
mod parameter_sets;

use parameter_sets::*;
use slhdsa_c_rs::bindings;

fn test_sign_verify<P: ParameterSet>() {
    unsafe {
        let prm = P::ptr();

        let id = bindings::slh_alg_id(std::ptr::from_ref(prm));
        let id = core::ffi::CStr::from_ptr(id)
            .to_str()
            .expect("Invalid CStr");
        log::info!("id={:?}", id);

        let sk_sz = bindings::slh_sk_sz(std::ptr::from_ref(prm));
        log::info!("sk_sz={:?}", sk_sz);
        let pk_sz = bindings::slh_pk_sz(std::ptr::from_ref(prm));
        log::info!("pk_sz={:?}", pk_sz);
        let sig_sz = bindings::slh_sig_sz(std::ptr::from_ref(prm));
        log::info!("sig_sz={:?}", sig_sz);

        let mut sk: Vec<u8> = vec![0; sk_sz];
        let mut pk: Vec<u8> = vec![0; pk_sz];

        let rbg = helpers::randombytes;

        let ret = bindings::slh_keygen(sk.as_mut_ptr(), pk.as_mut_ptr(), Some(rbg), prm);
        assert_eq!(ret, 0);

        log::info!("sk={:x?}", sk);
        log::info!("pk={:x?}", pk);

        let msg: &[u8] = &[1, 2, 3, 4, 5];
        log::info!("msg={:?}", msg);

        let ctx: &[u8] = &[];
        log::info!("ctx={:x?}", ctx);

        let mut sig: Vec<u8> = vec![0; sig_sz];
        let addrnd = ::core::ptr::null();

        let ret = bindings::slh_sign(
            sig.as_mut_ptr(),
            msg.as_ptr(),
            msg.len(),
            ctx.as_ptr(),
            ctx.len(),
            sk.as_ptr(),
            addrnd,
            prm,
        );
        assert_eq!(ret, sig_sz);
        log::debug!("sig={:x?}", sig);

        let ret = bindings::slh_verify(
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
            ctx.as_ptr(),
            ctx.len(),
            pk.as_ptr(),
            prm,
        );
        log::info!("slh_verify() returned {:x?} on happy path", ret);
        assert_eq!(ret, 1);

        {
            let msg: &[u8] = &[1, 2, 3, 4, 5, 6];

            let ret = bindings::slh_verify(
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
                sig.len(),
                ctx.as_ptr(),
                ctx.len(),
                pk.as_ptr(),
                prm,
            );
            log::info!("slh_verify() returned {:x?} on tampered message", ret);
            assert_eq!(ret, 0);
        }

        {
            let mut sk: Vec<u8> = vec![0; sk_sz];
            let mut pk: Vec<u8> = vec![0; pk_sz];

            let ret = bindings::slh_keygen(sk.as_mut_ptr(), pk.as_mut_ptr(), Some(rbg), prm);
            assert_eq!(ret, 0);

            let ret = bindings::slh_verify(
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
                sig.len(),
                ctx.as_ptr(),
                ctx.len(),
                pk.as_ptr(),
                prm,
            );
            log::info!("slh_verify() returned {:x?} on wrong pk", ret);
            assert_eq!(ret, 0);
        }
    }
}

macro_rules! gen_basic_binding_tests {
    ( $( $ty:ident ),+ $(,)? ) => {
        $(
            paste::paste! {
                #[test]
                fn [<basic_bindings_test_ $ty:lower>]() {
                    common::setup().expect("Failed during initial setup");
                    test_sign_verify::<$ty>();
                }
            }
        )+
    };
}

gen_basic_binding_tests!(
    SLH_DSA_SHAKE_128s,
    SLH_DSA_SHAKE_128f,
    SLH_DSA_SHAKE_192s,
    SLH_DSA_SHAKE_192f,
    SLH_DSA_SHAKE_256s,
    SLH_DSA_SHAKE_256f,
    SLH_DSA_SHA2_128s,
    SLH_DSA_SHA2_128f,
    SLH_DSA_SHA2_192s,
    SLH_DSA_SHA2_192f,
    SLH_DSA_SHA2_256s,
    SLH_DSA_SHA2_256f,
);
