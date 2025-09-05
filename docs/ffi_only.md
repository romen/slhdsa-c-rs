This crate only provides FFI bindings, unless the `wrapper` feature is
enabled.

```rust
use slhdsa_c_rs::ffi;

unsafe {
  let prm = &ffi::slh_dsa_shake_192f;

  let id = ffi::slh_alg_id(core::ptr::from_ref(prm));
  let id = core::ffi::CStr::from_ptr(id)
      .to_str()
      .expect("Invalid CStr");
  println!("id={:?}", id);

  let sk_sz = ffi::slh_sk_sz(core::ptr::from_ref(prm));
  println!("sk_sz={:?}", sk_sz);
  assert_eq!(sk_sz, 96);

  let pk_sz = ffi::slh_pk_sz(core::ptr::from_ref(prm));
  println!("pk_sz={:?}", pk_sz);
  assert_eq!(pk_sz, 48);

  let sig_sz = ffi::slh_sig_sz(core::ptr::from_ref(prm));
  println!("sig_sz={:?}", sig_sz);
  assert_eq!(sig_sz, 35664);
}
```
