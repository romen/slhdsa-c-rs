# [`slhdsa-c`][slhdsa-c] Rust bindings

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![ISC/MIT/Apache2 licensed][license-image]
![MSRV][rustc-image]

Rust bindings for the [`slhdsa-c`][slhdsa-c] implementation of the
SLH-DSA (a.k.a. SPHINCS+) signature scheme,
conforming to the [FIPS-205 Standard].

## ⚠️ Security Warning

This crate has never been independently audited!

USE AT YOUR OWN RISK!

## License

This crate is licensed under the same terms for
the [`slhdsa-c`][slhdsa-c] project:

- [ISC license](https://spdx.org/licenses/ISC.html)
- [MIT license](https://opensource.org/licenses/MIT)
- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
licensed as above, without any additional terms or conditions.

[crate-image]: https://img.shields.io/crates/v/slhdsa-c-rs?logo=rust
[crate-link]: https://crates.io/crates/slhdsa-c-rs
[docs-image]: https://docs.rs/slhdsa-c-rs/badge.svg
[docs-link]: https://docs.rs/slhdsa-c-rs/
[build-image]: https://img.shields.io/badge/build-not_automated_yet-red "not automated yet"
[build-link]: # "not automated yet"
[license-image]: https://img.shields.io/badge/license-ISC/MIT/Apache2.0-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[//]: # "links"
[slhdsa-c]: https://github.com/pq-code-package/slhdsa-c
[RustCrypto]: https://github.com/RustCrypto
[FIPS-205 Standard]: https://csrc.nist.gov/pubs/fips/205/final
