# Run This Job

A generic job execution framework in Rust

## About

`rtj` aims to provide a generic but robust and secure framework for users to develop their own
job execution applications.

Encryption tasks are left to [crypto_box](https://crates.io/crates/crypto_box), and are therefore
compatible with other implementations of the [standard](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption).

Transfer of message bytes is up to the user, but as all data end up serialized to arrays or vectors of u8 there are near limitless
options available.

### Example

A typical "Hello" [example](https://github.com/anthonyjmartinez/rtj/blob/main/examples/hello.rs) that itself uses all defined methods can be run by cloning this repository,
and running `cargo run --example hello`

### MSRV

This crate uses format strings as introduced in Rust 1.58, which is thus the Minimum Supported Rust Version.

### License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.

Copyright (C) 2021-2024 Anthony Martinez
