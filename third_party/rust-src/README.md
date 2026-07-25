# Rust standard library source packaging inputs

`COPYRIGHT` and `LICENSE-MIT` are copied byte-for-byte from the Rust repository
at commit `01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf`, the source commit for Rust
`1.93.1`. The packaged data tree combines these notices, the repository's
standard Apache-2.0 license text, and the `library/` directory from the pinned
rustup `rust-src` component.

The package task verifies the exact toolchain release and commit before copying
the source tree. It never downloads source during packaging and never falls back
to a project or system `rust-src`.
