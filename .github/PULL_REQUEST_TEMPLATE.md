<!-- A change is best agreed in an issue before it is written; see
     CONTRIBUTING.md. Link that issue here if there is one. -->

## What this changes

<!-- The change in the repository's own terms: what the code now does. -->

## Why

<!-- The reasoning, where it is not obvious from the change itself. -->

## Checks

<!-- CI runs all of these; running them locally first is faster than a round
     trip. See CONTRIBUTING.md. -->

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace --all-features`
- [ ] `cargo doc --workspace --all-features --no-deps` with `RUSTDOCFLAGS='-D warnings'`
- [ ] `cargo build --lib --target wasm32-unknown-unknown`
- [ ] `cargo build --lib --target x86_64-pc-windows-msvc`
- [ ] `cargo +1.91 test --workspace --all-features` with `RUSTFLAGS='-D warnings'`
- [ ] `cargo deny check licenses advisories sources`, if a dependency changed
- [ ] The public surface is unchanged, **or** `public-api.txt` is regenerated
      and the diff is intentional

## What it reads and writes

- [ ] No archive is read, refused or written differently, **or** the
      description says which, and a test shows what the reference readers
      read
- [ ] A difference from a reference reader the change introduces or leaves is
      listed in the documentation
