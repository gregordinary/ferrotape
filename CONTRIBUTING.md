# Contributing

ferrotape is maintained in spare time. This document sets out how changes are
handled, and what you need to build and test the code.

## Reporting a security issue

Report a security issue privately, through the channel
[SECURITY.md](SECURITY.md) describes, and please do not open a public issue
for one. The chief one is an archive read with members other than the
reference readers see. SECURITY.md lists the others.

## Proposing a change

Open an issue before writing code, so the design can be agreed before anyone
spends time on it. ferrotape's contract includes its API, which archives it
accepts, what it reports for their members, and the bytes it writes. A
change to any of them is recorded in the changelog with what it changes,
even one that fixes a difference from a reference reader.

## Matching the reference readers

ferrotape's reference readers are GNU tar, bsdtar (libarchive), Go's
`archive/tar` and Python's `tarfile`. It reads an archive as they read it, or
refuses it, and its documentation states the rule that decides each case
where they disagree. Each rule is specified by measurement, and a question
about what a reference reader does is answered by running it.

GNU tar is licensed GPL-3.0-or-later, the others under licenses of their own,
and ferrotape is MIT or Apache-2.0. No part of any reference reader is
translated into ferrotape. Their source is not read while ferrotape's code is
written. Please follow the same rule in any contribution.

A difference between ferrotape and the reference readers on any archive is a
defect, unless the documentation states it.

The case catalog in [`catalog/`](catalog/README.md) holds the archives the
rules rest on. Each case records the rule, ferrotape's verdict in every
setting, and each reference reader's reading, taken by running the reader.
`cargo test` holds ferrotape to every case. A change to what ferrotape reads
comes with a case that shows it. The harness in `harness/` records the case's
readings, running the readers at the versions the catalog pins.

## Building and testing

The toolchain is pinned in `rust-toolchain.toml`, so `rustup` provisions the
right version, components, and targets automatically.

```sh
cargo build
cargo test
```

The library has no dependencies. The fuzzing harness in `fuzz/` has its own
(see "Fuzzing").

`cargo test --workspace` also checks the case catalog, and needs no
reference reader installed. Recording a case's readings, or checking that
the readers still give the recorded ones, needs GNU tar, bsdtar, Python and
Go at the pinned versions. The catalog's README names each version and build,
and shows how to install them:

```sh
cargo run -p ferrotape-harness -- record catalog/pax/a-new-rule.case
cargo run -p ferrotape-harness -- check catalog
```

## Before opening a pull request

CI runs all of these, and running them locally first is faster than a round
trip.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo doc --workspace --all-features --no-deps    # RUSTDOCFLAGS='-D warnings'
cargo build --lib --target wasm32-unknown-unknown
cargo build --lib --target x86_64-pc-windows-msvc
cargo +1.91 test --workspace --all-features    # RUSTFLAGS='-D warnings'
cargo deny check licenses advisories sources
cargo deny --manifest-path fuzz/Cargo.toml check licenses advisories sources
```

The fifth and sixth build the library for WebAssembly with no operating system
beneath it, and for Windows. A stray use of a Unix-only interface fails to
build there, where on Linux it would compile. The seventh runs the tests under
the minimum supported Rust version, which sits below the pinned toolchain, and
needs that toolchain installed. The last two check the licenses, advisories
and sources of two dependency graphs: the library's, and the fuzzing
harness's, which holds the only third-party crates. They need
[cargo-deny](https://github.com/EmbarkStudios/cargo-deny).

The public API is recorded in `public-api.txt`, and CI fails on any change to
it that the file does not show. A change that adds to or alters the API
regenerates it with
[cargo-public-api](https://github.com/cargo-public-api/cargo-public-api),
under the nightly the CI job pins:

```sh
RUSTUP_TOOLCHAIN=nightly-2026-07-09 cargo public-api -p ferrotape --all-features \
    --omit blanket-impls,auto-derived-impls > public-api.txt
```

## Fuzzing

`fuzz/` holds two [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)
targets, in a workspace of their own, so the harness never joins the
library's build:

- `read` reads arbitrary input as an archive at each level and in each
  global-header mode. It reads from a `Read` and by seeking, and reads each
  member's data or skips it. It checks that the four ways agree, that a
  refusal is final, and that every offset and size stays within the input.
  It also checks that `Strict` reads nothing `Compatible` reads otherwise,
  and `Refuse` nothing `Apply` or `Defer` does.
- `round_trip` generates headers from its input and writes them. It checks
  that a header it refuses writes nothing, and that every other reads back as
  set at each level and in each mode. The one exception is a member whose mode
  has setuid, setgid or sticky beside an access control list, which `Strict`
  refuses.

The targets need a nightly toolchain. CI builds both and runs each for a
fixed number of runs. After changing the reader or the writer, run the
target that drives it for a while before opening the pull request:

```sh
cd fuzz
cargo +nightly fuzz run read
cargo +nightly fuzz run read -- -jobs=4 -workers=4
```

`cargo fuzz list` names the targets. With `-jobs`, libFuzzer writes each
job's log to `fuzz-<n>.log` in the directory it runs in. Running from `fuzz/`
keeps the logs beside the corpus and out of the repository's status. An
input that fails is saved under `fuzz/artifacts/` and replays with
`cargo +nightly fuzz run <target> <file>`.

## Code conventions

- **No `unsafe`.** The crate forbids it, its tests included.
- **No panics in library code.** Archives come from sources the caller does
  not control, so a reachable panic is a denial of service waiting for an
  input to find it. The lints at the top of `src/lib.rs` deny the common ways
  to panic or to compute a wrong length silently (indexing, unchecked
  arithmetic, truncating casts, `unwrap`, `expect`, the panicking macros). A
  site that genuinely cannot fail, and is clearer written
  directly, has `#[expect(lint, reason = "...")]` on the smallest item that
  holds it. The reason states the invariant that makes it safe. Tests are
  exempt.
- **Bounded resources.** Every allocation an archive can drive has a ceiling,
  documented and configurable. Reading takes time linear in the archive,
  apart from sorting a pax extended header's records to compare them (n log n
  in the header's length). Nothing recurses on the archive.
- **`std` for I/O only.** Items the standard library re-exports from `core`
  and `alloc` are named from those crates, as lints require. Paths and names
  are bytes: nothing in the API is an `OsStr` or a `Path`.
- **Room to grow.** A public struct or enum that can gain a field or variant
  is `#[non_exhaustive]`, and a member's properties are read through methods
  rather than fields. An addition is then not a breaking change.
- **Errors are typed and say what.** An error names the rule an archive
  breaks and its offset in the stream, as structured fields rather than
  strings. A refusal names what the reference readers disagree about, in a
  kind a program can match on. Error enums are `#[non_exhaustive]`, and their
  `Display` is written by hand.
- **Documentation is part of the change.** Public items have rustdoc, and
  internal items have it wherever the behavior is not obvious. Comments
  explain *why*, not *what*. A difference from a reference reader is listed
  on the `differences` page, with the catalog cases that show it.
- **No emoji** in code, comments, documentation, or commit messages.

## Commit messages

Write in the imperative mood, describing the change in the repository's own
terms. A body explaining the reasoning is welcome where the reasoning is not
obvious.

## License

The project is dual-licensed under Apache-2.0 and MIT. Unless you state
otherwise, any contribution you intentionally submit for inclusion, as defined
in the Apache-2.0 license, is dual-licensed the same way, with no additional
terms or conditions.
