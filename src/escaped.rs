//! Byte strings in `Debug` output.

use core::fmt;

/// A byte string that debugs as a quoted string, its bytes outside printable
/// ASCII escaped, rather than as a list of numbers.
pub(crate) struct Escaped<'a>(pub(crate) &'a [u8]);

impl fmt::Debug for Escaped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\"", self.0.escape_ascii())
    }
}
