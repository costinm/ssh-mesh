//! Owned building blocks for bounded cooperative programs.
//!
//! Unlike the allocation-free synchronous evaluator, this optional module uses
//! `alloc` so program data can outlive a host invocation.

use crate::{Code, one, take, validate_value};
use alloc::{string::String, vec, vec::Vec};
use mesh_api::cbor::{Item, Reader, Writer};

pub mod wire;

pub mod async_runtime;

mod runtime;
pub use runtime::{Event, Runner};

/// A collection of independent ordered rule lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Program {
    /// Independent rule lists, scheduled cooperatively.
    pub lists: Vec<RuleList>,
}
/// Ordered rules with a private context and a unique name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleList {
    /// Nonempty name, unique within the program.
    pub name: String,
    /// CBOR map with unique unsigned integer keys.
    pub context: Vec<u8>,
    /// Rules executed in order until completion or failure.
    pub rules: Vec<Rule>,
}
/// One ordered program operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rule {
    /// Evaluate an expression and retain its result.
    Eval {
        /// Encoded expression evaluated for this rule.
        expr: Vec<u8>,
    },
    /// Evaluate an expression and update a context tag.
    Set {
        /// Context tag to replace or insert.
        tag: u64,
        /// Encoded expression providing the new value.
        expr: Vec<u8>,
    },
    /// Finish the list when the expression evaluates to true.
    BreakIf {
        /// Encoded boolean expression; true ends this list.
        expr: Vec<u8>,
    },
    /// Suspend the list for a relative delay.
    After {
        /// Delay relative to the current monotonic time, in milliseconds.
        delay_ms: u64,
    },
}

/// Limits for both program admission and execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramLimits {
    /// Maximum aggregate encoded program input size in bytes.
    pub max_input_bytes: usize,
    /// Maximum independent rule lists.
    pub max_lists: usize,
    /// Maximum total rules across all lists.
    pub max_rules: usize,
    /// Maximum simultaneously waiting calls.
    pub max_pending: usize,
    /// Maximum encoded context size per list.
    pub max_context_bytes: usize,
    /// Maximum encoded size of an intermediate or returned value.
    pub max_value_bytes: usize,
    /// Maximum live evaluation continuations and operand values per list.
    pub max_frames: usize,
    /// Maximum expression nodes executed across the program.
    pub max_nodes: u32,
    /// Maximum wait for a call response, in monotonic milliseconds.
    pub timeout_ms: u64,
}

impl Default for ProgramLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 65536,
            max_lists: 16,
            max_rules: 256,
            max_pending: 16,
            max_context_bytes: 4096,
            max_value_bytes: 4096,
            max_frames: 32,
            max_nodes: 4096,
            timeout_ms: 10000,
        }
    }
}

/// An encoded context, with checked, atomic updates and no mutable map access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    encoded: Vec<u8>,
    max_bytes: usize,
    max_value_bytes: usize,
}

impl Context {
    /// Validate and own a context map within the supplied byte bounds.
    pub fn new(encoded: &[u8], max_bytes: usize, max_value_bytes: usize) -> Result<Self, Code> {
        if encoded.len() > max_bytes {
            return Err(Code::Size);
        }
        validate_value(encoded, 0)?;
        let mut reader = Reader::new(encoded);
        let Some(Item::Map(n)) = reader.next() else {
            return Err(Code::Malformed);
        };
        for _ in 0..n {
            if !matches!(reader.next(), Some(Item::Uint(_))) {
                return Err(Code::Malformed);
            }
            if take(&mut reader)?.len() > max_value_bytes {
                return Err(Code::Size);
            }
        }
        if !reader.rest().is_empty() {
            return Err(Code::Malformed);
        }
        Ok(Self {
            encoded: encoded.to_vec(),
            max_bytes,
            max_value_bytes,
        })
    }

    /// Return the encoded value for a tag, or None if it is absent.
    pub fn get(&self, tag: u64) -> Option<&[u8]> {
        let mut reader = Reader::new(&self.encoded);
        let Some(Item::Map(n)) = reader.next() else {
            return None;
        };
        for _ in 0..n {
            let Some(Item::Uint(key)) = reader.next() else {
                return None;
            };
            let value = take(&mut reader).ok()?;
            if key == tag {
                return Some(value);
            }
        }
        None
    }

    /// Borrow the complete encoded context map.
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Insert or replace a value. On any error the original context is intact.
    pub fn set(&mut self, tag: u64, value: &[u8]) -> Result<(), Code> {
        if value.len() > self.max_value_bytes {
            return Err(Code::Size);
        }
        validate_value(value, 0)?;
        one(value)?;
        let mut reader = Reader::new(&self.encoded);
        let Some(Item::Map(n)) = reader.next() else {
            return Err(Code::Malformed);
        };
        let exists = self.get(tag).is_some();
        let count = n.checked_add(usize::from(!exists)).ok_or(Code::Size)?;
        let mut out = vec![0; self.max_bytes];
        let mut writer = Writer::new(&mut out);
        writer.map(count);
        for _ in 0..n {
            let Some(Item::Uint(key)) = reader.next() else {
                return Err(Code::Malformed);
            };
            let old = take(&mut reader)?;
            writer.uint(key).raw(if key == tag { value } else { old });
        }
        if !exists {
            writer.uint(tag).raw(value);
        }
        let len = writer.finish().ok_or(Code::Size)?.len();
        out.truncate(len);
        validate_value(&out, 0)?;
        self.encoded = out;
        Ok(())
    }
}
