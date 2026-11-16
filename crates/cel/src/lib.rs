#![no_std]
#![warn(missing_docs)]
//! Types for the micro-CEL evaluator.
//!
//! CBOR maps have at most [`MAX_MAP_ENTRIES`] entries and scalar keys only
//! (integer, boolean, null, text, or bytes). Presence checks support both field
//! selection and the index extension: only a missing final lookup becomes
//! false; errors evaluating the receiver or index propagate. Container equality
//! work is bounded by input limits but is not fully metered.

pub mod support;
pub use support::encoding::validate_data;
use support::encoding::{
    Val, array, constant, encoded_len, equal, fields, lookup, lookup_tag, node, one, required,
    static_int, take, uint, val_eq, validate_value, value, write_val,
};

#[cfg(feature = "program")]
extern crate alloc;
#[cfg(feature = "program")]
pub mod program;
#[cfg(feature = "service")]
pub mod service;

#[cfg(all(feature = "translate", not(test)))]
extern crate std;
#[cfg(feature = "translate")]
pub mod host;

/// Evaluator failures. Invocation errors retain the component's original code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    /// Successful operation.
    Ok,
    /// Unsupported expression or operation.
    Unsupported,
    /// Expression, continuation, or value nesting exceeds its limit.
    Depth,
    /// Expression node budget exhausted.
    Nodes,
    /// Invalid CBOR or expression structure.
    Malformed,
    /// Operand types do not support the requested operation.
    Type,
    /// Requested field, index, or continuation does not exist.
    NotFound,
    /// Arithmetic overflow or division by zero.
    Arith,
    /// Input, output, or storage bound exceeded.
    Size,
    /// Failure reported by an invoked component.
    Invoke(i32),
}

/// Bounds on the expression walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum expression nesting, with the root at depth one.
    pub max_depth: u32,
    /// Maximum expression nodes inspected or executed.
    pub max_nodes: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_nodes: 512,
        }
    }
}
/// Node count and depth measured during expression validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    /// Number of expression nodes visited.
    pub nodes: u32,
    /// Maximum expression nesting, with the root at depth one.
    pub max_depth: u32,
}

/// Invokes a component, returning a CBOR value borrowed from `out`.
pub trait Invoke {
    /// Invoke a component with encoded parameters, returning its result borrowed from out.
    fn invoke<'a>(
        &mut self,
        component: i32,
        method: i32,
        params: &[u8],
        out: &'a mut [u8],
    ) -> Result<&'a [u8], i32>;
}

/// Invocation implementation for environments without external calls.
pub struct NoInvoke;

impl Invoke for NoInvoke {
    fn invoke<'a>(&mut self, _: i32, _: i32, _: &[u8], _: &'a mut [u8]) -> Result<&'a [u8], i32> {
        Err(crate::support::status::ERR_UNSUPPORTED)
    }
}

mod arena;
use arena::Arena;
use mesh_api::cbor::{Item, Writer};

/// Maximum encoded size of each AST, variables value, or invocation result.
pub const MAX_INPUT_BYTES: usize = 16_384;
/// Maximum nesting depth of CBOR values (the root is at depth zero).
pub const MAX_VALUE_DEPTH: u32 = 32;
/// Maximum entries in any CBOR map.
pub const MAX_MAP_ENTRIES: usize = 128;

impl Code {
    /// Encode a failure as a component status, preserving opaque invocation errors.
    pub fn to_i32(self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::Unsupported => -1001,
            Self::Depth => -1002,
            Self::Nodes => -1003,
            Self::Malformed => -1004,
            Self::Type => -1005,
            Self::NotFound => -1006,
            Self::Arith => -1007,
            Self::Size => -1008,
            // Invocation codes are opaque; they are not a reversible encoding.
            Self::Invoke(rc) => rc,
        }
    }
    /// Decode a CEL status; unknown values remain opaque invocation errors.
    pub fn from_i32(n: i32) -> Self {
        match n {
            0 => Self::Ok,
            -1001 => Self::Unsupported,
            -1002 => Self::Depth,
            -1003 => Self::Nodes,
            -1004 => Self::Malformed,
            -1005 => Self::Type,
            -1006 => Self::NotFound,
            -1007 => Self::Arith,
            -1008 => Self::Size,
            n => Self::Invoke(n),
        }
    }
}

fn string(v: Val<'_>) -> Result<&[u8], Code> {
    match v {
        Val::Text(s) | Val::Bytes(s) => Ok(s),
        _ => Err(Code::Type),
    }
}
fn boolean(v: Val<'_>) -> Result<bool, Code> {
    if let Val::Bool(b) = v {
        Ok(b)
    } else {
        Err(Code::Type)
    }
}
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || (needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle))
}
fn arity(id: u64) -> Result<usize, Code> {
    match id {
        3 | 13 | 19 | 24 => Ok(1),
        4 | 23 => Ok(3),
        1 | 2 | 5..=12 | 14..=18 | 20..=22 => Ok(2),
        _ => Err(Code::Unsupported),
    }
}

fn select_value<'a>(operand: Val<'a>, field: Item<'_>) -> Result<Val<'a>, Code> {
    match (operand, field) {
        (Val::Map(m), Item::Uint(n)) => lookup_tag(m, n),
        (Val::Map(m), Item::Text(s)) => lookup(m, Val::Text(s)),
        (Val::List(m), Item::Uint(n)) => {
            lookup(m, Val::Int(i32::try_from(n).map_err(|_| Code::NotFound)?))
        }
        (Val::Map(_) | Val::List(_), _) => Err(Code::Malformed),
        _ => Err(Code::Type),
    }
}

pub(crate) fn apply<'a>(
    id: u64,
    a: Val<'a>,
    b: Option<Val<'a>>,
    arena: &mut Arena<'a>,
) -> Result<Val<'a>, Code> {
    match id {
        3 => return Ok(Val::Bool(!boolean(a)?)),
        13 => {
            return match a {
                Val::Int(x) => Ok(Val::Int(x.checked_neg().ok_or(Code::Arith)?)),
                _ => Err(Code::Type),
            };
        }
        19 => {
            let n = match a {
                Val::Text(s) => core::str::from_utf8(s)
                    .map_err(|_| Code::Malformed)?
                    .chars()
                    .count(),
                Val::Bytes(s) => s.len(),
                Val::List(s) | Val::Map(s) => match one(s)? {
                    Item::Array(n) | Item::Map(n) => n,
                    _ => return Err(Code::Malformed),
                },
                _ => return Err(Code::Type),
            };
            return Ok(Val::Int(i32::try_from(n).map_err(|_| Code::Size)?));
        }
        _ => {}
    }
    let b = b.ok_or(Code::Malformed)?;
    if id != 5 && id != 6 && (matches!(a, Val::Null) || matches!(b, Val::Null)) {
        return Err(Code::Type);
    }
    match id {
        5 | 6 => Ok(Val::Bool(equal(a, b)? == (id == 5))),
        7..=10 => {
            let ord = match (a, b) {
                (Val::Int(x), Val::Int(y)) => x.cmp(&y),
                (Val::Text(x), Val::Text(y)) | (Val::Bytes(x), Val::Bytes(y)) => x.cmp(y),
                _ => return Err(Code::Type),
            };
            Ok(Val::Bool(match id {
                7 => ord.is_lt(),
                8 => !ord.is_gt(),
                9 => ord.is_gt(),
                _ => !ord.is_lt(),
            }))
        }
        11 => {
            let found = match b {
                Val::Text(s) | Val::Bytes(s) => contains(s, string(a)?),
                Val::List(s) => {
                    let (n, mut r) = array(s)?;
                    let mut found = false;
                    for _ in 0..n {
                        match equal(a, value(take(&mut r)?)?) {
                            Ok(true) => found = true,
                            Ok(false) | Err(Code::Type) => {}
                            Err(e) => return Err(e),
                        }
                    }
                    found
                }
                Val::Map(s) => match lookup(s, a) {
                    Ok(_) => true,
                    Err(Code::NotFound) => false,
                    Err(e) => return Err(e),
                },
                _ => return Err(Code::Type),
            };
            Ok(Val::Bool(found))
        }
        12 => match (a, b) {
            (Val::Int(x), Val::Int(y)) => Ok(Val::Int(x.checked_add(y).ok_or(Code::Arith)?)),
            (Val::Text(x), Val::Text(y)) | (Val::Bytes(x), Val::Bytes(y)) => {
                let n = x.len().checked_add(y.len()).ok_or(Code::Size)?;
                let buf = arena.alloc(n).ok_or(Code::Size)?;
                buf[..x.len()].copy_from_slice(x);
                buf[x.len()..].copy_from_slice(y);
                if matches!(a, Val::Text(_)) {
                    Ok(Val::Text(buf))
                } else {
                    Ok(Val::Bytes(buf))
                }
            }
            _ => Err(Code::Type),
        },
        14..=17 => {
            let (Val::Int(x), Val::Int(y)) = (a, b) else {
                return Err(Code::Type);
            };
            Ok(Val::Int(
                match id {
                    14 => x.checked_sub(y),
                    15 => x.checked_mul(y),
                    16 => x.checked_div(y),
                    _ => x.checked_rem(y),
                }
                .ok_or(Code::Arith)?,
            ))
        }
        18 => match a {
            Val::Map(s) | Val::List(s) => lookup(s, b),
            _ => Err(Code::Type),
        },
        20..=22 => {
            let (x, y) = (string(a)?, string(b)?);
            Ok(Val::Bool(match id {
                20 => x.starts_with(y),
                21 => x.ends_with(y),
                _ => contains(x, y),
            }))
        }
        _ => Err(Code::Unsupported),
    }
}

struct Engine<'a, I> {
    vars: &'a [u8],
    arena: Arena<'a>,
    limits: Limits,
    left: u32,
    inv: &'a mut I,
}
impl<'a, I: Invoke> Engine<'a, I> {
    fn eval(&mut self, ast: &'a [u8], depth: u32) -> Result<Val<'a>, Code> {
        // Hard ceiling protects the native stack even with hostile caller limits.
        if depth > self.limits.max_depth || depth > 128 {
            return Err(Code::Depth);
        }
        self.left = self.left.checked_sub(1).ok_or(Code::Nodes)?;
        let (kind, p) = node(ast)?;
        match kind {
            1 => constant(p),
            2 => {
                let f = fields(p)?;
                let tag = uint(required(&f, 1)?)?;
                if f[2].is_some() || f[3].is_some() {
                    return Err(Code::Malformed);
                }
                lookup_tag(self.vars, tag)
            }
            3 => self.select(p, depth),
            4 => self.call(p, depth),
            5 | 6 => self.container(p, depth, kind == 6),
            _ => Err(Code::Malformed),
        }
    }
    fn select(&mut self, p: &'a [u8], depth: u32) -> Result<Val<'a>, Code> {
        let f = fields(p)?;
        if f[3].is_some() {
            return Err(Code::Malformed);
        }
        let operand = self.eval(required(&f, 1)?, depth + 1)?;
        let field = one(required(&f, 2)?)?;
        select_value(operand, field)
    }
    #[inline(never)]
    fn container(&mut self, p: &'a [u8], depth: u32, map: bool) -> Result<Val<'a>, Code> {
        let f = fields(p)?;
        if f[2].is_some() || f[3].is_some() {
            return Err(Code::Malformed);
        }
        let (n, mut r) = array(required(&f, 1)?)?;
        if n > 128 {
            return Err(Code::Size);
        }
        // Descriptors live in scratch, not on each recursive evaluator frame.
        let word = core::mem::size_of::<usize>();
        let desc = self
            .arena
            .alloc(n.checked_mul(2 * word).ok_or(Code::Size)?)
            .ok_or(Code::Size)?;
        let mut len = 9usize;
        for i in 0..n {
            let (key, expr) = if map {
                let (count, mut pair) = array(take(&mut r)?)?;
                if count != 2 {
                    return Err(Code::Malformed);
                };
                let k = take(&mut pair)?;
                match one(k)? {
                    Item::Text(_) | Item::Bytes(_) | Item::Uint(_) | Item::Neg(_) => {
                        value(k)?;
                    }
                    _ => return Err(Code::Malformed),
                };
                let e = take(&mut pair)?;
                if !pair.rest().is_empty() {
                    return Err(Code::Malformed);
                };
                (Some(k), e)
            } else {
                (None, take(&mut r)?)
            };
            let v = self.eval(expr, depth + 1)?;
            let size = encoded_len(v)?
                .checked_add(key.map_or(0, |k| k.len()))
                .ok_or(Code::Size)?;
            let offset = self.arena.used();
            let buf = self.arena.alloc(size).ok_or(Code::Size)?;
            let mut w = Writer::new(buf);
            if let Some(k) = key {
                w.raw(k);
            }
            write_val(&mut w, v);
            let chunk = w.finish().ok_or(Code::Size)?;
            let start = i * 2 * word;
            desc[start..start + word].copy_from_slice(&offset.to_ne_bytes());
            desc[start + word..start + 2 * word].copy_from_slice(&chunk.len().to_ne_bytes());
            len = len.checked_add(chunk.len()).ok_or(Code::Size)?;
        }
        if !r.rest().is_empty() {
            return Err(Code::Malformed);
        }
        let buf = self.arena.alloc(len).ok_or(Code::Size)?;
        let mut written = {
            let mut w = Writer::new(&mut *buf);
            if map {
                w.map(n);
            } else {
                w.array(n);
            }
            w.finish().ok_or(Code::Size)?.len()
        };
        for d in desc.chunks_exact(2 * word) {
            let mut offset = [0u8; core::mem::size_of::<usize>()];
            let mut size = offset;
            offset.copy_from_slice(&d[..word]);
            size.copy_from_slice(&d[word..]);
            let size = usize::from_ne_bytes(size);
            let end = written.checked_add(size).ok_or(Code::Size)?;
            self.arena
                .copy_allocated(
                    usize::from_ne_bytes(offset),
                    buf.get_mut(written..end).ok_or(Code::Size)?,
                )
                .ok_or(Code::Size)?;
            written = end;
        }
        let data = &buf[..written];
        validate_value(data, 0)?;
        if map {
            Ok(Val::Map(data))
        } else {
            Ok(Val::List(data))
        }
    }
    fn call(&mut self, p: &'a [u8], depth: u32) -> Result<Val<'a>, Code> {
        let f = fields(p)?;
        let id = uint(required(&f, 1)?)?;
        let expected = arity(id)?;
        let (n, mut r) = array(required(&f, 2)?)?;
        let target = f[3];
        if n.checked_add(usize::from(target.is_some())) != Some(expected) {
            return Err(Code::Malformed);
        }
        let mut args = [None; 3];
        let mut offset = 0;
        if let Some(t) = target {
            args[0] = Some(t);
            offset = 1;
        }
        for i in 0..n {
            args[i + offset] = Some(take(&mut r)?);
        }
        if !r.rest().is_empty() {
            return Err(Code::Malformed);
        }
        if id == 23 {
            static_int(args[0].ok_or(Code::Malformed)?)?;
            static_int(args[1].ok_or(Code::Malformed)?)?;
        }
        if id == 24 {
            let expr = args[0].ok_or(Code::Malformed)?;
            let (k, p) = node(expr)?;
            // Charge the presence operand node, as ordinary evaluation does.
            if depth + 1 > self.limits.max_depth || depth + 1 > 128 {
                return Err(Code::Depth);
            }
            self.left = self.left.checked_sub(1).ok_or(Code::Nodes)?;
            let result = if k == 3 {
                let f = fields(p)?;
                let operand = self.eval(required(&f, 1)?, depth + 2)?;
                select_value(operand, one(required(&f, 2)?)?)
            } else if k == 4 {
                let f = fields(p)?;
                if uint(required(&f, 1)?)? != 18 {
                    return Err(Code::Malformed);
                }
                let (_, mut r) = array(required(&f, 2)?)?;
                let (receiver, index) = if let Some(t) = f[3] {
                    (t, take(&mut r)?)
                } else {
                    (take(&mut r)?, take(&mut r)?)
                };
                let receiver = self.eval(receiver, depth + 2)?;
                let index = self.eval(index, depth + 2)?;
                match receiver {
                    Val::Map(s) | Val::List(s) => lookup(s, index),
                    _ => Err(Code::Type),
                }
            } else {
                return Err(Code::Malformed);
            };
            return match result {
                Ok(_) => Ok(Val::Bool(true)),
                Err(Code::NotFound) => Ok(Val::Bool(false)),
                Err(e) => Err(e),
            };
        }
        let first = self.eval(args[0].ok_or(Code::Malformed)?, depth + 1);
        if id == 1 || id == 2 {
            let left = first.and_then(boolean);
            let absorb = id == 1;
            match left {
                Err(e)
                    if !matches!(
                        e,
                        Code::NotFound | Code::Type | Code::Arith | Code::Invoke(_)
                    ) =>
                {
                    return Err(e);
                }
                _ => {}
            }
            if left == Ok(absorb) {
                return Ok(Val::Bool(absorb));
            }
            // The RHS runs exactly once unless the LHS is already absorbing.
            let right = self
                .eval(args[1].ok_or(Code::Malformed)?, depth + 1)
                .and_then(boolean);
            match right {
                Err(e)
                    if !matches!(
                        e,
                        Code::NotFound | Code::Type | Code::Arith | Code::Invoke(_)
                    ) =>
                {
                    return Err(e);
                }
                _ => {}
            }
            if right == Ok(absorb) {
                return Ok(Val::Bool(absorb));
            }
            return match (left, right) {
                (Err(e), _) | (_, Err(e)) => Err(e),
                _ => Ok(Val::Bool(!absorb)),
            };
        }
        let a = first?;
        if id == 4 {
            let branch = if boolean(a)? { 1 } else { 2 };
            return self.eval(args[branch].ok_or(Code::Malformed)?, depth + 1);
        }
        if matches!(id, 3 | 13 | 19) {
            return apply(id, a, None, &mut self.arena);
        }
        let b = self.eval(args[1].ok_or(Code::Malformed)?, depth + 1)?;
        if id == 23 {
            let c = self.eval(args[2].ok_or(Code::Malformed)?, depth + 1)?;
            let (Val::Int(comp), Val::Int(method), Val::Map(params)) = (a, b, c) else {
                return Err(Code::Type);
            };
            let len = self.arena.remaining() / 4;
            let buf = self.arena.alloc(len).ok_or(Code::Size)?;
            let result = self
                .inv
                .invoke(comp, method, params, buf)
                .map_err(Code::Invoke)?;
            validate_value(result, 0)?;
            return value(result);
        }
        apply(id, a, Some(b), &mut self.arena)
    }
}

/// Evaluate an expression, returning one CBOR value borrowed from `out`.
pub fn eval<'o>(
    ast: &[u8],
    vars: &[u8],
    scratch: &mut [u8],
    out: &'o mut [u8],
    limits: Limits,
    inv: &mut impl Invoke,
) -> Result<&'o [u8], Code> {
    check(ast, &limits)?;
    if vars.len() > MAX_INPUT_BYTES {
        return Err(Code::Size);
    }
    if !matches!(one(vars)?, Item::Map(_)) {
        return Err(Code::Malformed);
    }
    validate_value(vars, 0)?;
    let mut e = Engine {
        vars,
        arena: Arena::new(scratch),
        limits,
        left: limits.max_nodes,
        inv,
    };
    let v = e.eval(ast, 1)?;
    let mut w = Writer::new(out);
    write_val(&mut w, v);
    w.finish().ok_or(Code::Size)
}

fn walk(
    ast: &[u8],
    depth: u32,
    limits: &Limits,
    info: &mut NodeInfo,
    policy: bool,
) -> Result<(), Code> {
    if depth > limits.max_depth || depth > 128 {
        return Err(Code::Depth);
    }
    info.nodes = info.nodes.checked_add(1).ok_or(Code::Nodes)?;
    if info.nodes > limits.max_nodes {
        return Err(Code::Nodes);
    }
    info.max_depth = info.max_depth.max(depth);
    let (k, p) = node(ast)?;
    match k {
        1 => {
            constant(p)?;
        }
        2 => {
            let f = fields(p)?;
            uint(required(&f, 1)?)?;
            if f[2].is_some() || f[3].is_some() {
                return Err(Code::Malformed);
            }
        }
        3 => {
            let f = fields(p)?;
            if f[3].is_some() {
                return Err(Code::Malformed);
            };
            match one(required(&f, 2)?)? {
                Item::Uint(_) | Item::Text(_) => {}
                _ => return Err(Code::Malformed),
            };
            walk(required(&f, 1)?, depth + 1, limits, info, policy)?;
        }
        4 | 5 => {
            let f = fields(p)?;
            let (arr, target) = if k == 4 {
                let id = uint(required(&f, 1)?)?;
                if policy && id == 23 {
                    return Err(Code::Unsupported);
                }
                let (n, mut r) = array(required(&f, 2)?)?;
                if n.checked_add(usize::from(f[3].is_some())) != Some(arity(id)?) {
                    return Err(Code::Malformed);
                };
                if id == 23 {
                    if let Some(t) = f[3] {
                        static_int(t)?;
                        static_int(take(&mut r)?)?;
                    } else {
                        static_int(take(&mut r)?)?;
                        static_int(take(&mut r)?)?;
                    }
                }
                if id == 24 {
                    let expr = if let Some(t) = f[3] {
                        t
                    } else {
                        let (_, mut rr) = array(required(&f, 2)?)?;
                        take(&mut rr)?
                    };
                    let (kind, payload) = node(expr)?;
                    if kind != 3 && !(kind == 4 && uint(required(&fields(payload)?, 1)?)? == 18) {
                        return Err(Code::Malformed);
                    }
                }
                (required(&f, 2)?, f[3])
            } else {
                if f[2].is_some() || f[3].is_some() {
                    return Err(Code::Malformed);
                }
                (required(&f, 1)?, None)
            };
            if let Some(t) = target {
                walk(t, depth + 1, limits, info, policy)?;
            }
            let (n, mut r) = array(arr)?;
            if k == 5 && n > 128 {
                return Err(Code::Size);
            }
            for _ in 0..n {
                walk(take(&mut r)?, depth + 1, limits, info, policy)?;
            }
            if !r.rest().is_empty() {
                return Err(Code::Malformed);
            }
        }
        6 => {
            let f = fields(p)?;
            if f[2].is_some() || f[3].is_some() {
                return Err(Code::Malformed);
            }
            let (n, mut r) = array(required(&f, 1)?)?;
            if n > 128 {
                return Err(Code::Size);
            }
            let entries = r;
            for i in 0..n {
                let (count, mut pair) = array(take(&mut r)?)?;
                if count != 2 {
                    return Err(Code::Malformed);
                }
                let key = take(&mut pair)?;
                match one(key)? {
                    Item::Text(_) | Item::Bytes(_) | Item::Uint(_) | Item::Neg(_) => {
                        value(key)?;
                    }
                    _ => return Err(Code::Malformed),
                }
                let mut prior = entries;
                for _ in 0..i {
                    let (_, mut p) = array(take(&mut prior)?)?;
                    if val_eq(key, take(&mut p)?, 0)? {
                        return Err(Code::Malformed);
                    }
                }
                walk(take(&mut pair)?, depth + 1, limits, info, policy)?;
                if !pair.rest().is_empty() {
                    return Err(Code::Malformed);
                }
            }
            if !r.rest().is_empty() {
                return Err(Code::Malformed);
            }
        }
        _ => return Err(Code::Malformed),
    }
    Ok(())
}
/// Validate an expression and report its size and nesting depth.
pub fn check(ast: &[u8], limits: &Limits) -> Result<NodeInfo, Code> {
    if ast.len() > MAX_INPUT_BYTES {
        return Err(Code::Size);
    }
    let mut info = NodeInfo {
        nodes: 0,
        max_depth: 0,
    };
    walk(ast, 1, limits, &mut info, false)?;
    Ok(info)
}

/// Validate a pure policy, rejecting invocation in every branch.
pub fn check_policy(ast: &[u8], limits: &Limits) -> Result<NodeInfo, Code> {
    if ast.len() > MAX_INPUT_BYTES {
        return Err(Code::Size);
    }
    let mut info = NodeInfo {
        nodes: 0,
        max_depth: 0,
    };
    walk(ast, 1, limits, &mut info, true)?;
    Ok(info)
}

/// Evaluate a validated, invocation-free policy; non-boolean results fail closed.
pub fn eval_policy(
    ast: &[u8],
    vars: &[u8],
    scratch: &mut [u8],
    limits: Limits,
) -> Result<bool, Code> {
    check_policy(ast, &limits)?;
    if vars.len() > MAX_INPUT_BYTES {
        return Err(Code::Size);
    }
    if !matches!(one(vars)?, Item::Map(_)) {
        return Err(Code::Malformed);
    }
    validate_value(vars, 0)?;
    let mut inv = NoInvoke;
    let mut e = Engine {
        vars,
        arena: Arena::new(scratch),
        limits,
        left: limits.max_nodes,
        inv: &mut inv,
    };
    boolean(e.eval(ast, 1)?)
}

#[cfg(test)]
extern crate std;
#[cfg(test)]
mod tests {
    use super::*;
    use std::{vec, vec::Vec};
    fn enc(f: impl FnOnce(&mut Writer<'_>)) -> Vec<u8> {
        let mut buf = [0; 4096];
        let mut w = Writer::new(&mut buf);
        f(&mut w);
        w.finish().unwrap().to_vec()
    }
    fn lit(n: i32) -> Vec<u8> {
        enc(|w| {
            w.map(1).uint(1).map(1).uint(1).int(n.into());
        })
    }
    fn b(v: bool) -> Vec<u8> {
        enc(|w| {
            w.map(1).uint(1).map(1).uint(3).boolean(v);
        })
    }
    fn txt(s: &str) -> Vec<u8> {
        enc(|w| {
            w.map(1).uint(1).map(1).uint(5).text(s);
        })
    }
    fn bytes(s: &[u8]) -> Vec<u8> {
        enc(|w| {
            w.map(1).uint(1).map(1).uint(6).bytes(s);
        })
    }
    fn ident(n: u64) -> Vec<u8> {
        enc(|w| {
            w.map(1).uint(2).map(1).uint(1).uint(n);
        })
    }
    fn call(id: u64, args: &[Vec<u8>]) -> Vec<u8> {
        enc(|w| {
            w.map(1)
                .uint(4)
                .map(2)
                .uint(1)
                .uint(id)
                .uint(2)
                .array(args.len());
            for a in args {
                w.raw(a);
            }
        })
    }
    fn list(args: &[Vec<u8>]) -> Vec<u8> {
        enc(|w| {
            w.map(1).uint(5).map(1).uint(1).array(args.len());
            for a in args {
                w.raw(a);
            }
        })
    }
    fn select(expr: Vec<u8>, key: &[u8]) -> Vec<u8> {
        enc(|w| {
            w.map(1).uint(3).map(2).uint(1).raw(&expr).uint(2).raw(key);
        })
    }
    fn run(a: &[u8], vars: &[u8]) -> Result<Vec<u8>, Code> {
        let mut scratch = [0; 8192];
        let mut out = [0; 4096];
        eval(
            a,
            vars,
            &mut scratch,
            &mut out,
            Limits::default(),
            &mut NoInvoke,
        )
        .map(|x| x.to_vec())
    }
    fn ev(a: &[u8]) -> Result<Vec<u8>, Code> {
        run(a, &[0xa0])
    }
    fn integer(n: i32) -> Vec<u8> {
        enc(|w| {
            w.int(n.into());
        })
    }
    fn truth(x: bool) -> Vec<u8> {
        enc(|w| {
            w.boolean(x);
        })
    }
    fn bin(id: u64, a: Vec<u8>, b: Vec<u8>) -> Result<Vec<u8>, Code> {
        ev(&call(id, &[a, b]))
    }
    #[test]
    fn arithmetic_add() {
        assert_eq!(bin(12, lit(3), lit(4)), Ok(integer(7)));
        assert_eq!(bin(12, lit(i32::MAX), lit(1)), Err(Code::Arith));
    }
    #[test]
    fn arithmetic_sub() {
        assert_eq!(bin(14, lit(3), lit(4)), Ok(integer(-1)));
        assert_eq!(bin(14, lit(i32::MIN), lit(1)), Err(Code::Arith));
    }
    #[test]
    fn arithmetic_mul() {
        assert_eq!(bin(15, lit(3), lit(4)), Ok(integer(12)));
        assert_eq!(bin(15, lit(i32::MAX), lit(2)), Err(Code::Arith));
    }
    #[test]
    fn arithmetic_div() {
        assert_eq!(bin(16, lit(9), lit(3)), Ok(integer(3)));
        assert_eq!(bin(16, lit(1), lit(0)), Err(Code::Arith));
        assert_eq!(bin(16, lit(i32::MIN), lit(-1)), Err(Code::Arith));
    }
    #[test]
    fn arithmetic_rem() {
        assert_eq!(bin(17, lit(10), lit(3)), Ok(integer(1)));
        assert_eq!(bin(17, lit(1), lit(0)), Err(Code::Arith));
    }
    #[test]
    fn unary() {
        assert_eq!(ev(&call(13, &[lit(5)])), Ok(integer(-5)));
        assert_eq!(ev(&call(3, &[b(true)])), Ok(truth(false)));
        assert_eq!(ev(&call(13, &[lit(i32::MIN)])), Err(Code::Arith));
    }
    #[test]
    fn short_circuit() {
        let bad = call(16, &[lit(1), lit(0)]);
        assert_eq!(bin(2, b(false), bad.clone()), Ok(truth(false)));
        assert_eq!(bin(1, b(true), bad), Ok(truth(true)));
        assert_eq!(ev(&call(4, &[b(true), lit(8), ident(88)])), Ok(integer(8)));
    }
    #[test]
    fn bools() {
        assert_eq!(bin(1, b(false), b(true)), Ok(truth(true)));
        assert_eq!(bin(2, b(true), b(false)), Ok(truth(false)));
        assert_eq!(bin(2, lit(1), b(false)), Ok(truth(false)));
    }
    #[test]
    fn equality() {
        assert_eq!(bin(5, txt("abc"), bytes(b"abc")), Ok(truth(true)));
        assert_eq!(bin(6, lit(2), lit(3)), Ok(truth(true)));
        assert_eq!(bin(5, b(true), lit(3)), Ok(truth(false)));
    }
    #[test]
    fn ordering() {
        for (id, x) in [(7, true), (8, true), (9, false), (10, false)] {
            assert_eq!(bin(id, lit(1), lit(2)), Ok(truth(x)));
        }
        assert_eq!(bin(7, txt("a"), txt("b")), Ok(truth(true)));
        assert_eq!(bin(7, txt("a"), bytes(b"b")), Err(Code::Type));
    }
    #[test]
    fn strings() {
        assert_eq!(
            bin(12, txt("a"), txt("b")),
            Ok(enc(|w| {
                w.text("ab");
            }))
        );
        assert_eq!(
            bin(12, bytes(b"a"), bytes(b"b")),
            Ok(enc(|w| {
                w.bytes(b"ab");
            }))
        );
        assert_eq!(bin(12, txt("a"), bytes(b"b")), Err(Code::Type));
        assert_eq!(ev(&call(19, &[txt("abc")])), Ok(integer(3)));
    }
    #[test]
    fn string_functions() {
        for (id, s) in [(20, "ab"), (21, "bc"), (22, "b")] {
            assert_eq!(bin(id, txt("abc"), txt(s)), Ok(truth(true)));
        }
        assert_eq!(bin(22, txt("abc"), txt("")), Ok(truth(true)));
    }
    #[test]
    fn membership() {
        assert_eq!(bin(11, lit(2), list(&[lit(1), lit(2)])), Ok(truth(true)));
        assert_eq!(bin(11, txt("bc"), txt("abcd")), Ok(truth(true)));
        let vars = enc(|w| {
            w.map(1).uint(1).map(1).text("x").int(9);
        });
        assert_eq!(
            run(&call(11, &[txt("x"), ident(1)]), &vars),
            Ok(truth(true))
        );
    }
    #[test]
    fn lists() {
        let l = list(&[lit(7), lit(8)]);
        assert_eq!(bin(18, l.clone(), lit(1)), Ok(integer(8)));
        assert_eq!(bin(18, l, lit(2)), Err(Code::NotFound));
    }
    #[test]
    fn maps() {
        let vars = enc(|w| {
            w.map(1)
                .uint(1)
                .map(2)
                .uint(7)
                .map(1)
                .text("x")
                .int(8)
                .text("a")
                .int(3);
        });
        let s = select(select(ident(1), &[7]), &[0x61, b'x']);
        assert_eq!(run(&s, &vars), Ok(integer(8)));
        assert_eq!(run(&select(ident(1), &[0x61, b'a']), &vars), Ok(integer(3)));
        assert_eq!(run(&ident(2), &vars), Err(Code::NotFound));
    }
    #[test]
    fn validation() {
        let a = call(12, &[lit(1), call(15, &[lit(2), lit(3)])]);
        assert_eq!(
            check(&a, &Limits::default()),
            Ok(NodeInfo {
                nodes: 5,
                max_depth: 3
            })
        );
        assert_eq!(
            check(
                &a,
                &Limits {
                    max_depth: 2,
                    max_nodes: 99
                }
            ),
            Err(Code::Depth)
        );
        assert_eq!(
            check(
                &a,
                &Limits {
                    max_depth: 9,
                    max_nodes: 4
                }
            ),
            Err(Code::Nodes)
        );
    }
    #[test]
    fn malformed() {
        let a = call(12, &[lit(1), lit(2)]);
        for n in 0..a.len() {
            assert!(ev(&a[..n]).is_err());
        }
        assert_eq!(ev(&[0]), Err(Code::Malformed));
        assert_eq!(ev(&[0xa1, 6, 0xa0]), Err(Code::Malformed));
        assert_eq!(ev(&[0xa1, 7, 0xa0]), Err(Code::Unsupported));
        assert_eq!(ev(&[0xa1, 1, 0xa1, 4, 0]), Err(Code::Unsupported));
        assert_eq!(ev(&call(12, &[lit(1)])), Err(Code::Malformed));
    }
    #[test]
    fn presence_logic_and_policy() {
        let missing = select(ident(1), &[0x61, b'x']);
        let vars = [0xa1, 1, 0xa0];
        assert_eq!(
            run(&call(24, core::slice::from_ref(&missing)), &vars),
            Ok(truth(false))
        );
        assert_eq!(
            run(&call(24, &[select(lit(1), &[0x61, b'x'])]), &vars),
            Err(Code::Type)
        );
        assert_eq!(
            run(&call(1, &[missing.clone(), b(true)]), &vars),
            Ok(truth(true))
        );
        assert_eq!(
            run(&call(2, &[missing.clone(), b(false)]), &vars),
            Ok(truth(false))
        );
        assert_eq!(
            run(&call(1, &[missing, b(false)]), &vars),
            Err(Code::NotFound)
        );
        let forbidden = call(
            4,
            &[b(true), b(true), call(23, &[lit(1), lit(2), ident(1)])],
        );
        assert_eq!(
            check_policy(&forbidden, &Limits::default()),
            Err(Code::Unsupported)
        );
        let mut scratch = [0; 1024];
        assert_eq!(
            eval_policy(&forbidden, &vars, &mut scratch, Limits::default()),
            Err(Code::Unsupported)
        );
        assert_eq!(
            eval_policy(&lit(1), &vars, &mut scratch, Limits::default()),
            Err(Code::Type)
        );
        assert_eq!(
            eval_policy(&b(true), &vars, &mut scratch, Limits::default()),
            Ok(true)
        );
    }
    #[test]
    fn stack_budget_subprocess() {
        if cfg!(debug_assertions) {
            return;
        }
        const ENV: &str = "MICRO_CEL_STACK_CHILD";
        if std::env::var_os(ENV).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "tests::stack_budget_subprocess"])
                .env(ENV, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        std::thread::Builder::new()
            .stack_size(32 * 1024)
            .spawn(|| {
                let mut unary = lit(1);
                for _ in 0..12 {
                    unary = call(13, &[unary]);
                }
                let mut nested = lit(1);
                for _ in 0..12 {
                    nested = list(&[nested]);
                }
                assert!(ev(&unary).is_ok());
                assert!(ev(&nested).is_ok());
            })
            .unwrap()
            .join()
            .unwrap();
    }
    #[test]
    fn constructed_duplicate_keys_rejected() {
        let ast = enc(|w| {
            w.map(1)
                .uint(6)
                .map(1)
                .uint(1)
                .array(2)
                .array(2)
                .text("x")
                .raw(&lit(1))
                .array(2)
                .bytes(b"x")
                .raw(&lit(2));
        });
        assert_eq!(check(&ast, &Limits::default()), Err(Code::Malformed));
        assert_eq!(ev(&ast), Err(Code::Malformed));
    }
    struct CountingInvoke(usize);
    impl Invoke for CountingInvoke {
        /// Invoke a component with encoded parameters, returning its result borrowed from out.
        fn invoke<'a>(
            &mut self,
            _: i32,
            _: i32,
            _: &[u8],
            out: &'a mut [u8],
        ) -> Result<&'a [u8], i32> {
            self.0 += 1;
            out[0] = 0xf5;
            Ok(&out[..1])
        }
    }
    struct LargeInvoke;
    impl Invoke for LargeInvoke {
        /// Invoke a component with encoded parameters, returning its result borrowed from out.
        fn invoke<'a>(
            &mut self,
            _: i32,
            _: i32,
            _: &[u8],
            out: &'a mut [u8],
        ) -> Result<&'a [u8], i32> {
            Ok(&out[..MAX_INPUT_BYTES + 1])
        }
    }
    #[test]
    fn preflight_and_fatal_errors_do_not_invoke() {
        let effect = call(23, &[lit(4), lit(5), ident(1)]);
        let duplicate = enc(|w| {
            w.map(1)
                .uint(6)
                .map(1)
                .uint(1)
                .array(2)
                .array(2)
                .text("x")
                .raw(&effect)
                .array(2)
                .bytes(b"x")
                .raw(&effect);
        });
        let malformed = call(1, &[vec![0], b(true)]);
        let mut s = [0; 1024];
        let mut o = [0; 64];
        let mut inv = CountingInvoke(0);
        for ast in [&duplicate, &malformed] {
            assert_eq!(
                eval(
                    ast,
                    &[0xa1, 1, 0xa0],
                    &mut s,
                    &mut o,
                    Limits::default(),
                    &mut inv
                ),
                Err(Code::Malformed)
            );
        }
        assert_eq!(inv.0, 0);
        let large = list(&[lit(1), lit(2)]);
        let ast = call(1, &[call(5, &[large.clone(), large]), effect]);
        let mut tiny = [0; 1];
        assert_eq!(
            eval(
                &ast,
                &[0xa1, 1, 0xa0],
                &mut tiny,
                &mut o,
                Limits::default(),
                &mut inv
            ),
            Err(Code::Size)
        );
        assert_eq!(inv.0, 0);
        let resource = call(1, &[list(&[lit(1)]), b(true)]);
        assert_eq!(
            eval(
                &resource,
                &[0xa0],
                &mut tiny,
                &mut o,
                Limits::default(),
                &mut inv
            ),
            Err(Code::Size)
        );
    }
    #[test]
    fn presence_only_absorbs_final_lookup() {
        let vars = [0xa1, 1, 0xa0];
        assert_eq!(
            run(&call(24, &[call(18, &[ident(1), ident(2)])]), &vars),
            Err(Code::NotFound)
        );
        assert_eq!(
            run(&call(24, &[select(ident(1), &[0x61, b'x'])]), &vars),
            Ok(truth(false))
        );
        assert_eq!(
            run(&call(24, &[select(ident(2), &[0x61, b'x'])]), &vars),
            Err(Code::NotFound)
        );
        assert_eq!(
            run(&call(24, &[call(18, &[lit(1), lit(0)])]), &vars),
            Err(Code::Type)
        );
        assert_eq!(
            run(&call(24, &[call(18, &[ident(1), txt("x")])]), &vars),
            Ok(truth(false))
        );
    }
    #[test]
    fn data_depth_and_large_schema_tags() {
        let vars = enc(|w| {
            w.map(1).uint(u64::MAX).int(7);
        });
        assert_eq!(run(&ident(u64::MAX), &vars), Ok(integer(7)));
        assert_eq!(validate_data(&[0x81, 0x81, 0], 1), Err(Code::Depth));
        assert_eq!(validate_data(&[0x81, 0x81, 0], 2), Ok(()));
        let large = enc(|w| {
            w.uint(u64::MAX);
        });
        assert_eq!(validate_data(&large, 32), Err(Code::Malformed));
    }
    #[test]
    fn input_and_value_limits() {
        let huge = vec![0; MAX_INPUT_BYTES + 1];
        let mut s = [0; 128];
        let mut o = [0; 32];
        assert_eq!(check(&huge, &Limits::default()), Err(Code::Size));
        assert_eq!(check_policy(&huge, &Limits::default()), Err(Code::Size));
        assert_eq!(
            eval(
                &lit(1),
                &huge,
                &mut s,
                &mut o,
                Limits::default(),
                &mut NoInvoke
            ),
            Err(Code::Size)
        );
        let mut big_s = vec![0; 4 * (MAX_INPUT_BYTES + 1)];
        assert_eq!(
            eval(
                &call(23, &[lit(4), lit(5), ident(1)]),
                &[0xa1, 1, 0xa0],
                &mut big_s,
                &mut o,
                Limits::default(),
                &mut LargeInvoke
            ),
            Err(Code::Size)
        );
        let mut nested = vec![0xa1, 1];
        nested.extend(core::iter::repeat_n(0x81, MAX_VALUE_DEPTH as usize));
        nested.push(0);
        assert_eq!(run(&lit(1), &nested), Err(Code::Depth));
        assert_eq!(run(&lit(1), &[0xa1, 0x80, 0]), Err(Code::Malformed));
        let mut map = vec![0xb8, 129];
        for i in 0..129 {
            map.extend([0x18, i, 0]);
        }
        assert_eq!(run(&lit(1), &map), Err(Code::Size));
    }
    struct Fake(bool);
    impl Invoke for Fake {
        /// Invoke a component with encoded parameters, returning its result borrowed from out.
        fn invoke<'a>(
            &mut self,
            c: i32,
            m: i32,
            p: &[u8],
            out: &'a mut [u8],
        ) -> Result<&'a [u8], i32> {
            assert_eq!((c, m), (4, 5));
            assert_eq!(p, &[0xa0]);
            if self.0 {
                return Err(-7);
            }
            out[..3].copy_from_slice(&[0xa1, 1, 9]);
            Ok(&out[..3])
        }
    }
    #[test]
    fn invocation() {
        let ast = select(call(23, &[lit(4), lit(5), ident(1)]), &[1]);
        let vars = [0xa1, 1, 0xa0];
        let mut s = [0; 1024];
        let mut o = [0; 50];
        assert_eq!(
            eval(
                &ast,
                &vars,
                &mut s,
                &mut o,
                Limits::default(),
                &mut Fake(false)
            ),
            Ok(&[9][..])
        );
        assert_eq!(
            eval(
                &ast,
                &vars,
                &mut s,
                &mut o,
                Limits::default(),
                &mut Fake(true)
            ),
            Err(Code::Invoke(-7))
        );
    }
    #[test]
    fn codes() {
        for c in [
            Code::Ok,
            Code::Unsupported,
            Code::Depth,
            Code::Nodes,
            Code::Malformed,
            Code::Type,
            Code::NotFound,
            Code::Arith,
            Code::Size,
            Code::Invoke(-7),
        ] {
            assert_eq!(Code::from_i32(c.to_i32()), c);
        }
    }
    #[test]
    fn double_and_fits() {
        assert_eq!(
            ev(&[0xa1, 1, 0xa1, 4, 0xfb, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(Code::Unsupported)
        );
        let u = enc(|w| {
            w.map(1).uint(1).map(1).uint(2).uint(2147483648);
        });
        assert_eq!(ev(&u), Err(Code::Malformed));
        assert_eq!(ev(&lit(i32::MIN)), Ok(integer(i32::MIN)));
    }
    #[test]
    fn depth_and_budget() {
        let mut a = lit(1);
        for _ in 0..32 {
            a = call(13, &[a]);
        }
        assert_eq!(check(&a, &Limits::default()), Err(Code::Depth));
        let mut s = [0; 512];
        let mut out = [0; 32];
        assert_eq!(
            eval(
                &a,
                &[0xa0],
                &mut s,
                &mut out,
                Limits::default(),
                &mut NoInvoke
            ),
            Err(Code::Depth)
        );
        let a = call(12, &[lit(1), lit(2)]);
        assert_eq!(
            eval(
                &a,
                &[0xa0],
                &mut s,
                &mut out,
                Limits {
                    max_depth: 32,
                    max_nodes: 2
                },
                &mut NoInvoke
            ),
            Err(Code::Nodes)
        );
    }
    #[test]
    fn corrupt_inputs_do_not_panic() {
        let a = call(12, &[lit(20), lit(5)]);
        for i in 0..a.len() {
            for v in [0, 0xff, 0x9f, 0xbb, 0xfb] {
                let mut x = a.clone();
                x[i] = v;
                let _ = ev(&x);
                let _ = check(&x, &Limits::default());
            }
        }
    }
    fn null() -> Vec<u8> {
        vec![0xa1, 1, 0xa1, 7, 0xf6]
    }
    #[test]
    fn structural_maps_and_nested_lists() {
        // Equal nested maps in different order, with distinct integer encodings.
        let vars = [
            0xa2, 1, 0xa2, 0x61, b'a', 0x81, 0xa1, 1, 5, 0x61, b'b', 2, 2, 0xa2, 0x61, b'b', 2,
            0x61, b'a', 0x81, 0xa1, 0x18, 1, 0x18, 5,
        ];
        assert_eq!(run(&call(5, &[ident(1), ident(2)]), &vars), Ok(truth(true)));
        assert_eq!(
            run(&call(11, &[ident(1), list(&[ident(2)])]), &vars),
            Ok(truth(true))
        );
        assert_eq!(bin(5, lit(5), vec![0xa1, 1, 0xa1, 2, 5]), Ok(truth(true)));
    }
    #[test]
    fn duplicate_maps_are_rejected_in_both_directions_and_nested() {
        let vars = [
            0xa2, 1, 0xa2, 0x61, b'a', 1, 0x61, b'a', 1, 2, 0xa2, 0x61, b'a', 1, 0x61, b'b', 2,
        ];
        for args in [[ident(1), ident(2)], [ident(2), ident(1)]] {
            assert_eq!(run(&call(5, &args), &vars), Err(Code::Malformed));
        }
        let nested = [0xa1, 1, 0x81, 0xa2, 0x61, b'a', 1, 0x41, b'a', 2];
        assert_eq!(run(&lit(1), &nested), Err(Code::Malformed));
    }
    struct DuplicateInvoke;
    impl Invoke for DuplicateInvoke {
        /// Invoke a component with encoded parameters, returning its result borrowed from out.
        fn invoke<'a>(
            &mut self,
            _: i32,
            _: i32,
            _: &[u8],
            out: &'a mut [u8],
        ) -> Result<&'a [u8], i32> {
            let data = [0x81, 0xa2, 1, 1, 0x18, 1, 2];
            out[..data.len()].copy_from_slice(&data);
            Ok(&out[..data.len()])
        }
    }
    #[test]
    fn invocation_rejects_nested_duplicate_map() {
        let ast = call(23, &[lit(4), lit(5), ident(1)]);
        let mut s = [0; 1024];
        let mut o = [0; 50];
        assert_eq!(
            eval(
                &ast,
                &[0xa1, 1, 0xa0],
                &mut s,
                &mut o,
                Limits::default(),
                &mut DuplicateInvoke
            ),
            Err(Code::Malformed)
        );
    }
    #[test]
    fn static_invocation_targets() {
        let ast = call(23, &[ident(1), lit(5), ident(2)]);
        assert_eq!(run(&ast, &[0xa2, 1, 4, 2, 0xa0]), Err(Code::Malformed));
        assert_eq!(check(&ast, &Limits::default()), Err(Code::Malformed));
        let ast = call(23, &[lit(4), ident(1), ident(2)]);
        assert_eq!(check(&ast, &Limits::default()), Err(Code::Malformed));
        assert_eq!(run(&ast, &[0xa2, 1, 5, 2, 0xa0]), Err(Code::Malformed));
    }
    #[test]
    fn null_values() {
        assert_eq!(ev(&null()), Ok(vec![0xf6]));
        assert!(check(&null(), &Limits::default()).is_ok());
        assert_eq!(bin(5, null(), null()), Ok(truth(true)));
        assert_eq!(bin(6, null(), lit(1)), Ok(truth(true)));
        for id in [7, 11, 12, 18, 20] {
            assert_eq!(bin(id, null(), lit(1)), Err(Code::Type));
        }
        assert_eq!(ev(&call(19, &[null()])), Err(Code::Type));
        assert_eq!(bin(11, null(), list(&[null()])), Err(Code::Type));
    }
    struct NullInvoke;
    impl Invoke for NullInvoke {
        /// Invoke a component with encoded parameters, returning its result borrowed from out.
        fn invoke<'a>(
            &mut self,
            _: i32,
            _: i32,
            _: &[u8],
            out: &'a mut [u8],
        ) -> Result<&'a [u8], i32> {
            out[0] = 0xf6;
            Ok(&out[..1])
        }
    }
    #[test]
    fn invocation_null_ternary() {
        let result = call(23, &[lit(4), lit(5), ident(1)]);
        let ast = call(4, &[call(5, &[result, null()]), lit(8), lit(9)]);
        let mut scratch = [0; 1024];
        let mut out = [0; 50];
        assert_eq!(
            eval(
                &ast,
                &[0xa1, 1, 0xa0],
                &mut scratch,
                &mut out,
                Limits::default(),
                &mut NullInvoke
            ),
            Ok(&[8][..])
        );
    }
}
