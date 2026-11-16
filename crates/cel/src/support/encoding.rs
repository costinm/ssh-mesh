//! CEL-specific CBOR value and expression helpers.
use crate::{Code, MAX_INPUT_BYTES, MAX_MAP_ENTRIES, MAX_VALUE_DEPTH};
use mesh_api::cbor::{Item, Reader, Writer};

// Walk CEL fragments with checked container counts; floats may be skipped here
// so constant decoding can report Unsupported.
pub(crate) fn take<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], Code> {
    let start = r.rest();
    let mut pending = 1usize;
    while pending != 0 {
        pending -= 1;
        // Permit skipping a complete float so its enclosing constant can report
        // Unsupported; decoding a float as a value remains forbidden.
        let rest = r.rest();
        let float_len = match rest.first() {
            Some(0xf9) => 3,
            Some(0xfa) => 5,
            Some(0xfb) => 9,
            _ => 0,
        };
        if float_len != 0 {
            if rest.len() < float_len {
                return Err(Code::Malformed);
            }
            *r = Reader::new(&rest[float_len..]);
            continue;
        }
        let n = match r.next().ok_or(Code::Malformed)? {
            Item::Array(n) => n,
            Item::Map(n) => n.checked_mul(2).ok_or(Code::Malformed)?,
            _ => 0,
        };
        pending = pending.checked_add(n).ok_or(Code::Malformed)?;
        if pending > r.rest().len() {
            return Err(Code::Malformed);
        }
    }
    Ok(&start[..start.len() - r.rest().len()])
}
pub(crate) fn one(data: &[u8]) -> Result<Item<'_>, Code> {
    let mut r = Reader::new(data);
    let item = r.next().ok_or(Code::Malformed)?;
    let mut all = Reader::new(data);
    take(&mut all)?;
    if !all.rest().is_empty() {
        return Err(Code::Malformed);
    }
    Ok(item)
}
pub(crate) fn fields(data: &[u8]) -> Result<[Option<&[u8]>; 4], Code> {
    let mut r = Reader::new(data);
    let Item::Map(n) = r.next().ok_or(Code::Malformed)? else {
        return Err(Code::Malformed);
    };
    let mut result = [None; 4];
    for _ in 0..n {
        let Some(Item::Uint(k @ 1..=3)) = r.next() else {
            return Err(Code::Malformed);
        };
        let slot = &mut result[k as usize];
        if slot.is_some() {
            return Err(Code::Malformed);
        }
        *slot = Some(take(&mut r)?);
    }
    if !r.rest().is_empty() {
        return Err(Code::Malformed);
    }
    Ok(result)
}
pub(crate) fn required<'a>(f: &[Option<&'a [u8]>; 4], k: usize) -> Result<&'a [u8], Code> {
    f[k].ok_or(Code::Malformed)
}
pub(crate) fn uint(data: &[u8]) -> Result<u64, Code> {
    match one(data)? {
        Item::Uint(n) => Ok(n),
        _ => Err(Code::Malformed),
    }
}
pub(crate) fn node(data: &[u8]) -> Result<(u64, &[u8]), Code> {
    let mut r = Reader::new(data);
    if r.next() != Some(Item::Map(1)) {
        return Err(Code::Malformed);
    }
    let Some(Item::Uint(k)) = r.next() else {
        return Err(Code::Malformed);
    };
    if k == 7 {
        return Err(Code::Unsupported);
    }
    if !(1..=6).contains(&k) {
        return Err(Code::Malformed);
    }
    let payload = take(&mut r)?;
    if !r.rest().is_empty() {
        return Err(Code::Malformed);
    }
    Ok((k, payload))
}
pub(crate) fn array(data: &[u8]) -> Result<(usize, Reader<'_>), Code> {
    let mut r = Reader::new(data);
    let Some(Item::Array(n)) = r.next() else {
        return Err(Code::Malformed);
    };
    Ok((n, r))
}
#[derive(Clone, Copy)]
pub(crate) enum Val<'a> {
    Int(i32),
    Bool(bool),
    Null,
    Bytes(&'a [u8]),
    Text(&'a [u8]),
    List(&'a [u8]),
    Map(&'a [u8]),
}
pub(crate) fn value(data: &[u8]) -> Result<Val<'_>, Code> {
    Ok(match one(data)? {
        Item::Uint(n) => Val::Int(i32::try_from(n).map_err(|_| Code::Malformed)?),
        Item::Neg(n) => {
            Val::Int(i32::try_from(-1i128 - i128::from(n)).map_err(|_| Code::Malformed)?)
        }
        Item::Bool(b) => Val::Bool(b),
        Item::Null => Val::Null,
        Item::Bytes(s) => Val::Bytes(s),
        Item::Text(s) => Val::Text(s),
        Item::Array(_) => Val::List(data),
        Item::Map(_) => Val::Map(data),
    })
}
pub(crate) fn constant(data: &[u8]) -> Result<Val<'_>, Code> {
    let mut r = Reader::new(data);
    if r.next() != Some(Item::Map(1)) {
        return Err(Code::Malformed);
    }
    let Some(Item::Uint(k)) = r.next() else {
        return Err(Code::Malformed);
    };
    if k == 4 {
        return Err(Code::Unsupported);
    }
    let v = take(&mut r)?;
    if !r.rest().is_empty() {
        return Err(Code::Malformed);
    }
    let item = one(v)?;
    match (k, item) {
        (1, Item::Uint(_) | Item::Neg(_)) | (2, Item::Uint(_)) => value(v),
        (3, Item::Bool(b)) => Ok(Val::Bool(b)),
        (5, Item::Text(s)) => Ok(Val::Text(s)),
        (6, Item::Bytes(s)) => Ok(Val::Bytes(s)),
        (7, Item::Null) if v == [0xf6] => Ok(Val::Null),
        _ => Err(Code::Malformed),
    }
}
pub(crate) fn write_val<'a>(w: &mut Writer<'a>, v: Val<'_>) {
    match v {
        Val::Int(n) => {
            w.int(n.into());
        }
        Val::Bool(b) => {
            w.boolean(b);
        }
        Val::Null => {
            w.null();
        }
        Val::Bytes(s) => {
            w.bytes(s);
        }
        Val::Text(s) => {
            w.text_raw(s);
        }
        Val::List(s) | Val::Map(s) => {
            w.raw(s);
        }
    }
}
pub(crate) fn encoded_len(v: Val<'_>) -> Result<usize, Code> {
    let n = match v {
        Val::Int(_) => 9,
        Val::Bool(_) | Val::Null => 1,
        Val::Bytes(s) | Val::Text(s) => s.len().checked_add(9).ok_or(Code::Size)?,
        Val::List(s) | Val::Map(s) => s.len(),
    };
    Ok(n)
}
pub(crate) fn lookup<'a>(data: &'a [u8], key: Val<'_>) -> Result<Val<'a>, Code> {
    let mut r = Reader::new(data);
    match r.next().ok_or(Code::Malformed)? {
        Item::Map(n) => {
            for _ in 0..n {
                let k = take(&mut r)?;
                let v = take(&mut r)?;
                // Full-width schema keys are valid data but cannot match a CEL i32.
                if matches!(one(k)?, Item::Uint(n) | Item::Neg(n) if n > i32::MAX as u64) {
                    continue;
                }
                if matches!(equal(value(k)?, key), Ok(true)) {
                    return value(v);
                }
            }
            Err(Code::NotFound)
        }
        Item::Array(n) => {
            let Val::Int(i) = key else {
                return Err(Code::Type);
            };
            let i = usize::try_from(i).map_err(|_| Code::NotFound)?;
            if i >= n {
                return Err(Code::NotFound);
            }
            for _ in 0..i {
                take(&mut r)?;
            }
            value(take(&mut r)?)
        }
        _ => Err(Code::Type),
    }
}
pub(crate) fn lookup_tag(data: &[u8], tag: u64) -> Result<Val<'_>, Code> {
    let mut r = Reader::new(data);
    let Some(Item::Map(n)) = r.next() else {
        return Err(Code::Type);
    };
    for _ in 0..n {
        let k = take(&mut r)?;
        let v = take(&mut r)?;
        if matches!(one(k), Ok(Item::Uint(n)) if n == tag) {
            return value(v);
        }
    }
    Err(Code::NotFound)
}
pub(crate) fn equal(a: Val<'_>, b: Val<'_>) -> Result<bool, Code> {
    Ok(match (a, b) {
        (Val::Null, Val::Null) => true,
        (Val::Null, _) | (_, Val::Null) => false,
        (Val::Int(a), Val::Int(b)) => a == b,
        (Val::Bool(a), Val::Bool(b)) => a == b,
        (Val::Text(a) | Val::Bytes(a), Val::Text(b) | Val::Bytes(b)) => a == b,
        (Val::List(a), Val::List(b)) | (Val::Map(a), Val::Map(b)) => val_eq(a, b, 0)?,
        _ => false,
    })
}
// Compare encoded container members without depending on their encoding or map order.
/// Iterative structural comparison. Map keys are validated scalar values;
/// only value pairs occupy the bounded continuation work list.
pub(crate) fn val_eq<'a>(a: &'a [u8], b: &'a [u8], depth: u32) -> Result<bool, Code> {
    enum Frame<'a> {
        Pair(&'a [u8], &'a [u8], u32),
        Array(Reader<'a>, Reader<'a>, usize, u32),
        Map(Reader<'a>, Reader<'a>, usize, usize, u32),
    }
    fn scalar(a: Item<'_>, b: Item<'_>) -> bool {
        match (a, b) {
            (Item::Uint(x), Item::Uint(y)) | (Item::Neg(x), Item::Neg(y)) => x == y,
            (Item::Bool(x), Item::Bool(y)) => x == y,
            (Item::Null, Item::Null) => true,
            (Item::Text(x) | Item::Bytes(x), Item::Text(y) | Item::Bytes(y)) => x == y,
            _ => false,
        }
    }
    fn push<'a>(
        work: &mut [Option<Frame<'a>>],
        len: &mut usize,
        frame: Frame<'a>,
    ) -> Result<(), Code> {
        let slot = work.get_mut(*len).ok_or(Code::Depth)?;
        *slot = Some(frame);
        *len += 1;
        Ok(())
    }
    // One continuation per ancestor plus the current pair; no heap allocation.
    let mut work = [const { None }; crate::MAX_VALUE_DEPTH as usize + 2];
    let mut len = 0;
    push(&mut work, &mut len, Frame::Pair(a, b, depth))?;
    while len != 0 {
        len -= 1;
        let frame = work[len].take().ok_or(Code::Malformed)?;
        match frame {
            Frame::Pair(a, b, d) => {
                if d > crate::MAX_VALUE_DEPTH {
                    return Err(Code::Depth);
                }
                let mut ar = Reader::new(a);
                let mut br = Reader::new(b);
                let x = ar.next().ok_or(Code::Malformed)?;
                let y = br.next().ok_or(Code::Malformed)?;
                match (x, y) {
                    (Item::Array(n), Item::Array(m)) => {
                        if n != m {
                            return Ok(false);
                        }
                        push(&mut work, &mut len, Frame::Array(ar, br, n, d))?;
                    }
                    (Item::Map(n), Item::Map(m)) => {
                        if n != m {
                            return Ok(false);
                        }
                        push(&mut work, &mut len, Frame::Map(ar, br, n, m, d))?;
                    }
                    _ => {
                        if !scalar(x, y) {
                            return Ok(false);
                        }
                    }
                }
            }
            Frame::Array(mut a, mut b, n, d) => {
                if n != 0 {
                    let av = take(&mut a)?;
                    let bv = take(&mut b)?;
                    push(&mut work, &mut len, Frame::Array(a, b, n - 1, d))?;
                    push(&mut work, &mut len, Frame::Pair(av, bv, d + 1))?;
                }
            }
            Frame::Map(mut a, b, n, m, d) => {
                if n != 0 {
                    let key = one(take(&mut a)?)?;
                    let value = take(&mut a)?;
                    let mut scan = b;
                    let mut found = None;
                    for _ in 0..m {
                        let other = one(take(&mut scan)?)?;
                        let v = take(&mut scan)?;
                        if scalar(key, other) {
                            found = Some(v);
                            break;
                        }
                    }
                    let Some(other) = found else { return Ok(false) };
                    push(&mut work, &mut len, Frame::Map(a, b, n - 1, m, d))?;
                    push(&mut work, &mut len, Frame::Pair(value, other, d + 1))?;
                }
            }
        }
    }
    Ok(true)
}
// Map keys are scalar; text and bytes keys compare by their contents.
/// Validate one bounded CBOR value, including unique scalar map keys.
/// `max_depth` limits nested data independently of expression nesting.
pub fn validate_data(data: &[u8], max_depth: u32) -> Result<(), Code> {
    validate_value(
        data,
        MAX_VALUE_DEPTH.saturating_sub(max_depth.min(MAX_VALUE_DEPTH)),
    )
}

pub(crate) fn validate_value(data: &[u8], depth: u32) -> Result<(), Code> {
    if data.len() > MAX_INPUT_BYTES {
        return Err(Code::Size);
    }
    if depth > MAX_VALUE_DEPTH {
        return Err(Code::Depth);
    }
    let mut r = Reader::new(data);
    let mut remaining = [0usize; MAX_VALUE_DEPTH as usize + 1];
    let mut maps = [false; MAX_VALUE_DEPTH as usize + 1];
    let mut level = depth as usize;
    remaining[level] = 1;
    loop {
        if remaining[level] == 0 {
            if level == depth as usize {
                break;
            }
            level -= 1;
            continue;
        }
        remaining[level] -= 1;
        let key_position = maps[level] && remaining[level] % 2 == 1;
        // Reader maps CBOR undefined to Null, but CEL only permits actual null.
        if r.rest().first() == Some(&0xf7) {
            return Err(Code::Malformed);
        }
        let item = r.next().ok_or(Code::Malformed)?;
        let children = match item {
            // Schema tags are u64 map keys, not CEL integer values.
            Item::Uint(n) | Item::Neg(n) if !key_position && n > i32::MAX as u64 => {
                return Err(Code::Malformed);
            }
            Item::Array(n) => n,
            Item::Map(n) => {
                if n > MAX_MAP_ENTRIES {
                    return Err(Code::Size);
                }
                let entries = r;
                let mut scan = r;
                for i in 0..n {
                    if scan.rest().first() == Some(&0xf7) {
                        return Err(Code::Malformed);
                    }
                    let key = take(&mut scan)?;
                    match one(key)? {
                        Item::Uint(_)
                        | Item::Neg(_)
                        | Item::Bool(_)
                        | Item::Null
                        | Item::Text(_)
                        | Item::Bytes(_) => {}
                        _ => return Err(Code::Malformed),
                    }
                    take(&mut scan)?;
                    let mut prior = entries;
                    for _ in 0..i {
                        let other = take(&mut prior)?;
                        take(&mut prior)?;
                        if val_eq(key, other, 0)? {
                            return Err(Code::Malformed);
                        }
                    }
                }
                n.checked_mul(2).ok_or(Code::Malformed)?
            }
            _ => 0,
        };
        if children != 0 {
            if level == MAX_VALUE_DEPTH as usize {
                return Err(Code::Depth);
            }
            level += 1;
            remaining[level] = children;
            maps[level] = matches!(item, Item::Map(_));
        }
    }
    if !r.rest().is_empty() {
        return Err(Code::Malformed);
    }
    Ok(())
}
pub(crate) fn static_int(ast: &[u8]) -> Result<(), Code> {
    let (kind, p) = node(ast).map_err(|_| Code::Malformed)?;
    if kind != 1 {
        return Err(Code::Malformed);
    }
    match constant(p) {
        Ok(Val::Int(_)) => Ok(()),
        _ => Err(Code::Malformed),
    }
}
