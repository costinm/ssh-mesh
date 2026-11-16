//! Owned, transport-independent component call correlations.
//!
//! A portable `no_std` + `alloc` bridge for issuing component RPCs and correlating their replies.
//! Callers supply a component, method, and encoded CBOR parameters; the bridge allocates a token,
//! validates the incoming response against the pending call, and forwards a result or error event.
//! Pending entries expire for slot cleanup; expiry does not itself send a timeout event.
//! Transport limits may be lower than the bridge's caller-selected bounds.

use crate::cbor::{Item, Reader, Writer};
use alloc::vec;

/// Error when an envelope, response, token, or parameter payload is malformed or unmatched.
pub const ERR_ARG: i32 = -1;
/// Error returned when all correlation slots are occupied by unexpired calls.
pub const ERR_BUSY: i32 = -5;
/// Error returned when the caller's output buffer or encoded frame size capacity is insufficient.
pub const ERR_SIZE: i32 = -8;

/// One in-flight component call correlation slot.
#[derive(Clone, Copy)]
pub struct Pending {
    token: u64,
    until: u64,
    component: i32,
    method: i32,
}

/// Transport-independent correlation table for legacy fire-and-forget calls.
pub struct PendingCalls<const N: usize> {
    pending: [Option<Pending>; N],
    next: u64,
}

impl<const N: usize> PendingCalls<N> {
    /// Construct an empty [`PendingCalls`] correlation table with `N` slots.
    pub const fn new() -> Self {
        Self {
            pending: [None; N],
            next: 0,
        }
    }

    /// Reserve a correlation token, encode one call envelope, and send it via `send`.
    ///
    /// All clock/expiry arguments use monotonic milliseconds. `params` must encode exactly one
    /// valid CBOR item. If encoding or `send` returns a negative status, the reserved slot is
    /// released immediately.
    pub fn invoke(
        &mut self,
        now: u64,
        expiry_ms: u64,
        component: i32,
        method: i32,
        params: &[u8],
        mut send: impl FnMut(u64, &[u8]) -> i32,
    ) -> Result<(), i32> {
        validate_one_item(params)?;
        let capacity = params.len().checked_add(64).ok_or(ERR_SIZE)?;
        let token = reserve(
            &mut self.pending,
            &mut self.next,
            now,
            component,
            method,
            expiry_ms,
        )?;
        let mut buf = vec![0; capacity];
        let rc = match envelope(&mut buf, component, method, token, params) {
            Ok(data) => send(token, data),
            Err(rc) => rc,
        };
        if rc < 0 {
            take(&mut self.pending, token, now);
            Err(rc)
        } else {
            Ok(())
        }
    }

    /// Validate a correlated response `input` against slot `id` at `now`, re-encode the validated
    /// reply into `out`, and forward it with `send`.
    ///
    /// Keeps the reservation active if `send` fails with a negative status so the caller can retry.
    pub fn forward(
        &mut self,
        id: u64,
        now: u64,
        input: &[u8],
        out: &mut [u8],
        validate: impl Fn(&[u8]) -> Result<(), i32>,
        send: impl FnOnce(&[u8]) -> i32,
    ) -> i32 {
        let data = match prepare(&self.pending, id, now, input, out, validate) {
            Ok(data) => data,
            Err(rc) => return rc,
        };
        let rc = send(data);
        if rc >= 0 {
            take(&mut self.pending, id, now);
        }
        rc
    }
}

impl<const N: usize> Default for PendingCalls<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Reserve an unused slot in `pending` expiring at `now.saturating_add(expiry)`, returning the
/// non-zero correlation token (`1..2^62`).
pub fn reserve<const N: usize>(
    pending: &mut [Option<Pending>; N],
    next: &mut u64,
    now: u64,
    component: i32,
    method: i32,
    expiry: u64,
) -> Result<u64, i32> {
    let slot = pending
        .iter()
        .position(|p| p.is_none_or(|p| p.until <= now))
        .ok_or(ERR_BUSY)?;
    loop {
        *next = (next.wrapping_add(1) & ((1u64 << 62) - 1)).max(1);
        if !pending
            .iter()
            .flatten()
            .any(|p| p.token == *next && p.until > now)
        {
            break;
        }
    }
    pending[slot] = Some(Pending {
        token: *next,
        until: now.saturating_add(expiry),
        component,
        method,
    });
    Ok(*next)
}

/// Remove the slot matching `token` and return `true` if it existed and had not expired at `now`.
pub fn take<const N: usize>(pending: &mut [Option<Pending>; N], token: u64, now: u64) -> bool {
    if let Some(slot) = pending
        .iter_mut()
        .find(|p| p.is_some_and(|p| p.token == token))
    {
        return slot.take().is_some_and(|p| p.until > now);
    }
    false
}

/// Encode one component-call request envelope (`{1: component, 2: method, 3: token, 5: params}`)
/// into `buf`, verifying that `params` contains exactly one valid CBOR item.
pub fn envelope<'a>(
    buf: &'a mut [u8],
    component: i32,
    method: i32,
    token: u64,
    params: &[u8],
) -> Result<&'a [u8], i32> {
    validate_one_item(params)?;
    let mut w = Writer::new(buf);
    w.map(4)
        .uint(1)
        .int(component.into())
        .uint(2)
        .int(method.into())
        .uint(3)
        .uint(token)
        .uint(5)
        .raw(params);
    w.finish().ok_or(ERR_SIZE)
}

fn validate_one_item(data: &[u8]) -> Result<(), i32> {
    let mut r = Reader::new(data);
    item(&mut r)?;
    if !r.rest().is_empty() {
        return Err(ERR_ARG);
    }
    Ok(())
}

fn item<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], i32> {
    let start = r.rest();
    let mut left = 1usize;
    while left > 0 {
        left -= 1;
        // Preserve float encodings for the evaluator to classify as unsupported.
        let rest = r.rest();
        let float_len = match rest.first() {
            Some(0xf9) => 3,
            Some(0xfa) => 5,
            Some(0xfb) => 9,
            _ => 0,
        };
        if float_len != 0 {
            if rest.len() < float_len {
                return Err(ERR_ARG);
            }
            *r = Reader::new(&rest[float_len..]);
            continue;
        }
        let children = match r.next().ok_or(ERR_ARG)? {
            Item::Array(n) => n,
            Item::Map(n) => n.checked_mul(2).ok_or(ERR_ARG)?,
            _ => 0,
        };
        left = left.checked_add(children).ok_or(ERR_ARG)?;
        if left > r.rest().len() {
            return Err(ERR_ARG);
        }
    }
    Ok(&start[..start.len() - r.rest().len()])
}

/// Extract integer-keyed CBOR map entries (`1..N`) from `data` as raw encoded CBOR item slices.
pub fn fields<const N: usize>(data: &[u8]) -> Result<[Option<&[u8]>; N], i32> {
    let mut r = Reader::new(data);
    let Some(Item::Map(n)) = r.next() else {
        return Err(ERR_ARG);
    };
    let mut result = [None; N];
    for _ in 0..n {
        let Some(Item::Uint(k)) = r.next() else {
            return Err(ERR_ARG);
        };
        let k = usize::try_from(k).map_err(|_| ERR_ARG)?;
        if k == 0 || k >= N || result[k].is_some() {
            return Err(ERR_ARG);
        }
        result[k] = Some(item(&mut r)?);
    }
    if !r.rest().is_empty() {
        return Err(ERR_ARG);
    }
    Ok(result)
}

/// Validate a correlated response `input` against `pending` for token `id` at `now` and encode a
/// canonical response envelope (`{1: component, 2: method, 3: id, 6|7: result_or_err}`) into `out`.
pub fn prepare<'a, const N: usize>(
    pending: &[Option<Pending>; N],
    id: u64,
    now: u64,
    input: &[u8],
    out: &'a mut [u8],
    validate: impl Fn(&[u8]) -> Result<(), i32>,
) -> Result<&'a [u8], i32> {
    let expected = pending
        .iter()
        .flatten()
        .find(|p| p.token == id && p.until > now)
        .ok_or(ERR_ARG)?;
    let f = fields::<8>(input).map_err(|_| ERR_ARG)?;
    if f[4].is_some() || f[5].is_some() {
        return Err(ERR_ARG);
    }
    let (Some(component), Some(method), Some(token)) = (f[1], f[2], f[3]) else {
        return Err(ERR_ARG);
    };
    let int = |data| {
        let mut r = Reader::new(data);
        r.next().and_then(|v| v.as_int())
    };
    if int(component) != Some(i64::from(expected.component))
        || int(method) != Some(i64::from(expected.method))
    {
        return Err(ERR_ARG);
    }
    let mut r = Reader::new(token);
    if r.next() != Some(Item::Uint(id)) {
        return Err(ERR_ARG);
    }
    let (key, result) = match (f[6], f[7]) {
        (Some(v), None) => (6, v),
        (None, Some(v)) => (7, v),
        _ => return Err(ERR_ARG),
    };
    validate(result)?;
    if key == 7 && int(result).and_then(|n| i32::try_from(n).ok()).is_none() {
        return Err(ERR_ARG);
    }
    let mut w = Writer::new(out);
    w.map(4)
        .uint(1)
        .raw(component)
        .uint(2)
        .raw(method)
        .uint(3)
        .uint(id)
        .uint(key)
        .raw(result);
    w.finish().ok_or(ERR_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Writer;
    use alloc::{vec, vec::Vec};

    fn reply(id: u64, component: i32, method: i32, key: u64, body: &[u8]) -> Vec<u8> {
        let mut buf = [0; 256];
        let mut w = Writer::new(&mut buf);
        w.map(4)
            .uint(1)
            .int(component.into())
            .uint(2)
            .int(method.into())
            .uint(3)
            .uint(id)
            .uint(key)
            .raw(body);
        w.finish().unwrap().to_vec()
    }

    #[test]
    fn new_capacity_expiry_and_send_rollback() {
        let mut calls = PendingCalls::<1>::new();
        assert_eq!(calls.invoke(0, 10, 12, 3, &[0xa0], |_, _| -9), Err(-9));
        let mut id = 0;
        calls
            .invoke(0, 10, 12, 3, &[0xa0], |token, _| {
                id = token;
                0
            })
            .unwrap();
        assert!(id > 0 && id < (1 << 62));
        assert_eq!(
            calls.invoke(9, 10, 12, 3, &[0xa0], |_, _| panic!()),
            Err(ERR_BUSY)
        );
        let mut out = [0; 128];
        assert_eq!(
            calls.forward(
                id,
                10,
                &reply(id, 12, 3, 6, &[0xf5]),
                &mut out,
                |_| Ok(()),
                |_| panic!()
            ),
            ERR_ARG
        );
        calls
            .invoke(10, 10, 12, 3, &[0xa0], |token, _| {
                assert_ne!(token, id);
                0
            })
            .unwrap();
        assert_eq!(
            PendingCalls::<0>::default().invoke(0, 1, 1, 1, &[0xa0], |_, _| panic!()),
            Err(ERR_BUSY)
        );
    }

    #[test]
    fn invoke_and_envelope_reject_invalid_or_multi_item_params() {
        let mut calls = PendingCalls::<1>::new();
        let mut buf = [0u8; 64];
        for bad_params in [&[][..], &[0xff], &[0xa1, 0x01], &[0xa0, 0xa0]] {
            assert_eq!(envelope(&mut buf, 1, 2, 3, bad_params), Err(ERR_ARG));
            assert_eq!(
                calls.invoke(0, 10, 1, 2, bad_params, |_, _| panic!()),
                Err(ERR_ARG)
            );
        }
        // Slot must remain free after rejecting invalid params.
        calls.invoke(0, 10, 1, 2, &[0xa0], |_, _| 0).unwrap();
    }

    #[test]
    fn validation_retry_and_opaque_result() {
        let mut calls = PendingCalls::<1>::default();
        let mut id = 0;
        calls
            .invoke(0, 100, 12, 3, &[0xa0], |token, _| {
                id = token;
                0
            })
            .unwrap();
        let mut out = [0; 128];
        for bad in [
            vec![0xff],
            reply(id, 13, 3, 6, &[0xf5]),
            reply(id, 12, 4, 6, &[0xf5]),
            reply(id + 1, 12, 3, 6, &[0xf5]),
            reply(id, 12, 3, 7, &[0xf5]),
        ] {
            assert_eq!(
                calls.forward(id, 1, &bad, &mut out, |_| Ok(()), |_| panic!()),
                -1
            );
        }
        let good = reply(id, 12, 3, 6, &[0xa1, 0x61, b'x', 0x82, 0xf5, 0xf6]);
        assert_eq!(
            calls.forward(id, 1, &good, &mut out, |_| Err(-7), |_| panic!()),
            -7
        );
        assert_eq!(
            calls.forward(
                id,
                1,
                &good,
                &mut out,
                |_| Ok(()),
                |event| {
                    assert_eq!(event, good);
                    -9
                }
            ),
            -9
        );
        assert_eq!(
            calls.forward(
                id,
                1,
                &good,
                &mut out,
                |_| Ok(()),
                |event| {
                    assert_eq!(event, good);
                    1
                }
            ),
            1
        );
        assert_eq!(
            calls.forward(id, 1, &good, &mut out, |_| Ok(()), |_| panic!()),
            -1
        );
        calls
            .invoke(2, 100, 12, 3, &[0xa0], |token, _| {
                id = token;
                0
            })
            .unwrap();
        let error = reply(id, 12, 3, 7, &[0x38, 41]);
        assert_eq!(
            calls.forward(
                id,
                2,
                &error,
                &mut out,
                |body| {
                    assert_eq!(body, [0x38, 41]);
                    Ok(())
                },
                |event| {
                    assert_eq!(event, error);
                    0
                }
            ),
            0
        );
    }
}
