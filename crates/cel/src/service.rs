//! Alarm-driven program service. No borrowed ABI data is retained.
use crate::support::status::{ERR_ARG, ERR_BUSY, ERR_SIZE};
use crate::{
    Code, Limits,
    program::{Event, Program, ProgramLimits, Rule, RuleList, Runner, wire},
};
use alloc::{boxed::Box, vec, vec::Vec};
use mesh_api::cbor::{Item, Reader, Writer};

// Envelope parsers accept positive signed-i64 tokens, so reserve bit 62,
// not the sign bit. The legacy namespace stays below this bit.
/// Namespace bit distinguishing program calls from legacy calls.
pub const TOKEN_BIT: u64 = 1 << 62;
/// Default call response timeout in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 10_000;
#[derive(Clone, Copy)]
struct Pending {
    wire: u64,
    runner: u64,
    component: i32,
    method: i32,
    until: u64,
}
struct Active {
    runner: Runner,
    pending: Vec<Option<Pending>>,
    deferred: Option<Event>,
}

/// Null is a valid empty state in the host's zero-filled state block.
#[derive(Default)]
pub struct Service {
    active: Option<Box<Active>>,
    next: u64,
    alarm: u64,
}
impl Service {
    /// Drop the active program and all retained correlation state.
    pub fn clear(&mut self) {
        self.active = None;
    }
    fn active(&mut self) -> Option<&mut Active> {
        self.active.as_deref_mut()
    }
    /// Admit a structurally and semantically valid program.
    /// Returns ERR_BUSY if another program is active; invalid input is not retained.
    pub fn start(&mut self, data: &[u8], limits: ProgramLimits, max_depth: u32) -> Result<(), i32> {
        if self.active.is_some() {
            return Err(ERR_BUSY);
        }
        let program = wire::decode(data, &limits).map_err(Code::to_i32)?;
        for list in &program.lists {
            for rule in &list.rules {
                if let Rule::Eval { expr } | Rule::Set { expr, .. } | Rule::BreakIf { expr } = rule
                {
                    crate::check(
                        expr,
                        &Limits {
                            max_depth: limits.max_frames.min(128) as u32,
                            max_nodes: limits.max_nodes,
                        },
                    )
                    .map_err(Code::to_i32)?;
                }
            }
            crate::validate_data(&list.context, max_depth).map_err(Code::to_i32)?;
        }
        // A sequence can wait for only one call at a time. Size storage from
        // actual admitted lists, not an embedding module's fixed capacity.
        let capacity = limits.max_pending.min(program.lists.len());
        let runner = Runner::new(program, limits).map_err(Code::to_i32)?;
        self.active = Some(Box::new(Active {
            runner,
            pending: vec![None; capacity],
            deferred: None,
        }));
        Ok(())
    }
    /// Match without consuming unknown or malformed responses. Returns None for legacy IDs.
    pub fn answer(&mut self, id: u64, now: u64, data: &[u8], max_depth: u32) -> Option<i32> {
        if id & TOKEN_BIT == 0 {
            return None;
        }
        let Some(active) = self.active() else {
            return Some(ERR_ARG);
        };
        let Some(slot) = active
            .pending
            .iter()
            .position(|p| p.is_some_and(|p| p.wire == id && now < p.until))
        else {
            return Some(ERR_ARG);
        };
        let p = active.pending[slot]?;
        let result = match response(p, data) {
            Ok(result) => result,
            Err(rc) => return Some(rc),
        };
        let validation = match result {
            Ok(value) => crate::validate_data(value, max_depth),
            Err(_) => Ok(()),
        };
        if let Err(code) = validation {
            return Some(code.to_i32());
        }
        match active
            .runner
            .resume_at(now, p.runner, p.component, p.method, result)
        {
            Ok(()) => {
                active.pending[slot] = None;
                Some(0)
            }
            Err(code) => {
                if !active.runner.is_pending(p.runner) {
                    active.pending[slot] = None;
                }
                Some(code.to_i32())
            }
        }
    }
    /// Process exactly one runner event per request; caller retries events after send errors.
    /// Calls expire at the earlier of timeout_ms and the program timeout.
    pub fn poll(
        &mut self,
        now: u64,
        mut send: impl FnMut(u32, i32, i32, u64, &[u8]) -> i32,
        out: &mut [u8],
        timeout_ms: u64,
        routes: Routes,
    ) -> Result<usize, i32> {
        // Split the counter from the separately allocated active state.
        let next = &mut self.next;
        let Some(active) = self.active.as_deref_mut() else {
            return status(out, 0, None);
        };
        let event = active
            .deferred
            .take()
            .unwrap_or_else(|| active.runner.poll(now));
        for slot in &mut active.pending {
            if slot.is_some_and(|p| now >= p.until || !active.runner.is_pending(p.runner)) {
                *slot = None;
            }
        }
        match event {
            Event::Call {
                token,
                list: _,
                component,
                method,
                params,
            } => {
                let Some(slot) = active.pending.iter().position(Option::is_none) else {
                    let _ = active
                        .runner
                        .resume(token, component, method, Err(ERR_BUSY));
                    return status(out, 1, None);
                };
                *next = (next.wrapping_add(1) & (TOKEN_BIT - 1)).max(1);
                // Never reuse a live wire token, even after counter wrap.
                while active
                    .pending
                    .iter()
                    .flatten()
                    .any(|p| p.wire == (TOKEN_BIT | *next))
                {
                    *next = (next.wrapping_add(1) & (TOKEN_BIT - 1)).max(1);
                }
                let id = TOKEN_BIT | *next;
                // Both layers use the same deadline, even when the transport
                // supplies a shorter timeout than the program profile.
                let until = active
                    .runner
                    .limit_deadline(token, now.saturating_add(timeout_ms))
                    .map_err(Code::to_i32)?;
                let mut buf = vec![0; params.len().saturating_add(64)];
                let rc = match envelope(&mut buf, component, method, id, &params) {
                    Ok(data) => send(routes.envelope_addr, 0, 0, id, data),
                    Err(rc) => rc,
                };
                if rc < 0 {
                    let _ = active.runner.resume(token, component, method, Err(rc));
                } else {
                    active.pending[slot] = Some(Pending {
                        wire: id,
                        runner: token,
                        component,
                        method,
                        until,
                    });
                }
                status(out, 1, None)
            }
            Event::Complete { list, ref result } => {
                let mut buf = vec![0; result.len().saturating_add(32)];
                let mut w = Writer::new(&mut buf);
                w.map(3)
                    .uint(1)
                    .uint(list as u64)
                    .uint(2)
                    .uint(1)
                    .uint(3)
                    .raw(result);
                let data = w.finish().ok_or(ERR_SIZE)?;
                let rc = send(
                    routes.event_addr,
                    routes.event_component,
                    routes.event_method,
                    0,
                    data,
                );
                if rc < 0 {
                    active.deferred = Some(event);
                    return Err(rc);
                }
                status(out, 1, None)
            }
            Event::Failed { list, error } => {
                let mut buf = [0; 64];
                let mut w = Writer::new(&mut buf);
                w.map(3)
                    .uint(1)
                    .uint(list as u64)
                    .uint(2)
                    .uint(2)
                    .uint(3)
                    .int(error.to_i32().into());
                let data = w.finish().ok_or(ERR_SIZE)?;
                let rc = send(
                    routes.event_addr,
                    routes.event_component,
                    routes.event_method,
                    0,
                    data,
                );
                if rc < 0 {
                    active.deferred = Some(Event::Failed { list, error });
                    return Err(rc);
                }
                status(out, 1, None)
            }
            Event::Sleep { until_ms } => status(out, 2, Some(until_ms)),
            Event::Finished => {
                self.clear();
                status(out, 0, None)
            }
        }
    }
    /// Replace the sole outstanding alarm; id zero is represented by one.
    pub fn rearm(
        &mut self,
        delay: Option<u32>,
        mut cancel: impl FnMut(i32) -> i32,
        mut set: impl FnMut(u32) -> i32,
    ) -> Result<(), i32> {
        if self.alarm != 0 {
            let rc = cancel((self.alarm - 1) as i32);
            if rc < 0 {
                return Err(rc);
            }
            self.alarm = 0;
        }
        if let Some(delay) = delay {
            let id = set(delay.max(1));
            if id < 0 {
                return Err(id);
            }
            self.alarm = id as u64 + 1;
        }
        Ok(())
    }
    /// Release ownership of the alarm that has just fired.
    pub fn alarm_fired(&mut self) {
        self.alarm = 0;
    }
    /// Drive one bounded event and maintain its sole queued wake/retry.
    #[allow(clippy::too_many_arguments)] // Mirrors the embedding transport/alarm callbacks.
    pub fn drive(
        &mut self,
        now: u64,
        send: impl FnMut(u32, i32, i32, u64, &[u8]) -> i32,
        out: &mut [u8],
        timeout_ms: u64,
        routes: Routes,
        cancel: impl FnMut(i32) -> i32,
        set: impl FnMut(u32) -> i32,
    ) -> Result<usize, i32> {
        let result = self.poll(now, send, out, timeout_ms, routes);
        let delay = next_wake(result.as_ref().map(|n| &out[..*n]).map_err(|e| *e), now)?;
        self.rearm(delay, cancel, set)?;
        result
    }
    /// Admit a program and schedule its first wake, rolling back if scheduling fails.
    pub fn start_queued(
        &mut self,
        data: &[u8],
        limits: ProgramLimits,
        max_depth: u32,
        cancel: impl FnMut(i32) -> i32,
        set: impl FnMut(u32) -> i32,
    ) -> Result<(), i32> {
        self.start(data, limits, max_depth)?;
        if let Err(rc) = self.rearm(Some(1), cancel, set) {
            self.clear();
            return Err(rc);
        }
        Ok(())
    }
    /// Accept a correlated response and schedule progress after successful resumption.
    pub fn answer_queued(
        &mut self,
        id: u64,
        now: u64,
        data: &[u8],
        max_depth: u32,
        cancel: impl FnMut(i32) -> i32,
        set: impl FnMut(u32) -> i32,
    ) -> Option<i32> {
        let rc = self.answer(id, now, data, max_depth)?;
        if rc == 0 {
            Some(self.rearm(Some(1), cancel, set).err().unwrap_or(0))
        } else {
            Some(rc)
        }
    }
    /// Cancel the outstanding alarm and release the active program.
    pub fn stop(&mut self, cancel: impl FnMut(i32) -> i32) -> Result<(), i32> {
        let result = self.rearm(None, cancel, |_| ERR_ARG);
        self.clear();
        result
    }
}
/// Scheduling policy is independent of the embedding transport and alarms.
pub fn next_wake(status: Result<&[u8], i32>, now: u64) -> Result<Option<u32>, i32> {
    let data = match status {
        Ok(data) => data,
        Err(_) => return Ok(Some(100)),
    };
    let f = fields::<3>(data).map_err(Code::to_i32)?;
    let mut r = Reader::new(f[1].ok_or(ERR_ARG)?);
    match r.next() {
        Some(Item::Uint(0)) => Ok(None),
        Some(Item::Uint(1)) => Ok(Some(1)),
        Some(Item::Uint(2)) => {
            let mut r = Reader::new(f[2].ok_or(ERR_ARG)?);
            let Some(Item::Uint(until)) = r.next() else {
                return Err(ERR_ARG);
            };
            Ok(if until == u64::MAX {
                None
            } else {
                Some(until.saturating_sub(now).clamp(1, u32::MAX as u64) as u32)
            })
        }
        _ => Err(ERR_ARG),
    }
}
fn status(out: &mut [u8], state: u64, until: Option<u64>) -> Result<usize, i32> {
    let mut w = Writer::new(out);
    w.map(if until.is_some() { 2 } else { 1 })
        .uint(1)
        .uint(state);
    if let Some(until) = until {
        w.uint(2).uint(until);
    }
    Ok(w.finish().ok_or(ERR_SIZE)?.len())
}
fn response(p: Pending, data: &[u8]) -> Result<Result<&[u8], i32>, i32> {
    let f = fields::<8>(data).map_err(|_| ERR_ARG)?;
    if f[4].is_some() || f[5].is_some() {
        return Err(ERR_ARG);
    }
    let integer = |v: Option<&[u8]>| -> Option<i64> {
        let mut r = Reader::new(v?);
        let n = r.next()?.as_int()?;
        if r.rest().is_empty() { Some(n) } else { None }
    };
    if integer(f[1]) != Some(i64::from(p.component)) || integer(f[2]) != Some(i64::from(p.method)) {
        return Err(ERR_ARG);
    }
    let mut r = Reader::new(f[3].ok_or(ERR_ARG)?);
    if r.next() != Some(Item::Uint(p.wire)) || !r.rest().is_empty() {
        return Err(ERR_ARG);
    }
    match (f[6], f[7]) {
        (Some(v), None) => Ok(Ok(v)),
        (None, Some(v)) => {
            let n = integer(Some(v))
                .and_then(|n| i32::try_from(n).ok())
                .ok_or(ERR_ARG)?;
            Ok(Err(n))
        }
        _ => Err(ERR_ARG),
    }
}

/// Transport destinations supplied by the embedding runtime.
#[derive(Clone, Copy)]
pub struct Routes {
    /// Transport address accepting component-call envelopes.
    pub envelope_addr: u32,
    /// Transport address receiving list completion events.
    pub event_addr: u32,
    /// Component receiving list completion events.
    pub event_component: i32,
    /// Method receiving list completion events.
    pub event_method: i32,
}

pub use mesh_api::call::{Pending as LegacyPending, envelope, reserve, take};

/// CEL adapter for the transport-independent correlation state.
pub struct LegacyCalls<const N: usize>(mesh_api::call::PendingCalls<N>);
impl<const N: usize> Default for LegacyCalls<N> {
    fn default() -> Self {
        Self(mesh_api::call::PendingCalls::default())
    }
}
impl<const N: usize> LegacyCalls<N> {
    /// Reserve a legacy correlation token and send its envelope; roll back on send failure.
    pub fn invoke(
        &mut self,
        now: u64,
        expiry_ms: u64,
        component: i32,
        method: i32,
        params: &[u8],
        send: impl FnMut(u64, &[u8]) -> i32,
    ) -> Result<(), i32> {
        self.0
            .invoke(now, expiry_ms, component, method, params, send)
    }
    /// Validate and forward a correlated legacy reply; consume only after successful delivery.
    pub fn forward(
        &mut self,
        id: u64,
        now: u64,
        input: &[u8],
        out: &mut [u8],
        max_depth: u32,
        send: impl FnOnce(&[u8]) -> i32,
    ) -> i32 {
        self.0.forward(
            id,
            now,
            input,
            out,
            |value| crate::validate_data(value, max_depth).map_err(|_| ERR_ARG),
            send,
        )
    }
}
fn item<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], Code> {
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
                return Err(Code::Malformed);
            }
            *r = Reader::new(&rest[float_len..]);
            continue;
        }
        let children = match r.next().ok_or(Code::Malformed)? {
            Item::Array(n) => n,
            Item::Map(n) => n.checked_mul(2).ok_or(Code::Malformed)?,
            _ => 0,
        };
        left = left.checked_add(children).ok_or(Code::Malformed)?;
        if left > r.rest().len() {
            return Err(Code::Malformed);
        }
    }
    Ok(&start[..start.len() - r.rest().len()])
}
/// Parse unique unsigned envelope fields, rejecting zero, unknown, and duplicate tags.
pub fn fields<const N: usize>(data: &[u8]) -> Result<[Option<&[u8]>; N], Code> {
    let mut r = Reader::new(data);
    let Some(Item::Map(n)) = r.next() else {
        return Err(Code::Malformed);
    };
    let mut result = [None; N];
    for _ in 0..n {
        let Some(Item::Uint(k)) = r.next() else {
            return Err(Code::Malformed);
        };
        let k = usize::try_from(k).map_err(|_| Code::Malformed)?;
        if k == 0 || k >= N || result[k].is_some() {
            return Err(Code::Malformed);
        }
        result[k] = Some(item(&mut r)?);
    }
    if !r.rest().is_empty() {
        return Err(Code::Malformed);
    }
    Ok(result)
}
/// Validate a live legacy response and encode its forwarding payload without consuming it.
pub fn prepare<'a, const N: usize>(
    pending: &[Option<LegacyPending>; N],
    id: u64,
    now: u64,
    input: &[u8],
    out: &'a mut [u8],
    max_depth: u32,
) -> Result<&'a [u8], i32> {
    mesh_api::call::prepare(pending, id, now, input, out, |value| {
        crate::validate_data(value, max_depth).map_err(|_| ERR_ARG)
    })
}

/// Validate and evaluate one expression using the owned runner.
/// Policy mode rejects calls and requires a boolean result.
pub fn evaluate_one(
    ast: &[u8],
    vars: &[u8],
    lim: Limits,
    policy: bool,
    mut bounds: ProgramLimits,
    max_depth: u32,
    mut invoke: impl FnMut(i32, i32, &[u8]) -> Result<(), i32>,
) -> Result<Vec<u8>, Code> {
    crate::validate_data(vars, max_depth)?;
    crate::check(ast, &lim)?;
    bounds.max_frames = lim.max_depth as usize;
    bounds.max_nodes = lim.max_nodes;
    let program = Program {
        lists: vec![RuleList {
            name: "eval".into(),
            context: vars.to_vec(),
            rules: vec![Rule::Eval { expr: ast.to_vec() }],
        }],
    };
    let mut runner = Runner::new(program, bounds)?;
    loop {
        match runner.poll(0) {
            Event::Call {
                token,
                component,
                method,
                params,
                ..
            } => {
                if policy {
                    return Err(Code::Unsupported);
                }
                let result = invoke(component, method, &params);
                runner.resume(token, component, method, result.map(|()| &b"\xf6"[..]))?;
            }
            Event::Complete { result, .. } => {
                crate::validate_data(&result, max_depth)?;
                if policy && result.as_slice() != [0xf4] && result.as_slice() != [0xf5] {
                    return Err(Code::Type);
                }
                return Ok(result);
            }
            Event::Failed { error, .. } => return Err(error),
            Event::Sleep { .. } | Event::Finished => return Err(Code::Malformed),
        }
    }
}
