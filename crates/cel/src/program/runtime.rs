//! Cooperative, explicitly stacked program execution. Pure operator cost is
//! not yet metered by byte/work count; node fuel bounds expression visits only.
use super::{Context, Program, ProgramLimits, Rule};
use crate::Code;
use alloc::{collections::BTreeSet, vec, vec::Vec};
use mesh_api::cbor::{Item, Writer};

/// Timeout is reported as `Code::Invoke(-110)`.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// A call requiring host dispatch and a correlated response.
    Call {
        /// Opaque token identifying a live call continuation.
        token: u64,
        /// Zero-based rule list index.
        list: usize,
        /// Destination component identifier.
        component: i32,
        /// Destination method identifier.
        method: i32,
        /// Owned CBOR map containing call parameters.
        params: Vec<u8>,
    },
    /// A list finished successfully.
    Complete {
        /// Zero-based rule list index.
        list: usize,
        /// Encoded result value or host invocation error.
        result: Vec<u8>,
    },
    /// A list terminated with an error.
    Failed {
        /// Zero-based rule list index.
        list: usize,
        /// Failure terminating the list.
        error: Code,
    },
    /// `u64::MAX` also indicates that only external call completions can make progress.
    Sleep {
        /// Absolute monotonic deadline; u64::MAX means no scheduled wake.
        until_ms: u64,
    },
    /// Every list has completed or failed.
    Finished,
}
type Value = Result<Vec<u8>, Code>;
enum Build {
    Operator(u64),
    PresenceIndex,
    List,
    Map(Vec<Vec<u8>>),
}
enum Task {
    Eval(Vec<u8>),
    Gather {
        build: Build,
        remaining: Vec<Vec<u8>>,
        values: Vec<Vec<u8>>,
    },
    Select(Vec<u8>),
    PresenceSelect(Vec<u8>),
    Logic(u64, Vec<u8>),
    LogicEnd(u64, Value),
    Cond(Vec<u8>, Vec<u8>),
}
struct Request {
    /// Destination component identifier.
    component: i32,
    /// Destination method identifier.
    method: i32,
    /// Owned CBOR map containing call parameters.
    params: Vec<u8>,
}
struct Waiting {
    /// Opaque token identifying a live call continuation.
    token: u64,
    /// Destination component identifier.
    component: i32,
    /// Destination method identifier.
    method: i32,
    until: u64,
}
struct State {
    context: Context,
    rules: Vec<Rule>,
    pc: usize,
    tasks: Vec<Task>,
    values: Vec<Value>,
    last: Vec<u8>,
    waiting: Option<Waiting>,
    request: Option<Request>,
    wake: Option<u64>,
    done: bool,
}
/// Owned cooperative program execution with bounded resources.
pub struct Runner {
    lists: Vec<State>,
    limits: ProgramLimits,
    fuel: u32,
    cursor: usize,
    next_token: u64,
    now: u64,
}

fn encoded(cap: usize, f: impl FnOnce(&mut Writer<'_>)) -> Result<Vec<u8>, Code> {
    let mut b = vec![0; cap];
    let mut w = Writer::new(&mut b);
    f(&mut w);
    let n = w.finish().ok_or(Code::Size)?.len();
    b.truncate(n);
    Ok(b)
}
fn bool_value(v: &[u8]) -> Result<bool, Code> {
    match crate::one(v)? {
        Item::Bool(b) => Ok(b),
        _ => Err(Code::Type),
    }
}
fn presence(value: Value) -> Value {
    match value {
        Ok(_) => Ok(vec![0xf5]),
        Err(Code::NotFound) => Ok(vec![0xf4]),
        Err(e) => Err(e),
    }
}
fn args(p: &[u8]) -> Result<(u64, Vec<Vec<u8>>), Code> {
    let f = crate::fields(p)?;
    let id = crate::uint(crate::required(&f, 1)?)?;
    let (n, mut r) = crate::array(crate::required(&f, 2)?)?;
    let arity = if id == 24 { 1 } else { crate::arity(id)? };
    if n.checked_add(usize::from(f[3].is_some())) != Some(arity) {
        return Err(Code::Malformed);
    }
    let mut a = Vec::new();
    if let Some(t) = f[3] {
        a.push(t.to_vec());
    }
    for _ in 0..n {
        a.push(crate::take(&mut r)?.to_vec());
    }
    if !r.rest().is_empty() {
        return Err(Code::Malformed);
    }
    if a.len() != arity {
        return Err(Code::Malformed);
    }
    if id == 23 {
        crate::static_int(&a[0])?;
        crate::static_int(&a[1])?;
    }
    Ok((id, a))
}
fn pure(id: u64, values: &[Vec<u8>], lim: &ProgramLimits) -> Value {
    let a = crate::value(&values[0])?;
    let mut storage = vec![0; lim.max_value_bytes];
    let mut arena = crate::arena::Arena::new(&mut storage);
    let b = values.get(1).map(|v| crate::value(v)).transpose()?;
    let result = crate::apply(id, a, b, &mut arena)?;
    encoded(lim.max_value_bytes, |w| crate::write_val(w, result))
}
fn select(field: &[u8], val: &[u8], lim: &ProgramLimits) -> Value {
    let result = crate::select_value(crate::value(val)?, crate::one(field)?)?;
    encoded(lim.max_value_bytes, |w| crate::write_val(w, result))
}
fn gather(tasks: &mut Vec<Task>, build: Build, mut expressions: Vec<Vec<u8>>) -> Result<(), Code> {
    expressions.reverse();
    // An empty collection still needs its builder to run, but has no operand
    // value to collect. The empty case is handled directly by Eval below.
    let first = expressions.pop().ok_or(Code::Malformed)?;
    tasks.push(Task::Gather {
        build,
        remaining: expressions,
        values: Vec::new(),
    });
    tasks.push(Task::Eval(first));
    Ok(())
}
impl Runner {
    /// Create a runner with bounded storage and validated contexts.
    /// ASTs are checked during execution.
    pub fn new(program: Program, limits: ProgramLimits) -> Result<Self, Code> {
        if program.lists.len() > limits.max_lists
            || limits.max_frames == 0
            || limits.max_pending == 0
            || limits.max_value_bytes == 0
            || limits.timeout_ms == 0
        {
            return Err(Code::Size);
        }
        let mut bytes = 0usize;
        let mut rules = 0usize;
        let mut lists = Vec::new();
        let mut names = BTreeSet::new();
        for list in program.lists {
            if list.name.is_empty() || !names.insert(list.name.clone()) {
                return Err(Code::Malformed);
            }
            rules = rules.checked_add(list.rules.len()).ok_or(Code::Size)?;
            bytes = bytes
                .checked_add(list.name.len())
                .and_then(|x| x.checked_add(list.context.len()))
                .ok_or(Code::Size)?;
            for rule in &list.rules {
                if let Rule::Eval { expr } | Rule::Set { expr, .. } | Rule::BreakIf { expr } = rule
                {
                    bytes = bytes.checked_add(expr.len()).ok_or(Code::Size)?;
                    if bytes > limits.max_input_bytes {
                        return Err(Code::Size);
                    }
                }
            }
            if bytes > limits.max_input_bytes || rules > limits.max_rules {
                return Err(Code::Size);
            }
            let context = Context::new(
                &list.context,
                limits.max_context_bytes,
                limits.max_value_bytes,
            )?;
            crate::validate_data(context.encoded(), limits.max_frames.min(32) as u32)?;
            lists.push(State {
                context,
                rules: list.rules,
                pc: 0,
                tasks: Vec::new(),
                values: Vec::new(),
                last: vec![0xf6],
                waiting: None,
                request: None,
                wake: None,
                done: false,
            });
        }
        Ok(Self {
            lists,
            limits,
            fuel: limits.max_nodes,
            cursor: 0,
            next_token: 1,
            now: 0,
        })
    }
    #[cfg(feature = "service")]
    pub(crate) fn limit_deadline(&mut self, token: u64, until: u64) -> Result<u64, Code> {
        let waiting = self
            .lists
            .iter_mut()
            .filter_map(|s| s.waiting.as_mut())
            .find(|w| w.token == token)
            .ok_or(Code::NotFound)?;
        waiting.until = waiting.until.min(until);
        Ok(waiting.until)
    }
    /// Borrow a list context, or None for an invalid list index.
    pub fn context(&self, list: usize) -> Option<&Context> {
        self.lists.get(list).map(|s| &s.context)
    }
    /// Return the remaining expression node budget.
    pub fn fuel_remaining(&self) -> u32 {
        self.fuel
    }
    /// Whether a call still owns a live continuation (used to cancel host
    /// futures after expiry rather than retaining them until they resolve).
    pub fn is_pending(&self, token: u64) -> bool {
        self.lists
            .iter()
            .any(|s| s.waiting.as_ref().is_some_and(|w| w.token == token))
    }
    /// Resume at the last polled time. Event-loop hosts should prefer
    /// `resume_at` so a response arriving at its deadline cannot revive a call.
    pub fn resume(
        &mut self,
        token: u64,
        component: i32,
        method: i32,
        result: Result<&[u8], i32>,
    ) -> Result<(), Code> {
        self.resume_at(self.now, token, component, method, result)
    }
    /// Expire old calls at now_ms, then resume a matching live call.
    /// Invalid responses leave live continuations available for retry.
    pub fn resume_at(
        &mut self,
        now_ms: u64,
        token: u64,
        component: i32,
        method: i32,
        result: Result<&[u8], i32>,
    ) -> Result<(), Code> {
        self.expire(now_ms);
        let s = self
            .lists
            .iter_mut()
            .find(|s| s.waiting.as_ref().is_some_and(|w| w.token == token))
            .ok_or(Code::NotFound)?;
        let w = s.waiting.as_ref().ok_or(Code::NotFound)?;
        if w.component != component || w.method != method {
            return Err(Code::Malformed);
        }
        let value = match result {
            Ok(v) => {
                if v.len() > self.limits.max_value_bytes {
                    return Err(Code::Size);
                }
                crate::validate_data(v, self.limits.max_frames.min(32) as u32)?;
                crate::one(v)?;
                Ok(v.to_vec())
            }
            Err(e) => Err(Code::Invoke(e)),
        };
        s.waiting = None;
        s.values.push(value);
        Ok(())
    }
    fn expire(&mut self, now_ms: u64) {
        self.now = self.now.max(now_ms);
        for s in &mut self.lists {
            if s.waiting.as_ref().is_some_and(|w| self.now >= w.until) {
                s.waiting = None;
                s.values.push(Err(Code::Invoke(-110)));
            }
        }
    }
    /// Advance cooperative execution at a monotonic millisecond timestamp.
    pub fn poll(&mut self, now_ms: u64) -> Event {
        self.expire(now_ms);
        let now_ms = self.now;
        let count = self.lists.len();
        for _ in 0..count {
            let i = self.cursor % count;
            self.cursor = (i + 1) % count;
            if self.lists[i].done || self.lists[i].waiting.is_some() {
                continue;
            }
            if self.lists[i].wake.is_some_and(|t| now_ms < t) {
                continue;
            }
            self.lists[i].wake = None;
            let event = if self.lists[i].request.is_none() {
                self.run(i, now_ms)
            } else {
                None
            };
            if let Some(event) = event {
                return event;
            }
            if self.lists[i].request.is_some()
                && self.lists.iter().filter(|s| s.waiting.is_some()).count()
                    < self.limits.max_pending
            {
                let Some(token) = self.next_token.checked_add(1).map(|n| {
                    let t = self.next_token;
                    self.next_token = n;
                    t
                }) else {
                    self.lists[i].done = true;
                    return Event::Failed {
                        list: i,
                        error: Code::Size,
                    };
                };
                let Some(req) = self.lists[i].request.take() else {
                    self.lists[i].done = true;
                    return Event::Failed {
                        list: i,
                        error: Code::Malformed,
                    };
                };
                self.lists[i].waiting = Some(Waiting {
                    token,
                    component: req.component,
                    method: req.method,
                    until: now_ms.saturating_add(self.limits.timeout_ms),
                });
                return Event::Call {
                    token,
                    list: i,
                    component: req.component,
                    method: req.method,
                    params: req.params,
                };
            }
        }
        if self.lists.iter().all(|s| s.done) {
            return Event::Finished;
        }
        let until = self
            .lists
            .iter()
            .flat_map(|s| {
                s.wake
                    .into_iter()
                    .chain(s.waiting.as_ref().map(|w| w.until))
            })
            .min()
            .unwrap_or(u64::MAX);
        Event::Sleep { until_ms: until }
    }
    fn run(&mut self, i: usize, now: u64) -> Option<Event> {
        let s = &mut self.lists[i];
        loop {
            if let Some(Err(
                error @ (Code::Nodes
                | Code::Depth
                | Code::Size
                | Code::Malformed
                | Code::Unsupported),
            )) = s.values.last()
            {
                let error = *error;
                s.tasks.clear();
                s.values.clear();
                s.request = None;
                s.done = true;
                return Some(Event::Failed { list: i, error });
            }
            if s.tasks.is_empty() && !s.values.is_empty() {
                let Some(v) = s.values.pop() else {
                    s.done = true;
                    return Some(Event::Failed {
                        list: i,
                        error: Code::Malformed,
                    });
                };
                let v = match v {
                    Ok(v) => v,
                    Err(error) => {
                        s.done = true;
                        return Some(Event::Failed { list: i, error });
                    }
                };
                match &s.rules[s.pc] {
                    Rule::Set { tag, .. } => {
                        let mut updated = s.context.clone();
                        if let Err(error) = updated.set(*tag, &v).and_then(|()| {
                            crate::validate_data(
                                updated.encoded(),
                                self.limits.max_frames.min(32) as u32,
                            )
                        }) {
                            s.done = true;
                            return Some(Event::Failed { list: i, error });
                        }
                        s.context = updated;
                    }
                    Rule::BreakIf { .. } => match bool_value(&v) {
                        Ok(true) => {
                            s.done = true;
                            return Some(Event::Complete { list: i, result: v });
                        }
                        Ok(false) => {}
                        Err(error) => {
                            s.done = true;
                            return Some(Event::Failed { list: i, error });
                        }
                    },
                    _ => {}
                }
                s.last = v;
                s.pc += 1;
            }
            if s.tasks.is_empty() {
                if s.pc == s.rules.len() {
                    s.done = true;
                    return Some(Event::Complete {
                        list: i,
                        result: s.last.clone(),
                    });
                }
                match &s.rules[s.pc] {
                    Rule::After { delay_ms } => {
                        s.pc += 1;
                        s.wake = Some(now.saturating_add(*delay_ms));
                        return None;
                    }
                    Rule::Eval { expr } | Rule::Set { expr, .. } | Rule::BreakIf { expr } => {
                        s.tasks.push(Task::Eval(expr.clone()))
                    }
                }
            }
            let Some(task) = s.tasks.pop() else {
                s.done = true;
                return Some(Event::Failed {
                    list: i,
                    error: Code::Malformed,
                });
            };
            let outcome: Result<(), Code> = (|| {
                match task {
                    Task::Eval(ast) => {
                        self.fuel = self.fuel.checked_sub(1).ok_or(Code::Nodes)?;
                        let (kind, p) = crate::node(&ast)?;
                        match kind {
                            1 => {
                                let v = crate::constant(p)?;
                                let out = encoded(self.limits.max_value_bytes, |w| {
                                    crate::write_val(w, v)
                                })?;
                                s.values.push(Ok(out));
                            }
                            2 => {
                                let f = crate::fields(p)?;
                                if f[2].is_some() || f[3].is_some() {
                                    return Err(Code::Malformed);
                                }
                                let tag = crate::uint(crate::required(&f, 1)?)?;
                                s.values.push(
                                    s.context.get(tag).map(|v| v.to_vec()).ok_or(Code::NotFound),
                                );
                            }
                            3 => {
                                let f = crate::fields(p)?;
                                if f[3].is_some() {
                                    return Err(Code::Malformed);
                                }
                                let operand = crate::required(&f, 1)?.to_vec();
                                let field = crate::required(&f, 2)?.to_vec();
                                s.tasks.push(Task::Select(field));
                                s.tasks.push(Task::Eval(operand));
                            }
                            4 => {
                                let (id, a) = args(p)?;
                                match id {
                                    1 | 2 => {
                                        s.tasks.push(Task::Logic(id, a[1].clone()));
                                        s.tasks.push(Task::Eval(a[0].clone()));
                                    }
                                    4 => {
                                        s.tasks.push(Task::Cond(a[1].clone(), a[2].clone()));
                                        s.tasks.push(Task::Eval(a[0].clone()));
                                    }
                                    24 => {
                                        // Test only the final lookup. Failures computing
                                        // its receiver or index are ordinary errors.
                                        self.fuel = self.fuel.checked_sub(1).ok_or(Code::Nodes)?;
                                        let (kind, payload) = crate::node(&a[0])?;
                                        if kind == 3 {
                                            let f = crate::fields(payload)?;
                                            s.tasks.push(Task::PresenceSelect(
                                                crate::required(&f, 2)?.to_vec(),
                                            ));
                                            s.tasks
                                                .push(Task::Eval(crate::required(&f, 1)?.to_vec()));
                                        } else if kind == 4 {
                                            let (op, operands) = args(payload)?;
                                            if op != 18 {
                                                return Err(Code::Malformed);
                                            }
                                            gather(&mut s.tasks, Build::PresenceIndex, operands)?;
                                        } else {
                                            return Err(Code::Malformed);
                                        }
                                    }
                                    _ => gather(&mut s.tasks, Build::Operator(id), a)?,
                                }
                            }
                            5 => {
                                let f = crate::fields(p)?;
                                if f[2].is_some() || f[3].is_some() {
                                    return Err(Code::Malformed);
                                }
                                let (n, mut r) = crate::array(crate::required(&f, 1)?)?;
                                if n > 128 {
                                    return Err(Code::Size);
                                }
                                let mut a = Vec::new();
                                for _ in 0..n {
                                    a.push(crate::take(&mut r)?.to_vec())
                                }
                                if !r.rest().is_empty() {
                                    return Err(Code::Malformed);
                                }
                                if n == 0 {
                                    s.values.push(Ok(vec![0x80]));
                                } else {
                                    gather(&mut s.tasks, Build::List, a)?;
                                }
                            }
                            6 => {
                                let f = crate::fields(p)?;
                                if f[2].is_some() || f[3].is_some() {
                                    return Err(Code::Malformed);
                                }
                                let (n, mut r) = crate::array(crate::required(&f, 1)?)?;
                                if n > 128 {
                                    return Err(Code::Size);
                                }
                                let mut keys = Vec::new();
                                let mut expressions = Vec::new();
                                for _ in 0..n {
                                    let pair = crate::take(&mut r)?;
                                    let (count, mut pair) = crate::array(pair)?;
                                    if count != 2 {
                                        return Err(Code::Malformed);
                                    }
                                    keys.push(crate::take(&mut pair)?.to_vec());
                                    expressions.push(crate::take(&mut pair)?.to_vec());
                                    if !pair.rest().is_empty() {
                                        return Err(Code::Malformed);
                                    }
                                }
                                if !r.rest().is_empty() {
                                    return Err(Code::Malformed);
                                }
                                if n == 0 {
                                    s.values.push(Ok(vec![0xa0]));
                                } else {
                                    gather(&mut s.tasks, Build::Map(keys), expressions)?;
                                }
                            }
                            _ => return Err(Code::Unsupported),
                        }
                    }
                    Task::Select(field) => {
                        let v = s.values.pop().ok_or(Code::Malformed)?;
                        s.values
                            .push(v.and_then(|v| select(&field, &v, &self.limits)));
                    }
                    Task::PresenceSelect(field) => {
                        let v = s.values.pop().ok_or(Code::Malformed)?;
                        s.values.push(match v {
                            Ok(v) => presence(select(&field, &v, &self.limits)),
                            Err(e) => Err(e),
                        });
                    }
                    Task::Cond(a, b) => {
                        let v = s.values.pop().ok_or(Code::Malformed)?;
                        match v.and_then(|v| bool_value(&v)) {
                            Ok(true) => s.tasks.push(Task::Eval(a)),
                            Ok(false) => s.tasks.push(Task::Eval(b)),
                            Err(e) => s.values.push(Err(e)),
                        }
                    }
                    Task::Logic(id, b) => {
                        let a = s.values.pop().ok_or(Code::Malformed)?;
                        let a = a.and_then(|v| {
                            bool_value(&v).map(|b| vec![if b { 0xf5 } else { 0xf4 }])
                        });
                        let absorb = matches!((&a,id),(Ok(v),1) if v==&[0xf5])
                            || matches!((&a,id),(Ok(v),2) if v==&[0xf4]);
                        if absorb {
                            s.values.push(a)
                        } else {
                            s.tasks.push(Task::LogicEnd(id, a));
                            s.tasks.push(Task::Eval(b));
                        }
                    }
                    Task::LogicEnd(id, a) => {
                        let b = s.values.pop().ok_or(Code::Malformed)?.and_then(|v| {
                            bool_value(&v).map(|b| vec![if b { 0xf5 } else { 0xf4 }])
                        });
                        let absorb = matches!((&b,id),(Ok(v),1) if v==&[0xf5])
                            || matches!((&b,id),(Ok(v),2) if v==&[0xf4]);
                        s.values.push(if absorb {
                            b
                        } else {
                            match a {
                                Err(e) => Err(e),
                                Ok(_) => b,
                            }
                        });
                    }
                    Task::Gather {
                        build,
                        mut remaining,
                        mut values,
                    } => match s.values.pop().ok_or(Code::Malformed)? {
                        Err(e) => s.values.push(Err(e)),
                        Ok(value) => {
                            values.push(value);
                            if let Some(next) = remaining.pop() {
                                s.tasks.push(Task::Gather {
                                    build,
                                    remaining,
                                    values,
                                });
                                s.tasks.push(Task::Eval(next));
                            } else {
                                match build {
                                    Build::Operator(23) => {
                                        let (
                                            crate::Val::Int(component),
                                            crate::Val::Int(method),
                                            crate::Val::Map(_),
                                        ) = (
                                            crate::value(&values[0])?,
                                            crate::value(&values[1])?,
                                            crate::value(&values[2])?,
                                        )
                                        else {
                                            return Err(Code::Type);
                                        };
                                        s.request = Some(Request {
                                            component,
                                            method,
                                            params: values.remove(2),
                                        });
                                    }
                                    Build::Operator(id) => {
                                        s.values.push(pure(id, &values, &self.limits))
                                    }
                                    Build::PresenceIndex => {
                                        s.values.push(presence(pure(18, &values, &self.limits)))
                                    }
                                    Build::List => {
                                        let list = encoded(self.limits.max_value_bytes, |w| {
                                            w.array(values.len());
                                            for value in &values {
                                                w.raw(value);
                                            }
                                        })?;
                                        crate::validate_value(&list, 0)?;
                                        s.values.push(Ok(list));
                                    }
                                    Build::Map(keys) => {
                                        let map = encoded(self.limits.max_value_bytes, |w| {
                                            w.map(keys.len());
                                            for (key, value) in keys.iter().zip(&values) {
                                                w.raw(key).raw(value);
                                            }
                                        })?;
                                        crate::validate_value(&map, 0)?;
                                        s.values.push(Ok(map));
                                    }
                                }
                            }
                        }
                    },
                }
                if s.tasks.len() > self.limits.max_frames || s.values.len() > self.limits.max_frames
                {
                    return Err(Code::Depth);
                }
                Ok(())
            })();
            if let Err(e) = outcome {
                // Resource exhaustion is terminal, not an expression error
                // that a parent `has`/logical operator may hide. In particular
                // do not keep growing continuation stacks after their limit.
                if matches!(
                    e,
                    Code::Nodes | Code::Depth | Code::Size | Code::Malformed | Code::Unsupported
                ) {
                    s.tasks.clear();
                    s.values.clear();
                    s.request = None;
                    s.done = true;
                    return Some(Event::Failed { list: i, error: e });
                }
                s.values.push(Err(e));
            }
            if s.request.is_some() {
                return None;
            }
        }
    }
}
