//! Host-only TOML program document compiler. This is not a wire format.
use crate::{
    Code,
    host::translate::{Schema, translate},
    program::{self, Context, Event, Program, ProgramLimits, Rule, RuleList, Runner},
};
use mesh_api::cbor::Writer;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec,
    vec::Vec,
};
use toml::Value;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    schema: BTreeMap<String, u64>,
    lists: Vec<List>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    name: String,
    #[serde(default)]
    context: BTreeMap<String, Value>,
    rules: Vec<RuleDoc>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum RuleDoc {
    Simple(String),
    Object(RuleObject),
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleObject {
    set: Option<String>,
    expr: Option<String>,
    break_if: Option<String>,
    after_ms: Option<u64>,
}

/// Input syntax; TOML nested map keys that parse as i32 are integer keys.
#[derive(Clone, Copy, Debug)]
pub enum Format {
    /// TOML program and response documents.
    Toml,
}

/// Validate all expressions, including branches that execution may never visit,
/// and enforce the wire, context, list and program size limits.
pub fn validate_program(program: &Program, limits: &ProgramLimits) -> Result<(), Code> {
    // The shared codec checks the complete structural representation and bounds.
    program::wire::encode(program, limits)?;
    let ast_limits = crate::Limits {
        max_depth: limits.max_frames.min(128) as u32,
        max_nodes: limits.max_nodes,
    };
    for list in &program.lists {
        for rule in &list.rules {
            match rule {
                Rule::Eval { expr } | Rule::Set { expr, .. } | Rule::BreakIf { expr } => {
                    crate::check(expr, &ast_limits)?;
                }
                Rule::After { .. } => {}
            }
        }
    }
    Ok(())
}

/// Produce an artifact only after full host-side semantic validation.
pub fn encode(program: &Program, limits: &ProgramLimits) -> Result<Vec<u8>, Code> {
    validate_program(program, limits)?;
    program::wire::encode(program, limits)
}

/// Parse and compile a bounded document into the shared in-memory program model.
/// The byte limit is checked before invoking the document parser.
pub fn compile(source: &str, format: Format, limits: &ProgramLimits) -> Result<Program, String> {
    if source.len() > limits.max_input_bytes {
        return Err("program input exceeds max_input_bytes".into());
    }
    let doc: Document = match format {
        Format::Toml => toml::from_str(source).map_err(|e| format!("TOML: {e}"))?,
    };
    if doc.version != 1 {
        return Err("unsupported program version (expected 1)".into());
    }
    if doc.lists.len() > limits.max_lists {
        return Err("too many lists".into());
    }
    let mut tags = BTreeSet::new();
    for (name, tag) in &doc.schema {
        if name.is_empty()
            || !name
                .bytes()
                .enumerate()
                .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
        {
            return Err(format!("invalid schema name {name:?}"));
        }
        if !tags.insert(*tag) {
            return Err(format!("duplicate schema tag {tag}"));
        }
    }
    let schema = Schema(doc.schema.iter().map(|(n, t)| (n.clone(), *t)).collect());
    let mut names = BTreeSet::new();
    let mut total = 0usize;
    let mut lists = Vec::new();
    for list in doc.lists {
        if list.name.is_empty() || !names.insert(list.name.clone()) {
            return Err(format!("empty or duplicate list name {:?}", list.name));
        }
        total = total
            .checked_add(list.rules.len())
            .ok_or("too many rules")?;
        if total > limits.max_rules {
            return Err("too many rules".into());
        }
        let mut entries = Vec::new();
        for (name, value) in list.context {
            let tag = *doc
                .schema
                .get(&name)
                .ok_or_else(|| format!("unknown context name {name:?}"))?;
            let mut data = vec![0; limits.max_value_bytes];
            let mut writer = Writer::new(&mut data);
            write_value(&mut writer, &value, 0)?;
            let n = writer
                .finish()
                .ok_or("context value exceeds max_value_bytes")?
                .len();
            data.truncate(n);
            entries.push((tag, data));
        }
        entries.sort_by_key(|(tag, _)| *tag);
        let mut context = vec![0; limits.max_context_bytes];
        let mut writer = Writer::new(&mut context);
        writer.map(entries.len());
        for (tag, value) in entries {
            writer.uint(tag).raw(&value);
        }
        let n = writer
            .finish()
            .ok_or("context exceeds max_context_bytes")?
            .len();
        context.truncate(n);
        Context::new(&context, limits.max_context_bytes, limits.max_value_bytes)
            .map_err(|e| format!("invalid context: {e:?}"))?;
        let mut rules = Vec::new();
        for rule in list.rules {
            let object = match rule {
                RuleDoc::Simple(expr) => RuleObject {
                    set: None,
                    expr: Some(expr),
                    break_if: None,
                    after_ms: None,
                },
                RuleDoc::Object(o) => o,
            };
            let compiled = match (object.set, object.expr, object.break_if, object.after_ms) {
                (Some(name), Some(expr), None, None) => Rule::Set {
                    tag: *doc
                        .schema
                        .get(&name)
                        .ok_or_else(|| format!("unknown set name {name:?}"))?,
                    expr: translate(&expr, &schema)?,
                },
                (None, Some(expr), None, None) => Rule::Eval {
                    expr: translate(&expr, &schema)?,
                },
                (None, None, Some(expr), None) => Rule::BreakIf {
                    expr: translate(&expr, &schema)?,
                },
                (None, None, None, Some(delay_ms)) => Rule::After { delay_ms },
                _ => {
                    return Err(
                        "rule must contain expr, set with expr, break_if, or after_ms".into(),
                    );
                }
            };
            rules.push(compiled);
        }
        lists.push(RuleList {
            name: list.name,
            context,
            rules,
        });
    }
    let program = Program { lists };
    validate_program(&program, limits).map_err(|e| format!("program validation: {e:?}"))?;
    Runner::new(program.clone(), *limits)
        .map_err(|e| format!("program runner admission: {e:?}"))?;
    Ok(program)
}

/// A simulated host response. Delays use virtual milliseconds, never wall time.
#[derive(Clone, Debug)]
pub struct LocalReply {
    /// Simulated response latency in milliseconds.
    pub delay_ms: u64,
    /// Encoded result value or host invocation error.
    pub result: Result<Vec<u8>, i32>,
}

/// Observable local execution events, in deterministic order.
#[derive(Debug, PartialEq, Eq)]
pub enum LocalEvent {
    /// A call requiring host dispatch and a correlated response.
    Call {
        /// Virtual monotonic timestamp in milliseconds.
        at_ms: u64,
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
        /// Virtual monotonic timestamp in milliseconds.
        at_ms: u64,
        /// Zero-based rule list index.
        list: usize,
        /// Encoded result value or host invocation error.
        result: Vec<u8>,
    },
    /// A list terminated with an error.
    Failed {
        /// Virtual monotonic timestamp in milliseconds.
        at_ms: u64,
        /// Zero-based rule list index.
        list: usize,
        /// Failure terminating the list.
        error: Code,
    },
}
/// Simulation events and final list contexts.
#[derive(Debug)]
pub struct LocalResult {
    /// Observed events in execution order.
    pub events: Vec<LocalEvent>,
    /// Final encoded contexts in rule list order.
    pub contexts: Vec<Vec<u8>>,
}

/// Drive the shared runner without sleeping. A callback error aborts simulation;
/// a reply error is delivered to the runner as a component error.
pub fn run_local<F>(
    program: Program,
    limits: ProgramLimits,
    mut host: F,
) -> Result<LocalResult, String>
where
    F: FnMut(usize, i32, i32, &[u8]) -> Result<LocalReply, String>,
{
    let count = program.lists.len();
    let mut runner = Runner::new(program, limits).map_err(|e| format!("runner: {e:?}"))?;
    let mut now = 0u64;
    let mut events = Vec::new();
    type PendingResponse = (u64, u64, i32, i32, Result<Vec<u8>, i32>);
    let mut pending: Vec<PendingResponse> = Vec::new();
    loop {
        while let Some(index) = pending.iter().position(|p| p.0 <= now) {
            let (_, token, component, method, result) = pending.remove(index);
            runner
                .resume_at(
                    now,
                    token,
                    component,
                    method,
                    result.as_deref().map_err(|e| *e),
                )
                .map_err(|e| format!("invalid host response: {e:?}"))?;
        }
        match runner.poll(now) {
            Event::Call {
                token,
                list,
                component,
                method,
                params,
            } => {
                let reply = host(list, component, method, &params)?;
                events.push(LocalEvent::Call {
                    at_ms: now,
                    list,
                    component,
                    method,
                    params,
                });
                // At the exact deadline the runner treats the call as timed out.
                if reply.delay_ms < limits.timeout_ms {
                    pending.push((
                        now.saturating_add(reply.delay_ms),
                        token,
                        component,
                        method,
                        reply.result,
                    ));
                }
            }
            Event::Complete { list, result } => events.push(LocalEvent::Complete {
                at_ms: now,
                list,
                result,
            }),
            Event::Failed { list, error } => events.push(LocalEvent::Failed {
                at_ms: now,
                list,
                error,
            }),
            Event::Sleep { until_ms } => {
                let next = pending
                    .iter()
                    .map(|p| p.0)
                    .min()
                    .map_or(until_ms, |t| t.min(until_ms));
                if next == u64::MAX || next < now {
                    return Err("runner cannot make virtual-time progress".into());
                }
                now = next;
            }
            Event::Finished => {
                let contexts = (0..count)
                    .map(|i| {
                        Ok(runner
                            .context(i)
                            .ok_or("runner lost admitted list")?
                            .encoded()
                            .to_vec())
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                return Ok(LocalResult { events, contexts });
            }
        }
    }
}

/// Encode a TOML host response value under the same rules as context values.
pub fn encode_response(
    value: &Value,
    format: Format,
    limits: &ProgramLimits,
) -> Result<Vec<u8>, String> {
    let mut data = vec![0; limits.max_value_bytes];
    let mut writer = Writer::new(&mut data);
    match format {
        Format::Toml => write_value(&mut writer, value, 0)?,
    }
    let len = writer
        .finish()
        .ok_or("response exceeds max_value_bytes")?
        .len();
    data.truncate(len);
    crate::validate_value(&data, 0).map_err(|e| format!("invalid response: {e:?}"))?;
    Ok(data)
}

fn write_value(w: &mut Writer<'_>, value: &Value, depth: usize) -> Result<(), String> {
    if depth > 32 {
        return Err("context nesting exceeds 32".into());
    }
    match value {
        Value::Boolean(b) => {
            w.boolean(*b);
        }
        Value::Integer(n) => {
            let n = i32::try_from(*n).map_err(|_| "context numbers must be i32 integers")?;
            w.int(n.into());
        }
        Value::String(s) => {
            w.text(s);
        }
        Value::Array(a) => {
            w.array(a.len());
            for v in a {
                write_value(w, v, depth + 1)?;
            }
        }
        Value::Table(m) => {
            w.map(m.len());
            for (key, value) in m {
                if let Ok(n) = key.parse::<i32>() {
                    w.int(n.into());
                } else {
                    w.text(key);
                }
                write_value(w, value, depth + 1)?;
            }
        }
        _ => return Err("context values cannot contain floats or datetimes".into()),
    }
    Ok(())
}
