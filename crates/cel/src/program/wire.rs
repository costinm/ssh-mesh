//! Bounded version 1 program wire format. Structural map keys are in ascending order.
use super::{Context, Program, ProgramLimits, Rule, RuleList};
use crate::Code;
use alloc::{string::ToString, vec, vec::Vec};
use mesh_api::cbor::{Item, Reader, Writer};

fn whole<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], Code> {
    let start = r.rest();
    let mut left = 1usize;
    while left != 0 {
        left -= 1;
        let n = match r.next().ok_or(Code::Malformed)? {
            Item::Array(n) => n,
            Item::Map(n) => n.checked_mul(2).ok_or(Code::Malformed)?,
            _ => 0,
        };
        left = left.checked_add(n).ok_or(Code::Malformed)?;
        if left > r.rest().len() {
            return Err(Code::Malformed);
        }
    }
    Ok(&start[..start.len() - r.rest().len()])
}
fn key(r: &mut Reader<'_>, expected: u64) -> Result<(), Code> {
    if r.next() == Some(Item::Uint(expected)) {
        Ok(())
    } else {
        Err(Code::Malformed)
    }
}
fn uint(r: &mut Reader<'_>) -> Result<u64, Code> {
    match r.next() {
        Some(Item::Uint(n)) => Ok(n),
        _ => Err(Code::Malformed),
    }
}
fn map(r: &mut Reader<'_>, n: usize) -> Result<(), Code> {
    if r.next() == Some(Item::Map(n)) {
        Ok(())
    } else {
        Err(Code::Malformed)
    }
}
/// Decode a bounded program's structure, without semantically validating its ASTs.
/// Only accept artifacts from a trusted host that performed semantic validation.
pub fn decode(data: &[u8], limits: &ProgramLimits) -> Result<Program, Code> {
    if data.len() > limits.max_input_bytes {
        return Err(Code::Size);
    }
    let mut r = Reader::new(data);
    map(&mut r, 2)?;
    key(&mut r, 1)?;
    if uint(&mut r)? != 1 {
        return Err(Code::Malformed);
    }
    key(&mut r, 2)?;
    let Some(Item::Array(count)) = r.next() else {
        return Err(Code::Malformed);
    };
    if count > limits.max_lists {
        return Err(Code::Size);
    }
    let mut lists = Vec::new();
    let mut total = 0usize;
    for _ in 0..count {
        map(&mut r, 3)?;
        key(&mut r, 1)?;
        let Some(Item::Text(name)) = r.next() else {
            return Err(Code::Malformed);
        };
        let name = core::str::from_utf8(name).map_err(|_| Code::Malformed)?;
        if name.is_empty() || lists.iter().any(|l: &RuleList| l.name == name) {
            return Err(Code::Malformed);
        }
        key(&mut r, 2)?;
        let context = whole(&mut r)?;
        Context::new(context, limits.max_context_bytes, limits.max_value_bytes)?;
        key(&mut r, 3)?;
        let Some(Item::Array(n)) = r.next() else {
            return Err(Code::Malformed);
        };
        total = total.checked_add(n).ok_or(Code::Size)?;
        if total > limits.max_rules {
            return Err(Code::Size);
        }
        let mut rules = Vec::new();
        for _ in 0..n {
            let Some(Item::Map(fields)) = r.next() else {
                return Err(Code::Malformed);
            };
            key(&mut r, 1)?;
            let kind = uint(&mut r)?;
            if fields != if kind == 2 { 3 } else { 2 } {
                return Err(Code::Malformed);
            }
            key(&mut r, 2)?;
            let rule = if kind == 4 {
                Rule::After {
                    delay_ms: uint(&mut r)?,
                }
            } else {
                let expr = whole(&mut r)?;
                match kind {
                    1 => Rule::Eval {
                        expr: expr.to_vec(),
                    },
                    2 => {
                        key(&mut r, 3)?;
                        Rule::Set {
                            tag: uint(&mut r)?,
                            expr: expr.to_vec(),
                        }
                    }
                    3 => Rule::BreakIf {
                        expr: expr.to_vec(),
                    },
                    _ => return Err(Code::Malformed),
                }
            };
            rules.push(rule);
        }
        lists.push(RuleList {
            name: name.to_string(),
            context: context.to_vec(),
            rules,
        });
    }
    if !r.rest().is_empty() {
        return Err(Code::Malformed);
    }
    Ok(Program { lists })
}
/// Encode into a bounded buffer and validate its structure, not AST semantics.
/// Host producers should use `host::program::encode` instead.
pub fn encode(program: &Program, limits: &ProgramLimits) -> Result<Vec<u8>, Code> {
    if program.lists.len() > limits.max_lists {
        return Err(Code::Size);
    }
    let rules = program.lists.iter().try_fold(0usize, |n, list| {
        n.checked_add(list.rules.len()).ok_or(Code::Size)
    })?;
    if rules > limits.max_rules {
        return Err(Code::Size);
    }
    let mut data = vec![0; limits.max_input_bytes];
    let mut w = Writer::new(&mut data);
    w.map(2).uint(1).uint(1).uint(2).array(program.lists.len());
    for list in &program.lists {
        w.map(3)
            .uint(1)
            .text(&list.name)
            .uint(2)
            .raw(&list.context)
            .uint(3)
            .array(list.rules.len());
        for rule in &list.rules {
            match rule {
                Rule::Eval { expr } => {
                    w.map(2).uint(1).uint(1).uint(2).raw(expr);
                }
                Rule::Set { tag, expr } => {
                    w.map(3)
                        .uint(1)
                        .uint(2)
                        .uint(2)
                        .raw(expr)
                        .uint(3)
                        .uint(*tag);
                }
                Rule::BreakIf { expr } => {
                    w.map(2).uint(1).uint(3).uint(2).raw(expr);
                }
                Rule::After { delay_ms } => {
                    w.map(2).uint(1).uint(4).uint(2).uint(*delay_ms);
                }
            }
        }
    }
    let len = w.finish().ok_or(Code::Size)?.len();
    data.truncate(len);
    decode(&data, limits)?;
    Ok(data)
}
