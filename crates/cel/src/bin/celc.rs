//! Compile CEL expressions and TOML programs, with optional local simulation.
use micro_cel::host::translate::{Schema, translate};
use std::{
    env, fs,
    io::{self, Write},
    process,
};

fn output(bytes: &[u8], file: Option<String>, base64: bool) -> Result<(), String> {
    if let Some(f) = file {
        return fs::write(f, bytes).map_err(|e| e.to_string());
    }
    let encoded = if base64 {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for chunk in bytes.chunks(3) {
            let n = ((chunk[0] as u32) << 16)
                | ((chunk.get(1).copied().unwrap_or(0) as u32) << 8)
                | chunk.get(2).copied().unwrap_or(0) as u32;
            s.push(alphabet[((n >> 18) & 63) as usize] as char);
            s.push(alphabet[((n >> 12) & 63) as usize] as char);
            s.push(if chunk.len() > 1 {
                alphabet[((n >> 6) & 63) as usize] as char
            } else {
                '='
            });
            s.push(if chunk.len() > 2 {
                alphabet[(n & 63) as usize] as char
            } else {
                '='
            });
        }
        s
    } else {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    };
    writeln!(io::stdout(), "{encoded}").map_err(|e| e.to_string())
}

#[cfg(feature = "program-host")]
fn program_mode(
    file: &str,
    run: bool,
    responses: Option<String>,
    out: Option<String>,
    base64: bool,
) -> Result<(), String> {
    use micro_cel::{
        host::program::{Format, LocalEvent, LocalReply, compile, encode_response, run_local},
        program::{ProgramLimits, wire},
    };
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Response {
        component: i32,
        method: i32,
        #[serde(default)]
        delay_ms: u64,
        result: Option<toml::Value>,
        error: Option<i32>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Responses {
        responses: Vec<Response>,
    }
    let format = if file.ends_with(".toml") {
        Format::Toml
    } else {
        return Err("program extension must be .toml (other formats are unsupported)".into());
    };
    let limits = ProgramLimits::default();
    let source = fs::read_to_string(file).map_err(|e| e.to_string())?;
    let program = compile(&source, format, &limits)?;
    if !run {
        if responses.is_some() {
            return Err("--responses requires --run".into());
        }
        return output(
            &wire::encode(&program, &limits).map_err(|e| format!("wire: {e:?}"))?,
            out,
            base64,
        );
    }
    if out.is_some() || base64 {
        return Err("--run cannot be combined with -o or --base64".into());
    }
    let mut replies = Vec::new();
    if let Some(path) = responses {
        if !path.ends_with(".toml") {
            return Err("responses extension must be .toml (other formats are unsupported)".into());
        }
        let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
        if text.len() > limits.max_input_bytes {
            return Err("responses exceed max_input_bytes".into());
        }
        let entries: Responses =
            toml::from_str(&text).map_err(|e| format!("responses TOML: {e}"))?;
        for entry in entries.responses {
            let result = match (entry.result, entry.error) {
                (Some(v), None) => Ok(encode_response(&v, Format::Toml, &limits)?),
                (None, Some(e)) => Err(e),
                _ => return Err("response must contain exactly one result or error".into()),
            };
            if replies.iter().any(|(c, m, _): &(i32, i32, LocalReply)| {
                *c == entry.component && *m == entry.method
            }) {
                return Err("duplicate response component/method".into());
            }
            replies.push((
                entry.component,
                entry.method,
                LocalReply {
                    delay_ms: entry.delay_ms,
                    result,
                },
            ));
        }
    }
    let result = run_local(program, limits, |_, component, method, _| {
        replies
            .iter()
            .find(|(c, m, _)| *c == component && *m == method)
            .map(|(_, _, r)| r.clone())
            .ok_or_else(|| format!("no mock response for component {component}, method {method}"))
    })?;
    let mut failed = false;
    for event in result.events {
        match event {
            LocalEvent::Call {
                at_ms,
                list,
                component,
                method,
                params,
            } => println!(
                "{at_ms}ms list={list} call={component}:{method} params={}",
                hex(&params)
            ),
            LocalEvent::Complete {
                at_ms,
                list,
                result,
            } => println!("{at_ms}ms list={list} complete={}", hex(&result)),
            LocalEvent::Failed { at_ms, list, error } => {
                println!("{at_ms}ms list={list} failed={error:?}");
                failed = true;
            }
        }
    }
    if failed {
        Err("one or more lists failed".into())
    } else {
        Ok(())
    }
}
#[cfg(feature = "program-host")]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let (mut schema, mut out, mut file, mut expr, mut base64) = (None, None, None, None, false);
    let (mut program, mut execute, mut responses) = (None, false, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-s" => schema = Some(args.next().ok_or("-s requires a file")?),
            "-o" => out = Some(args.next().ok_or("-o requires a file")?),
            "-f" => file = Some(args.next().ok_or("-f requires a file")?),
            "--base64" => base64 = true,
            "--program" => program = Some(args.next().ok_or("--program requires a file")?),
            "--run" => execute = true,
            "--responses" => responses = Some(args.next().ok_or("--responses requires a file")?),
            _ if arg.starts_with('-') => return Err(format!("unknown option {arg}")),
            _ if expr.is_none() => expr = Some(arg),
            _ => return Err("too many expressions".into()),
        }
    }
    if let Some(path) = program {
        if schema.is_some() || file.is_some() || expr.is_some() {
            return Err("--program cannot be combined with -s, -f or an expression".into());
        }
        #[cfg(feature = "program-host")]
        {
            return program_mode(&path, execute, responses, out, base64);
        }
        #[cfg(not(feature = "program-host"))]
        {
            let _ = (path, execute, responses, out, base64);
            return Err("--program requires the program-host feature".into());
        }
    }
    if execute || responses.is_some() {
        return Err("--run and --responses require --program".into());
    }
    if file.is_some() && expr.is_some() {
        return Err("use either -f or an expression".into());
    }
    let source = if let Some(f) = file {
        fs::read_to_string(f).map_err(|e| e.to_string())?
    } else {
        expr.ok_or(concat!(
            "usage: celc [-s schema.txt] [-o out.bin] [--base64] ",
            "[-f file.cel | expression] | --program file.toml ",
            "[--run [--responses mocks.toml]]"
        ))?
    };
    let schema = if let Some(f) = schema {
        Schema::parse(&fs::read_to_string(f).map_err(|e| e.to_string())?)?
    } else {
        Schema::default()
    };
    output(&translate(&source, &schema)?, out, base64)
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        process::exit(1);
    }
}
