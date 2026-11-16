#![cfg(feature = "program-host")]
use micro_cel::{
    host::program::{Format, compile},
    program::ProgramLimits,
};

#[test]
fn toml_roundtrip() {
    let limits = ProgramLimits::default();
    let program = compile(
        include_str!("../examples/programs/basic.toml"),
        Format::Toml,
        &limits,
    )
    .unwrap();
    let artifact = micro_cel::host::program::encode(&program, &limits).unwrap();
    assert_eq!(
        micro_cel::program::wire::decode(&artifact, &limits).unwrap(),
        program
    );
}

#[test]
fn rejects_invalid_documents() {
    let limits = ProgramLimits::default();
    for text in [
        "version = 2\nschema = {}\nlists = []",
        "version = 1\nschema = {a = 1, a = 2}\nlists = []",
        "version = 1\nschema = {a = 1, b = 1}\nlists = []",
        "version = 1\nschema = {}\nlists = [{name = 'x', rules = []}, {name = 'x', rules = []}]",
        "version = 1\nschema = {}\nlists = [{name = 'x', rules = [{after_ms = -1}]}]",
        "version = 1\nschema = {}\nlists = [{name = 'x', context = {missing = 1}, rules = []}]",
        "version = 1\nschema = {x = 1}\nlists = [{name = 'x', context = {x = 2147483648}, rules = []}]",
        "version = 1\nschema = {}\nlists = []\nextra = true",
    ] {
        assert!(
            compile(text, Format::Toml, &limits).is_err(),
            "accepted {text}"
        );
    }
    let mut small = limits;
    small.max_input_bytes = 4;
    assert!(
        compile("invalid document", Format::Toml, &small)
            .unwrap_err()
            .contains("max_input_bytes")
    );
}

#[test]
fn wire_roundtrip_and_interleaved_virtual_execution() {
    use micro_cel::{
        host::program::{LocalEvent, LocalReply, run_local},
        program::wire,
    };
    let limits = ProgramLimits::default();
    let program = compile(
        include_str!("../examples/programs/interleaved.toml"),
        Format::Toml,
        &limits,
    )
    .unwrap();
    let artifact = wire::encode(&program, &limits).unwrap();
    assert_eq!(wire::decode(&artifact, &limits).unwrap(), program);
    let result = run_local(program, limits, |list, component, method, params| {
        assert_eq!((list, component, method), (0, 12, 3));
        assert_eq!(params, &[0xa1, 1, 0x65, b'h', b'e', b'l', b'l', b'o']);
        Ok(LocalReply {
            delay_ms: 10,
            result: Ok(vec![7]),
        })
    })
    .unwrap();
    assert!(
        matches!(result.events.as_slice(), [LocalEvent::Call {at_ms: 0, list: 0, ..}, LocalEvent::Complete {at_ms: 3, list: 1, ..}, LocalEvent::Complete {at_ms: 15, list: 0, result}] if result == &[0xf5])
    );
    assert_eq!(
        result.contexts[0],
        [0xa2, 1, 0xa1, 1, 0x65, b'h', b'e', b'l', b'l', b'o', 2, 7]
    );
    assert_eq!(result.contexts[1], [0xa1, 3, 3]);
}

#[test]
fn local_timeout_and_missing_callback() {
    use micro_cel::{
        Code,
        host::program::{LocalEvent, LocalReply, run_local},
    };
    let limits = ProgramLimits {
        timeout_ms: 4,
        ..ProgramLimits::default()
    };
    let program = compile(
        include_str!("../examples/programs/interleaved.toml"),
        Format::Toml,
        &limits,
    )
    .unwrap();
    assert!(
        run_local(program.clone(), limits, |_, _, _, _| Err(
            "missing callback".into()
        ))
        .unwrap_err()
        .contains("missing callback")
    );
    let result = run_local(program, limits, |_, _, _, _| {
        Ok(LocalReply {
            delay_ms: 4,
            result: Ok(vec![7]),
        })
    })
    .unwrap();
    assert!(result.events.iter().any(|e| matches!(
        e,
        LocalEvent::Failed {
            at_ms: 4,
            list: 0,
            error: Code::Invoke(-110)
        }
    )));
}

#[test]
fn cli_artifact_and_virtual_run() {
    use std::process::Command;
    let cli = env!("CARGO_BIN_EXE_celc");
    let root = env!("CARGO_MANIFEST_DIR");
    let output = Command::new(cli)
        .current_dir(root)
        .args(["--program", "examples/programs/basic.toml"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.stdout.is_empty());
    let output = Command::new(cli)
        .current_dir(root)
        .args([
            "--program",
            "examples/programs/interleaved.toml",
            "--run",
            "--responses",
            "examples/programs/responses.toml",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let trace = String::from_utf8(output.stdout).unwrap();
    assert!(trace.contains("3ms list=1 complete=03"));
    assert!(trace.contains("15ms list=0 complete=f5"));
    let output = Command::new(cli)
        .current_dir(root)
        .args(["--program", "examples/programs/interleaved.toml", "--run"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no mock response"));
}
