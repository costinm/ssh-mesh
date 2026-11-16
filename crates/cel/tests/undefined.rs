use micro_cel::{Code, Limits, NoInvoke, check, eval, validate_data};

const IDENT: &[u8] = &[0xa1, 2, 0xa1, 1, 1];
const NULL: &[u8] = &[0xa1, 1, 0xa1, 7, 0xf6];
const EQ_NULL: &[u8] = &[
    0xa1, 4, 0xa2, 1, 5, 2, 0x82, 0xa1, 2, 0xa1, 1, 1, 0xa1, 1, 0xa1, 7, 0xf6,
];

fn run(ast: &[u8], vars: &[u8]) -> Result<Vec<u8>, Code> {
    let mut scratch = [0; 4096];
    let mut out = [0; 256];
    eval(
        ast,
        vars,
        &mut scratch,
        &mut out,
        Limits::default(),
        &mut NoInvoke,
    )
    .map(|v| v.to_vec())
}

#[test]
fn value_tokens_not_payload_bytes() {
    for data in [
        &[0xf7][..],
        &[0x81, 0xf7],
        &[0xa1, 0xf7, 0],
        &[0xa2, 0xf6, 0, 0xf7, 1],
    ] {
        assert_eq!(validate_data(data, 32), Err(Code::Malformed));
    }
    for data in [
        &[0xf6][..],
        &[0x41, 0xf7],
        &[0x81, 0x41, 0xf7],
        &[0xa1, 0x41, 0xf7, 0xf6],
    ] {
        assert_eq!(validate_data(data, 32), Ok(()));
    }
    assert_eq!(
        run(IDENT, &[0xa1, 1, 0x81, 0x41, 0xf7]),
        Ok(vec![0x81, 0x41, 0xf7])
    );
}

#[test]
fn variables_and_constants_distinguish_null() {
    assert_eq!(run(EQ_NULL, &[0xa1, 1, 0xf7]), Err(Code::Malformed));
    assert_eq!(run(EQ_NULL, &[0xa1, 1, 0xf6]), Ok(vec![0xf5]));
    assert_eq!(run(IDENT, &[0xa1, 1, 0x81, 0xf7]), Err(Code::Malformed));
    assert_eq!(run(IDENT, &[0xa1, 1, 0xa1, 0xf7, 0]), Err(Code::Malformed));
    assert_eq!(run(NULL, &[0xa0]), Ok(vec![0xf6]));
    assert_eq!(
        check(&[0xa1, 1, 0xa1, 7, 0xf7], &Limits::default()),
        Err(Code::Malformed)
    );
}

#[cfg(feature = "program")]
#[test]
fn context_updates_are_atomic() {
    use micro_cel::program::Context;
    assert!(matches!(
        Context::new(&[0xa1, 1, 0xf7], 64, 32),
        Err(Code::Malformed)
    ));
    let mut context = Context::new(&[0xa1, 1, 0xf6], 64, 32).unwrap();
    let before = context.encoded().to_vec();
    assert_eq!(context.set(1, &[0x81, 0xf7]), Err(Code::Malformed));
    assert_eq!(context.encoded(), before);
}

#[cfg(all(feature = "program", feature = "translate"))]
#[test]
fn malformed_response_keeps_call_pending() {
    use micro_cel::host::translate::{Schema, translate};
    use micro_cel::program::{Event, Program, ProgramLimits, Rule, RuleList, Runner};
    let expr = translate("call(1, 2, {})", &Schema::parse("x=1").unwrap()).unwrap();
    let list = RuleList {
        name: "test".into(),
        context: vec![0xa0],
        rules: vec![Rule::Eval { expr }],
    };
    let mut runner = Runner::new(Program { lists: vec![list] }, ProgramLimits::default()).unwrap();
    let Event::Call { token, .. } = runner.poll(0) else {
        panic!("expected call")
    };
    assert_eq!(
        runner.resume_at(1, token, 1, 2, Ok(&[0xf7])),
        Err(Code::Malformed)
    );
    runner.resume_at(1, token, 1, 2, Ok(&[0xf6])).unwrap();
    assert_eq!(
        runner.poll(1),
        Event::Complete {
            list: 0,
            result: vec![0xf6]
        }
    );
}
