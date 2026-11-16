#![cfg(all(feature = "program", feature = "translate"))]
use micro_cel::{
    host::translate::{Schema, translate},
    program::{Context, Event, Program, ProgramLimits, Rule, RuleList, Runner},
};

fn program(expr: Vec<u8>, copies: usize) -> Program {
    Program {
        lists: (0..copies)
            .map(|i| RuleList {
                name: i.to_string(),
                context: vec![0xa0],
                rules: vec![Rule::Eval { expr: expr.clone() }],
            })
            .collect(),
    }
}

#[test]
fn deep_evaluation_uses_context_not_recursive_native_frames() {
    // Construct CBOR iteratively: neither compiler nor validator is included
    // in this device-path small-stack test.
    let mut expr = vec![0xa1, 1, 0xa1, 1, 1];
    for _ in 0..120 {
        let mut p = vec![0xa1, 4, 0xa2, 1, 13, 2, 0x81];
        p.extend(expr);
        expr = p;
    }
    let p = program(expr, 1);
    std::thread::Builder::new()
        .stack_size(32 * 1024)
        .spawn(move || {
            let limits = ProgramLimits {
                max_frames: 256,
                max_nodes: 1024,
                ..ProgramLimits::default()
            };
            let mut runner = Runner::new(p, limits).unwrap();
            assert_eq!(
                runner.poll(0),
                Event::Complete {
                    list: 0,
                    result: vec![1]
                }
            );
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn repeated_context_updates_remain_bounded() {
    let mut context = Context::new(&[0xa0], 64, 16).unwrap();
    for i in 0..100_000 {
        context.set(1, &[(i % 24) as u8]).unwrap();
        assert!(context.encoded().len() <= 4);
    }
    assert_eq!(context.get(1), Some(&[15][..]));
}

#[test]
fn many_lists_and_many_repeated_runs() {
    let expression = translate(
        "{\"a\": [1, 2, 3], \"b\": 4} == {\"b\": 4, \"a\": [1, 2, 3]}",
        &Schema::parse("").unwrap(),
    )
    .unwrap();
    let p = program(expression, 16);
    for _ in 0..250 {
        let mut runner = Runner::new(p.clone(), ProgramLimits::default()).unwrap();
        for list in 0..16 {
            assert_eq!(
                runner.poll(0),
                Event::Complete {
                    list,
                    result: vec![0xf5]
                }
            );
        }
        assert_eq!(runner.poll(0), Event::Finished);
    }
}

#[test]
fn nested_container_equality_has_bounded_native_stack() {
    let mut value = vec![1];
    for _ in 0..24 {
        let mut p = vec![0x81];
        p.extend(value);
        value = p;
    }
    let mut context = vec![0xa2, 1];
    context.extend(&value);
    context.push(2);
    context.extend(&value);
    let expression = translate("a == b", &Schema::parse("a=1\nb=2").unwrap()).unwrap();
    let p = Program {
        lists: vec![RuleList {
            name: "equal".into(),
            context,
            rules: vec![Rule::Eval { expr: expression }],
        }],
    };
    std::thread::Builder::new()
        .stack_size(32 * 1024)
        .spawn(move || {
            let mut runner = Runner::new(p, ProgramLimits::default()).unwrap();
            assert_eq!(
                runner.poll(0),
                Event::Complete {
                    list: 0,
                    result: vec![0xf5]
                }
            );
        })
        .unwrap()
        .join()
        .unwrap();
}
