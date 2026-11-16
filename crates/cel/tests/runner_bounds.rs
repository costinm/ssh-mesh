#![cfg(all(feature = "program", feature = "translate"))]

use mesh_api::cbor::Writer;
use micro_cel::{
    Code,
    host::translate::{Schema, translate},
    program::{Event, Program, ProgramLimits, Rule, RuleList, Runner},
};

fn translate_expr(source: &str) -> Vec<u8> {
    translate(source, &Schema::parse("x=1").unwrap()).unwrap()
}

fn runner(ast: Vec<u8>, limits: ProgramLimits) -> Runner {
    Runner::new(
        Program {
            lists: vec![RuleList {
                name: "test".into(),
                context: vec![0xa0],
                rules: vec![Rule::Eval { expr: ast }],
            }],
        },
        limits,
    )
    .unwrap()
}

fn run(source: &str, limits: ProgramLimits) -> Event {
    runner(translate_expr(source), limits).poll(0)
}

// Build over-wide literal ASTs directly: the host translator rejects them first.
fn wide_ast(map: bool) -> Vec<u8> {
    let value = translate_expr("1");
    let mut buffer = vec![0; 8192];
    let mut w = Writer::new(&mut buffer);
    w.map(1)
        .uint(if map { 6 } else { 5 })
        .map(1)
        .uint(1)
        .array(129);
    for i in 0..129 {
        if map {
            w.array(2).uint(i);
        }
        w.raw(&value);
    }
    w.finish().unwrap().to_vec()
}

#[test]
fn width_is_independent_of_frame_budget() {
    let limits = ProgramLimits {
        max_frames: 8,
        ..ProgramLimits::default()
    };
    for n in [8, 16] {
        let list = format!("[{}]", vec!["1"; n].join(","));
        let map = format!(
            "{{{}}}",
            (0..n)
                .map(|i| format!("{i}: 1"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let mut expected_list = vec![0x80 + n as u8];
        expected_list.extend(vec![1; n]);
        let mut expected_map = vec![0xa0 + n as u8];
        for i in 0..n {
            expected_map.extend([i as u8, 1]);
        }
        assert_eq!(
            run(&list, limits),
            Event::Complete {
                list: 0,
                result: expected_list
            },
            "{list}"
        );
        assert_eq!(
            run(&map, limits),
            Event::Complete {
                list: 0,
                result: expected_map
            },
            "{map}"
        );
    }
    for map in [false, true] {
        assert_eq!(
            runner(wide_ast(map), limits).poll(0),
            Event::Failed {
                list: 0,
                error: Code::Size
            }
        );
    }
}

#[test]
fn actual_continuation_depth_remains_bounded() {
    let limits = ProgramLimits {
        max_frames: 8,
        ..ProgramLimits::default()
    };
    assert_eq!(
        run("[[[[[[[[[1]]]]]]]]]", limits),
        Event::Failed {
            list: 0,
            error: Code::Depth
        }
    );
}

#[test]
fn constructed_collections_obey_global_data_depth() {
    let limits = ProgramLimits {
        max_frames: 64,
        ..ProgramLimits::default()
    };
    for source in ["[call(1, 2, {})]", "{\"a\": call(1, 2, {})}"] {
        let mut r = runner(translate_expr(source), limits);
        let token = match r.poll(0) {
            Event::Call { token, .. } => token,
            e => panic!("{e:?}"),
        };
        let mut value = vec![0x81; 32];
        value.push(0);
        r.resume(token, 1, 2, Ok(&value)).unwrap();
        assert_eq!(
            r.poll(0),
            Event::Failed {
                list: 0,
                error: Code::Depth
            },
            "{source}"
        );
    }
}

#[test]
fn structural_errors_are_terminal_but_ordinary_errors_are_absorbed() {
    let limits = ProgramLimits::default();
    for source in ["[1].foo || true", "[1].foo && false"] {
        assert_eq!(
            run(source, limits),
            Event::Failed {
                list: 0,
                error: Code::Malformed
            },
            "{source}"
        );
    }
    for (source, result) in [
        ("x || true", 0xf5),
        ("x && false", 0xf4),
        ("1 || true", 0xf5),
        ("1 && false", 0xf4),
    ] {
        assert_eq!(
            run(source, limits),
            Event::Complete {
                list: 0,
                result: vec![result]
            },
            "{source}"
        );
    }
}

#[test]
fn large_schema_keys_do_not_block_lookup() {
    // Full-width schema keys cannot match CEL operands and must be skipped.
    let mut context = vec![0xa1, 1, 0xa2, 0x1b];
    context.extend(u64::MAX.to_be_bytes());
    context.extend([7, 0x61, b'k', 0xf5]);
    for source in ["x.k", "has(x.k)", "\"k\" in x", "!has(x.missing)"] {
        let ast = translate_expr(source);
        let mut scratch = vec![0; 8192];
        let mut out = [0; 256];
        assert_eq!(
            micro_cel::eval(
                &ast,
                &context,
                &mut scratch,
                &mut out,
                micro_cel::Limits::default(),
                &mut micro_cel::NoInvoke
            ),
            Ok(&[0xf5][..])
        );
        let mut runner = Runner::new(
            Program {
                lists: vec![RuleList {
                    name: "lookup".into(),
                    context: context.clone(),
                    rules: vec![Rule::Eval { expr: ast }],
                }],
            },
            ProgramLimits::default(),
        )
        .unwrap();
        assert_eq!(
            runner.poll(0),
            Event::Complete {
                list: 0,
                result: vec![0xf5]
            }
        );
    }
}
