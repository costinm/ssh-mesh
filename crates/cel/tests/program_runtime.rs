#![cfg(all(feature = "program", feature = "translate"))]

use mesh_api::cbor::Writer;
use micro_cel::{
    Code,
    host::translate::{Schema, translate},
    program::{Event, Program, ProgramLimits, Rule, RuleList, Runner},
};

fn expr(s: &str) -> Vec<u8> {
    translate(s, &Schema::parse("x=1\ny=2").unwrap()).unwrap()
}
fn eval(s: &str) -> Rule {
    Rule::Eval { expr: expr(s) }
}
fn context(entries: &[(u64, i64)]) -> Vec<u8> {
    let mut buf = [0; 256];
    let mut w = Writer::new(&mut buf);
    w.map(entries.len());
    for &(k, v) in entries {
        w.uint(k).int(v);
    }
    w.finish().unwrap().to_vec()
}
fn list(name: &str, entries: &[(u64, i64)], rules: Vec<Rule>) -> RuleList {
    RuleList {
        name: name.into(),
        context: context(entries),
        rules,
    }
}
fn runner(lists: Vec<RuleList>) -> Runner {
    Runner::new(Program { lists }, ProgramLimits::default()).unwrap()
}
fn call(event: Event, list: usize, component: i32, method: i32, params: &[u8]) -> u64 {
    match event {
        Event::Call {
            token,
            list: l,
            component: c,
            method: m,
            params: p,
        } => {
            assert_eq!((l, c, m, p.as_slice()), (list, component, method, params));
            token
        }
        other => panic!("expected call, got {other:?}"),
    }
}

#[test]
fn interleaved_nested_calls_do_not_replay() {
    let mut r = runner(vec![
        list(
            "a",
            &[],
            vec![eval("call(1, 2, {}) + call(3, 4, {\"v\": call(5, 6, {})})")],
        ),
        list("b", &[], vec![eval("call(7, 8, {})")]),
    ]);
    let a = call(r.poll(0), 0, 1, 2, &[0xa0]);
    let b = call(r.poll(0), 1, 7, 8, &[0xa0]);
    r.resume(a, 1, 2, Ok(&[2])).unwrap();
    let nested = call(r.poll(0), 0, 5, 6, &[0xa0]);
    r.resume(b, 7, 8, Ok(&[9])).unwrap();
    assert_eq!(
        r.poll(0),
        Event::Complete {
            list: 1,
            result: vec![9]
        }
    );
    r.resume(nested, 5, 6, Ok(&[3])).unwrap();
    let outer = call(r.poll(0), 0, 3, 4, &[0xa1, 0x61, b'v', 3]);
    r.resume(outer, 3, 4, Ok(&[4])).unwrap();
    assert_eq!(
        r.poll(0),
        Event::Complete {
            list: 0,
            result: vec![6]
        }
    );
    assert_eq!(r.poll(0), Event::Finished);
}

#[test]
fn isolated_set_break_and_delay() {
    let mut r = runner(vec![
        list(
            "a",
            &[(1, 1)],
            vec![
                Rule::Set {
                    tag: 1,
                    expr: expr("x + 1"),
                },
                Rule::BreakIf { expr: expr("true") },
                eval("99"),
            ],
        ),
        list(
            "b",
            &[(1, 7)],
            vec![Rule::After { delay_ms: 10 }, eval("x")],
        ),
    ]);
    assert_eq!(
        r.poll(100),
        Event::Complete {
            list: 0,
            result: vec![0xf5]
        }
    );
    assert_eq!(r.context(0).unwrap().get(1), Some(&[2][..]));
    assert_eq!(r.context(1).unwrap().get(1), Some(&[7][..]));
    assert_eq!(r.poll(100), Event::Sleep { until_ms: 110 });
    assert_eq!(r.poll(109), Event::Sleep { until_ms: 110 });
    assert_eq!(
        r.poll(110),
        Event::Complete {
            list: 1,
            result: vec![7]
        }
    );
    assert_eq!(r.poll(110), Event::Finished);
}

#[test]
fn invalid_responses_leave_call_pending() {
    let limits = ProgramLimits {
        max_value_bytes: 8,
        ..ProgramLimits::default()
    };
    let mut r = Runner::new(
        Program {
            lists: vec![list("a", &[], vec![eval("call(1, 2, {})")])],
        },
        limits,
    )
    .unwrap();
    let token = call(r.poll(0), 0, 1, 2, &[0xa0]);
    assert_eq!(r.resume(token + 1, 1, 2, Ok(&[1])), Err(Code::NotFound));
    assert_eq!(r.resume(token, 9, 2, Ok(&[1])), Err(Code::Malformed));
    assert_eq!(r.resume(token, 1, 3, Ok(&[1])), Err(Code::Malformed));
    assert!(r.resume(token, 1, 2, Ok(&[0x81])).is_err());
    assert!(r.resume(token, 1, 2, Ok(&[1, 2])).is_err());
    assert_eq!(r.resume(token, 1, 2, Ok(&[0; 9])), Err(Code::Size));
    assert_eq!(r.poll(1), Event::Sleep { until_ms: 10000 });
    r.resume(token, 1, 2, Ok(&[7])).unwrap();
    assert_eq!(r.resume(token, 1, 2, Ok(&[8])), Err(Code::NotFound));
    assert_eq!(
        r.poll(1),
        Event::Complete {
            list: 0,
            result: vec![7]
        }
    );
}

#[test]
fn host_error_and_timeout_are_isolated() {
    let mut r = runner(vec![
        list("a", &[], vec![eval("call(1, 2, {})")]),
        list("b", &[], vec![eval("call(3, 4, {})")]),
    ]);
    let a = call(r.poll(10), 0, 1, 2, &[0xa0]);
    let b = call(r.poll(10), 1, 3, 4, &[0xa0]);
    r.resume(a, 1, 2, Err(-42)).unwrap();
    assert_eq!(
        r.poll(10),
        Event::Failed {
            list: 0,
            error: Code::Invoke(-42)
        }
    );
    assert_eq!(r.poll(10009), Event::Sleep { until_ms: 10010 });
    assert_eq!(
        r.poll(10010),
        Event::Failed {
            list: 1,
            error: Code::Invoke(-110)
        }
    );
    assert_eq!(r.resume(b, 3, 4, Ok(&[1])), Err(Code::NotFound));
}

#[test]
fn shared_fuel_survives_resume_and_is_shared_between_lists() {
    let limits = ProgramLimits {
        max_nodes: 5,
        ..ProgramLimits::default()
    };
    let mut r = Runner::new(
        Program {
            lists: vec![
                list("a", &[], vec![eval("call(1, 2, {})")]),
                list("b", &[], vec![eval("1")]),
            ],
        },
        limits,
    )
    .unwrap();
    let token = call(r.poll(0), 0, 1, 2, &[0xa0]);
    let remaining = r.fuel_remaining();
    assert!(remaining < 5);
    assert_eq!(
        r.poll(0),
        Event::Complete {
            list: 1,
            result: vec![1]
        }
    );
    assert_eq!(r.fuel_remaining() + 1, remaining);
    r.resume(token, 1, 2, Ok(&[2])).unwrap();
    assert_eq!(
        r.poll(0),
        Event::Complete {
            list: 0,
            result: vec![2]
        }
    );
    assert_eq!(r.fuel_remaining(), remaining - 1);
}

#[test]
fn short_circuit_and_has() {
    for (source, expected) in [
        ("true || call(1, 2, {})", 0xf5),
        ("false && call(1, 2, {})", 0xf4),
        ("has({}.missing)", 0xf4),
        ("has({\"v\": 7}.v)", 0xf5),
        ("x.missing || true", 0xf5),
        ("x.missing && false", 0xf4),
    ] {
        let mut r = Runner::new(
            Program {
                lists: vec![list("a", &[(2, 7)], vec![eval(source)])],
            },
            ProgramLimits::default(),
        )
        .unwrap_or_else(|e| panic!("admission failed for {source}: {e:?}"));
        assert_eq!(
            r.poll(0),
            Event::Complete {
                list: 0,
                result: vec![expected]
            },
            "{source}"
        );
    }
}

#[test]
fn presence_propagates_receiver_and_index_errors() {
    for source in ["has(x.missing)", "has({}[x])"] {
        let mut r = runner(vec![list("a", &[], vec![eval(source)])]);
        assert_eq!(
            r.poll(0),
            Event::Failed {
                list: 0,
                error: Code::NotFound
            }
        );
    }
}

#[test]
fn deadline_response_cannot_revive_a_waiting_sequence() {
    let mut r = runner(vec![list("a", &[], vec![eval("call(1, 2, {})")])]);
    let token = call(r.poll(10), 0, 1, 2, &[0xa0]);
    assert_eq!(
        r.resume_at(10010, token, 1, 2, Ok(&[1])),
        Err(Code::NotFound)
    );
    assert_eq!(
        r.poll(10010),
        Event::Failed {
            list: 0,
            error: Code::Invoke(-110)
        }
    );
}

#[test]
fn failed_operand_does_not_execute_later_calls() {
    for source in [
        "[x.missing, call(1, 2, {})]",
        "{\"a\": x.missing, \"b\": call(1, 2, {})}",
        "x.missing + call(1, 2, {})",
    ] {
        let mut r = runner(vec![list("a", &[], vec![eval(source)])]);
        assert_eq!(
            r.poll(0),
            Event::Failed {
                list: 0,
                error: Code::NotFound
            },
            "{source}"
        );
        assert_eq!(r.poll(0), Event::Finished);
    }
}

#[test]
fn resource_exhaustion_is_terminal_even_under_logical_absorbers() {
    let limits = ProgramLimits {
        max_value_bytes: 2,
        ..ProgramLimits::default()
    };
    let mut r = Runner::new(
        Program {
            lists: vec![list("a", &[], vec![eval("(\"long\" == \"long\") || true")])],
        },
        limits,
    )
    .unwrap();
    assert_eq!(
        r.poll(0),
        Event::Failed {
            list: 0,
            error: Code::Size
        }
    );
}

#[test]
fn map_values_can_suspend() {
    let mut r = runner(vec![list(
        "a",
        &[],
        vec![eval("{\"a\": 1, \"b\": call(2, 3, {})}")],
    )]);
    let token = call(r.poll(0), 0, 2, 3, &[0xa0]);
    r.resume(token, 2, 3, Ok(&[7])).unwrap();
    assert_eq!(
        r.poll(0),
        Event::Complete {
            list: 0,
            result: vec![0xa2, 0x61, b'a', 1, 0x61, b'b', 7]
        }
    );
}

#[test]
fn admission_limits_and_pending_cap() {
    let program = Program {
        lists: vec![
            list("a", &[], vec![eval("call(1, 2, {})")]),
            list("b", &[], vec![eval("call(3, 4, {})")]),
        ],
    };
    let mut limits = ProgramLimits {
        max_lists: 1,
        ..ProgramLimits::default()
    };
    assert!(matches!(
        Runner::new(program.clone(), limits),
        Err(Code::Size)
    ));
    limits.max_lists = 2;
    limits.max_rules = 1;
    assert!(matches!(
        Runner::new(program.clone(), limits),
        Err(Code::Size)
    ));
    limits.max_rules = 2;
    limits.max_input_bytes = 1;
    assert!(matches!(
        Runner::new(program.clone(), limits),
        Err(Code::Size)
    ));
    limits.max_input_bytes = 65536;
    limits.max_pending = 1;
    let mut r = Runner::new(program, limits).unwrap();
    let a = call(r.poll(0), 0, 1, 2, &[0xa0]);
    assert_eq!(r.poll(0), Event::Sleep { until_ms: 10000 });
    r.resume(a, 1, 2, Ok(&[1])).unwrap();
    let b = call(r.poll(0), 1, 3, 4, &[0xa0]);
    r.resume(b, 3, 4, Ok(&[2])).unwrap();
    assert_eq!(
        r.poll(0),
        Event::Complete {
            list: 0,
            result: vec![1]
        }
    );
    assert_eq!(
        r.poll(0),
        Event::Complete {
            list: 1,
            result: vec![2]
        }
    );
}
