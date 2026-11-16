#![cfg(feature = "service")]
use mesh_api::cbor::Writer;

#[test]
fn owned_legacy_calls_commit_only_successful_forwarding() {
    let mut calls = micro_cel::service::LegacyCalls::<1>::default();
    let mut token = 0;
    calls
        .invoke(0, 10, 12, 3, &[0xa0], |id, _| {
            token = id;
            0
        })
        .unwrap();
    assert!(token < micro_cel::service::TOKEN_BIT);
    assert_eq!(
        calls.invoke(1, 10, 12, 3, &[0xa0], |_, _| panic!()),
        Err(micro_cel::support::status::ERR_BUSY)
    );
    let mut out = [0; 64];
    let wrong = reply(token, 12, 4, Ok(7));
    assert_eq!(
        calls.forward(token, 1, &wrong, &mut out, 8, |_| panic!()),
        micro_cel::support::status::ERR_ARG
    );
    let valid = reply(token, 12, 3, Ok(7));
    assert_eq!(calls.forward(token, 1, &valid, &mut out, 8, |_| -9), -9);
    assert_eq!(calls.forward(token, 1, &valid, &mut out, 8, |_| 0), 0);
    assert_eq!(
        calls.forward(token, 1, &valid, &mut out, 8, |_| panic!()),
        micro_cel::support::status::ERR_ARG
    );
    assert_eq!(calls.invoke(2, 10, 12, 3, &[0xa0], |_, _| -8), Err(-8));
    calls.invoke(2, 10, 12, 3, &[0xa0], |_, _| 0).unwrap();
    calls.invoke(12, 10, 12, 3, &[0xa0], |_, _| 0).unwrap();
}

#[cfg(feature = "translate")]
#[test]
fn common_service_capacity_is_not_fixed_to_device_profile() {
    let encoded = program((0..6).map(|_| call(12, 3)).collect());
    let mut service = Service::default();
    start(&mut service, &encoded);
    let mut out = [0; 64];
    let mut sent = 0;
    for _ in 0..6 {
        poll(
            &mut service,
            0,
            |_, _, _, _, _| {
                sent += 1;
                0
            },
            &mut out,
        )
        .unwrap();
    }
    assert_eq!(sent, 6);
}

use micro_cel::support::status::{ERR_ARG, ERR_BUSY};
use micro_cel::{
    program::{Program, ProgramLimits, Rule, RuleList, wire},
    service::{LegacyCalls, Routes, Service, TOKEN_BIT},
};

const ROUTES: Routes = Routes {
    envelope_addr: 123,
    event_addr: 456,
    event_component: 77,
    event_method: 9,
};
const DEPTH: u32 = 32;
const TIMEOUT: u64 = 10_000;

fn program(exprs: Vec<Vec<u8>>) -> Vec<u8> {
    let p = Program {
        lists: exprs
            .into_iter()
            .enumerate()
            .map(|(i, expr)| RuleList {
                name: i.to_string(),
                context: vec![0xa0],
                rules: vec![Rule::Eval { expr }],
            })
            .collect(),
    };
    wire::encode(&p, &ProgramLimits::default()).unwrap()
}
fn literal_true() -> Vec<u8> {
    vec![0xa1, 1, 0xa1, 3, 0xf5]
}
#[cfg(feature = "translate")]
fn call(c: i32, m: i32) -> Vec<u8> {
    micro_cel::host::translate::translate(
        &format!("call({c}, {m}, {{}})"),
        &micro_cel::host::translate::Schema::parse("").unwrap(),
    )
    .unwrap()
}
fn reply(id: u64, c: i32, m: i32, result: Result<u64, i32>) -> Vec<u8> {
    let mut b = [0; 128];
    let mut w = Writer::new(&mut b);
    w.map(4)
        .uint(1)
        .int(c.into())
        .uint(2)
        .int(m.into())
        .uint(3)
        .uint(id);
    match result {
        Ok(n) => {
            w.uint(6).uint(n);
        }
        Err(n) => {
            w.uint(7).int(n.into());
        }
    }
    w.finish().unwrap().to_vec()
}
fn start(s: &mut Service, p: &[u8]) {
    s.start(p, ProgramLimits::default(), DEPTH).unwrap();
}
fn poll(
    s: &mut Service,
    now: u64,
    send: impl FnMut(u32, i32, i32, u64, &[u8]) -> i32,
    out: &mut [u8],
) -> Result<usize, i32> {
    s.poll(now, send, out, TIMEOUT, ROUTES)
}

#[test]
fn legacy_reservation_validation_retry_and_expiry() {
    let mut calls = LegacyCalls::<1>::default();
    let mut id = 0;
    let mut out = [0; 128];
    calls
        .invoke(10, 20, 1, 2, &[0xa0], |token, _| {
            id = token;
            0
        })
        .unwrap();
    assert_ne!(id, 0);
    assert_eq!(id & TOKEN_BIT, 0);
    assert_eq!(calls.invoke(11, 20, 1, 2, &[0xa0], |_, _| 0), Err(ERR_BUSY));
    for input in [
        vec![0xff],
        reply(id, 9, 2, Ok(7)),
        reply(id + 1, 1, 2, Ok(7)),
    ] {
        assert_eq!(
            calls.forward(id, 11, &input, &mut out, DEPTH, |_| panic!()),
            ERR_ARG
        );
    }
    let good = reply(id, 1, 2, Ok(7));
    assert_eq!(
        calls.forward(id, 11, &good, &mut out, DEPTH, |data| {
            assert_eq!(data, good);
            -9
        }),
        -9
    );
    assert_eq!(calls.forward(id, 11, &good, &mut out, DEPTH, |_| 0), 0);
    assert_eq!(
        calls.forward(id, 11, &good, &mut out, DEPTH, |_| panic!()),
        ERR_ARG
    );
    assert_eq!(calls.invoke(12, 20, 1, 2, &[0xa0], |_, _| -8), Err(-8));
    let mut expired = 0;
    calls
        .invoke(12, 20, 1, 2, &[0xa0], |token, _| {
            expired = token;
            0
        })
        .unwrap();
    assert_eq!(
        calls.forward(
            expired,
            32,
            &reply(expired, 1, 2, Ok(1)),
            &mut out,
            DEPTH,
            |_| panic!()
        ),
        ERR_ARG
    );
    calls.invoke(32, 20, 1, 2, &[0xa0], |_, _| 0).unwrap();
}

#[test]
fn zero_initialized_lifecycle_and_completion_retry() {
    // SAFETY: Service documents a zero-filled state as valid.
    let mut s: Service = unsafe { core::mem::zeroed() };
    let mut out = [0; 128];
    assert_eq!(poll(&mut s, 0, |_, _, _, _, _| panic!(), &mut out), Ok(3));
    let p = program(vec![literal_true()]);
    start(&mut s, &p);
    assert_eq!(s.start(&p, ProgramLimits::default(), DEPTH), Err(ERR_BUSY));
    let mut first = Vec::new();
    assert_eq!(
        poll(
            &mut s,
            0,
            |a, c, m, id, data| {
                assert_eq!((a, c, m, id), (456, 77, 9, 0));
                first = data.to_vec();
                -9
            },
            &mut out
        ),
        Err(-9)
    );
    assert_eq!(first, [0xa3, 1, 0, 2, 1, 3, 0xf5]);
    poll(
        &mut s,
        0,
        |a, c, m, id, data| {
            assert_eq!((a, c, m, id), (456, 77, 9, 0));
            assert_eq!(data, first);
            0
        },
        &mut out,
    )
    .unwrap();
    poll(&mut s, 0, |_, _, _, _, _| panic!(), &mut out).unwrap();
    start(&mut s, &p);
}

#[test]
fn queued_alarm_zero_ownership_and_start_rollback() {
    let p = program(vec![literal_true()]);
    let mut s = Service::default();
    assert_eq!(
        s.start_queued(&p, ProgramLimits::default(), DEPTH, |_| panic!(), |_| -7),
        Err(-7)
    );
    s.start_queued(
        &p,
        ProgramLimits::default(),
        DEPTH,
        |_| panic!(),
        |d| {
            assert_eq!(d, 1);
            0
        },
    )
    .unwrap();
    assert_eq!(
        s.rearm(
            Some(25),
            |id| {
                assert_eq!(id, 0);
                -9
            },
            |_| panic!()
        ),
        Err(-9)
    );
    s.rearm(
        Some(25),
        |id| {
            assert_eq!(id, 0);
            0
        },
        |d| {
            assert_eq!(d, 25);
            3
        },
    )
    .unwrap();
    s.stop(|id| {
        assert_eq!(id, 3);
        0
    })
    .unwrap();
    start(&mut s, &p);
    s.stop(|_| panic!()).unwrap();
}

#[cfg(feature = "translate")]
#[test]
fn correlation_failure_event_and_cleanup() {
    let mut s = Service::default();
    let mut out = [0; 128];
    start(&mut s, &program(vec![call(1, 2)]));
    let mut id = 0;
    poll(
        &mut s,
        10,
        |a, c, m, t, _| {
            assert_eq!((a, c, m), (123, 0, 0));
            id = t;
            0
        },
        &mut out,
    )
    .unwrap();
    assert_ne!(id & TOKEN_BIT, 0);
    assert_eq!(s.answer(1, 11, &[], DEPTH), None);
    assert_eq!(s.answer(id, 11, &[0xff], DEPTH), Some(ERR_ARG));
    assert_eq!(
        s.answer(id, 11, &reply(id, 9, 2, Ok(7)), DEPTH),
        Some(ERR_ARG)
    );
    assert_eq!(s.answer(id, 11, &reply(id, 1, 2, Ok(7)), DEPTH), Some(0));
    assert_eq!(
        s.answer(id, 11, &reply(id, 1, 2, Ok(7)), DEPTH),
        Some(ERR_ARG)
    );
    poll(
        &mut s,
        11,
        |_, _, _, _, data| {
            assert_eq!(data, [0xa3, 1, 0, 2, 1, 3, 7]);
            0
        },
        &mut out,
    )
    .unwrap();
    poll(&mut s, 11, |_, _, _, _, _| panic!(), &mut out).unwrap();
    start(&mut s, &program(vec![call(1, 2)]));
    let mut next = 0;
    poll(
        &mut s,
        12,
        |_, _, _, t, _| {
            next = t;
            0
        },
        &mut out,
    )
    .unwrap();
    assert_ne!(id, next);
    assert_eq!(
        s.answer(id, 12, &reply(id, 1, 2, Ok(7)), DEPTH),
        Some(ERR_ARG)
    );
    assert_eq!(
        s.answer(next, 12, &reply(next, 1, 2, Err(-42)), DEPTH),
        Some(0)
    );
    poll(
        &mut s,
        12,
        |a, c, m, _, data| {
            assert_eq!((a, c, m), (456, 77, 9));
            assert_eq!(&data[..5], &[0xa3, 1, 0, 2, 2]);
            0
        },
        &mut out,
    )
    .unwrap();
}

#[cfg(feature = "translate")]
#[test]
fn parallel_lists_and_reply_timeout() {
    let mut s = Service::default();
    let mut out = [0; 128];
    start(&mut s, &program(vec![call(1, 2), call(3, 4)]));
    let mut ids = Vec::new();
    for _ in 0..2 {
        poll(
            &mut s,
            10,
            |a, _, _, id, _| {
                assert_eq!(a, 123);
                ids.push(id);
                0
            },
            &mut out,
        )
        .unwrap();
    }
    assert_ne!(ids[0], ids[1]);
    assert_eq!(
        s.answer(ids[1], 11, &reply(ids[1], 3, 4, Ok(9)), DEPTH),
        Some(0)
    );
    poll(
        &mut s,
        11,
        |_, _, _, _, data| {
            assert_eq!(data, [0xa3, 1, 1, 2, 1, 3, 9]);
            0
        },
        &mut out,
    )
    .unwrap();
    let n = poll(&mut s, 11, |_, _, _, _, _| panic!(), &mut out).unwrap();
    let mut status = mesh_api::cbor::Reader::new(&out[..n]);
    for expected in [
        mesh_api::cbor::Item::Map(2),
        mesh_api::cbor::Item::Uint(1),
        mesh_api::cbor::Item::Uint(2),
        mesh_api::cbor::Item::Uint(2),
        mesh_api::cbor::Item::Uint(10010),
    ] {
        assert_eq!(status.next(), Some(expected));
    }
    assert!(status.rest().is_empty());
    assert_eq!(
        s.answer(ids[0], 10010, &reply(ids[0], 1, 2, Ok(1)), DEPTH),
        Some(ERR_ARG)
    );
    poll(
        &mut s,
        10010,
        |_, _, _, _, data| {
            assert_eq!(&data[..5], &[0xa3, 1, 0, 2, 2]);
            0
        },
        &mut out,
    )
    .unwrap();
}

#[cfg(feature = "translate")]
#[test]
fn queued_answer_drive_and_call_send_failure() {
    let mut s = Service::default();
    let mut out = [0; 128];
    let p = program(vec![call(1, 2)]);
    s.start_queued(&p, ProgramLimits::default(), DEPTH, |_| panic!(), |_| 0)
        .unwrap();
    s.alarm_fired();
    let mut id = 0;
    s.drive(
        10,
        |a, _, _, t, _| {
            assert_eq!(a, 123);
            id = t;
            0
        },
        &mut out,
        TIMEOUT,
        ROUTES,
        |_| panic!(),
        |d| {
            assert_eq!(d, 1);
            2
        },
    )
    .unwrap();
    assert_eq!(
        s.answer_queued(
            id,
            11,
            &reply(id, 9, 2, Ok(7)),
            DEPTH,
            |_| panic!(),
            |_| panic!()
        ),
        Some(ERR_ARG)
    );
    assert_eq!(
        s.answer_queued(
            id,
            11,
            &reply(id, 1, 2, Ok(7)),
            DEPTH,
            |alarm| {
                assert_eq!(alarm, 2);
                0
            },
            |d| {
                assert_eq!(d, 1);
                3
            }
        ),
        Some(0)
    );
    s.alarm_fired();
    s.drive(
        11,
        |_, _, _, _, data| {
            assert_eq!(data, [0xa3, 1, 0, 2, 1, 3, 7]);
            0
        },
        &mut out,
        TIMEOUT,
        ROUTES,
        |_| panic!(),
        |_| 4,
    )
    .unwrap();
    s.stop(|alarm| {
        assert_eq!(alarm, 4);
        0
    })
    .unwrap();
    start(&mut s, &p);
    poll(&mut s, 12, |_, _, _, _, _| -8, &mut out).unwrap();
    poll(
        &mut s,
        12,
        |a, c, m, _, data| {
            assert_eq!((a, c, m), (456, 77, 9));
            assert_eq!(&data[..5], &[0xa3, 1, 0, 2, 2]);
            0
        },
        &mut out,
    )
    .unwrap();
}

#[test]
fn service_rejects_invalid_ast_in_unselected_branch() {
    // true ? true : <malformed AST>
    let expression = vec![
        0xa1, 4, 0xa2, 1, 4, 2, 0x83, 0xa1, 1, 0xa1, 3, 0xf5, 0xa1, 1, 0xa1, 3, 0xf5, 0xa0,
    ];
    let mut service = Service::default();
    assert_eq!(
        service.start(&program(vec![expression]), ProgramLimits::default(), DEPTH),
        Err(micro_cel::Code::Malformed.to_i32())
    );
    start(&mut service, &program(vec![literal_true()]));
}

#[cfg(feature = "translate")]
#[test]
fn runner_expiry_releases_service_slot_before_service_deadline() {
    // The first list fails at 10 ms; a delayed list then needs its only slot.
    // Run both with and without a late response triggering runner expiration.
    for late_response in [false, true] {
        let limits = ProgramLimits {
            max_pending: 1,
            timeout_ms: 10,
            ..ProgramLimits::default()
        };
        let p = Program {
            lists: vec![
                RuleList {
                    name: "first".into(),
                    context: vec![0xa0],
                    rules: vec![Rule::Eval { expr: call(1, 2) }],
                },
                RuleList {
                    name: "second".into(),
                    context: vec![0xa0],
                    rules: vec![
                        Rule::After { delay_ms: 11 },
                        Rule::Eval { expr: call(3, 4) },
                    ],
                },
            ],
        };
        let p = wire::encode(&p, &limits).unwrap();
        let mut service = Service::default();
        service.start(&p, limits, DEPTH).unwrap();
        let mut out = [0; 128];
        let mut first = 0;
        poll(
            &mut service,
            0,
            |_, _, _, id, _| {
                first = id;
                0
            },
            &mut out,
        )
        .unwrap();
        poll(&mut service, 0, |_, _, _, _, _| panic!(), &mut out).unwrap();
        if late_response {
            assert_eq!(
                service.answer(first, 10, &reply(first, 1, 2, Ok(7)), DEPTH),
                Some(ERR_ARG)
            );
        }
        poll(&mut service, 10, |_, _, _, _, _| 0, &mut out).unwrap();
        let mut second = 0;
        poll(
            &mut service,
            11,
            |_, _, _, id, _| {
                second = id;
                0
            },
            &mut out,
        )
        .unwrap();
        assert_ne!(second, 0);
        assert_eq!(
            service.answer(second, 12, &reply(second, 3, 4, Ok(9)), DEPTH),
            Some(0)
        );
    }
}

#[cfg(feature = "translate")]
#[test]
fn transport_timeout_shortens_runner_deadline() {
    let limits = ProgramLimits {
        timeout_ms: 1000,
        ..ProgramLimits::default()
    };
    let mut service = Service::default();
    service
        .start(&program(vec![call(1, 2)]), limits, DEPTH)
        .unwrap();
    let mut out = [0; 128];
    let mut id = 0;
    service
        .poll(
            0,
            |_, _, _, token, _| {
                id = token;
                0
            },
            &mut out,
            10,
            ROUTES,
        )
        .unwrap();
    let n = service
        .poll(1, |_, _, _, _, _| panic!(), &mut out, 10, ROUTES)
        .unwrap();
    assert_eq!(&out[..n], &[0xa2, 1, 2, 2, 10]);
    assert_eq!(
        service.answer(id, 10, &reply(id, 1, 2, Ok(7)), DEPTH),
        Some(ERR_ARG)
    );
    let mut failed = false;
    service
        .poll(
            10,
            |_, _, _, _, data| {
                let fields = micro_cel::service::fields::<4>(data).unwrap();
                assert_eq!(fields[2], Some(&[2][..]));
                failed = true;
                0
            },
            &mut out,
            10,
            ROUTES,
        )
        .unwrap();
    assert!(failed);
}
