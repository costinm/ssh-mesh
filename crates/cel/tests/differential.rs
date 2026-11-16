#![cfg(feature = "program")]

use mesh_api::cbor::Writer;
use micro_cel::{
    Code, Limits, NoInvoke,
    program::{Event, Program, ProgramLimits, Rule, RuleList, Runner},
};

fn enc(f: impl FnOnce(&mut Writer<'_>)) -> Vec<u8> {
    let mut buf = vec![0; 32768];
    let mut w = Writer::new(&mut buf);
    f(&mut w);
    w.finish().unwrap().to_vec()
}
fn constant(kind: u64, value: &[u8]) -> Vec<u8> {
    enc(|w| {
        w.map(1).uint(1).map(1).uint(kind).raw(value);
    })
}
fn integer(n: i64) -> Vec<u8> {
    constant(
        1,
        &enc(|w| {
            w.int(n);
        }),
    )
}
fn boolean(b: bool) -> Vec<u8> {
    constant(3, &[if b { 0xf5 } else { 0xf4 }])
}
fn call(id: u64, args: &[Vec<u8>]) -> Vec<u8> {
    enc(|w| {
        w.map(1)
            .uint(4)
            .map(2)
            .uint(1)
            .uint(id)
            .uint(2)
            .array(args.len());
        for a in args {
            w.raw(a);
        }
    })
}
fn select(a: Vec<u8>, field: &[u8]) -> Vec<u8> {
    enc(|w| {
        w.map(1).uint(3).map(2).uint(1).raw(&a).uint(2).raw(field);
    })
}
fn list(items: &[Vec<u8>]) -> Vec<u8> {
    enc(|w| {
        w.map(1).uint(5).map(1).uint(1).array(items.len());
        for a in items {
            w.raw(a);
        }
    })
}
fn map(value: Vec<u8>) -> Vec<u8> {
    enc(|w| {
        w.map(1)
            .uint(6)
            .map(1)
            .uint(1)
            .array(1)
            .array(2)
            .text("x")
            .raw(&value);
    })
}
fn compare(ast: &[u8]) -> Result<Vec<u8>, Code> {
    let vars = [0xa2, 1, 0x82, 1, 2, 2, 0xa1, 0x61, b'x', 0xf5];
    let mut scratch = vec![0; 262144];
    let mut out = vec![0; 16384];
    let direct = micro_cel::eval(
        ast,
        &vars,
        &mut scratch,
        &mut out,
        Limits {
            max_depth: 64,
            max_nodes: 4096,
        },
        &mut NoInvoke,
    )
    .map(|v| v.to_vec());
    let limits = ProgramLimits {
        max_frames: 64,
        max_nodes: 4096,
        max_input_bytes: 32768,
        max_value_bytes: 16384,
        ..ProgramLimits::default()
    };
    let program = Program {
        lists: vec![RuleList {
            name: "test".into(),
            context: vars.to_vec(),
            rules: vec![Rule::Eval { expr: ast.to_vec() }],
        }],
    };
    let mut runner = Runner::new(program, limits).unwrap();
    let result = match runner.poll(0) {
        Event::Complete { result, .. } => Ok(result),
        Event::Failed { error, .. } => Err(error),
        e => panic!("unexpected event {e:?}"),
    };
    assert_eq!(
        direct,
        result,
        "AST: {ast:02x?}, check: {:?}",
        micro_cel::check(
            ast,
            &Limits {
                max_depth: 64,
                max_nodes: 4096
            }
        )
    );
    direct
}
struct Rng(u64);
impl Rng {
    fn next(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }
}
fn generate(r: &mut Rng, depth: u32) -> Vec<u8> {
    if depth == 0 || r.next(5) == 0 {
        return match r.next(12) {
            0 => integer(i32::MIN.into()),
            1 => integer(i32::MAX.into()),
            2 => integer(-1),
            3 => integer(0),
            4 => integer(1),
            5 => boolean(false),
            6 => boolean(true),
            7 => constant(7, &[0xf6]),
            8 => constant(5, &[0x60]),
            9 => constant(5, &[0x61, b'x']),
            10 => constant(6, &[0x41, b'x']),
            _ => enc(|w| {
                w.map(1).uint(2).map(1).uint(1).uint(1 + r.next(3));
            }),
        };
    }
    match r.next(8) {
        0 => list(&[generate(r, depth - 1), generate(r, depth - 1)]),
        1 => map(generate(r, depth - 1)),
        2 => select(
            generate(r, depth - 1),
            if r.next(2) == 0 {
                &[0][..]
            } else {
                &[0x61, b'x'][..]
            },
        ),
        3 => {
            let a = generate(r, depth - 1);
            call(24, &[select(a, &[0x61, b'x'])])
        }
        _ => {
            let id = 1 + r.next(22);
            let count = if matches!(id, 3 | 13 | 19) {
                1
            } else if id == 4 {
                3
            } else {
                2
            };
            let args = (0..count)
                .map(|_| generate(r, depth - 1))
                .collect::<Vec<_>>();
            call(id, &args)
        }
    }
}

#[test]
fn known_cases() {
    let missing = select(map(integer(1)), &[0x61, b'y']);
    let cases = [
        (call(12, &[integer(1), integer(2)]), Ok(vec![3])),
        (
            call(12, &[integer(i32::MAX.into()), integer(1)]),
            Err(Code::Arith),
        ),
        (call(13, &[integer(i32::MIN.into())]), Err(Code::Arith)),
        (call(16, &[integer(1), integer(0)]), Err(Code::Arith)),
        (call(5, &[constant(7, &[0xf6]), integer(1)]), Ok(vec![0xf4])),
        (call(5, &[integer(1), boolean(true)]), Ok(vec![0xf4])),
        (call(19, &[list(&[])]), Ok(vec![0])),
        (call(11, &[integer(1), list(&[integer(1)])]), Ok(vec![0xf5])),
        (call(18, &[list(&[]), integer(0)]), Err(Code::NotFound)),
        (call(24, std::slice::from_ref(&missing)), Ok(vec![0xf4])),
        (call(1, &[missing.clone(), boolean(true)]), Ok(vec![0xf5])),
        (call(2, &[missing, boolean(false)]), Ok(vec![0xf4])),
        (
            call(4, &[boolean(true), integer(7), integer(8)]),
            Ok(vec![7]),
        ),
    ];
    for (ast, expected) in cases {
        assert_eq!(compare(&ast), expected, "{ast:02x?}");
    }
}
#[test]
fn seeded_random_expressions() {
    let mut r = Rng(0x1234_5678_9abc_def0);
    for _ in 0..3000 {
        let _ = compare(&generate(&mut r, 5));
    }
}
