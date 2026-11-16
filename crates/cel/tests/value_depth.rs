use mesh_api::cbor::Writer;
use micro_cel::{Code, Invoke, Limits, NoInvoke, eval};

fn enc(f: impl FnOnce(&mut Writer<'_>)) -> Vec<u8> {
    let mut buf = [0; 1024];
    let mut w = Writer::new(&mut buf);
    f(&mut w);
    w.finish().unwrap().to_vec()
}
fn nested(n: usize) -> Vec<u8> {
    let mut v = vec![0x81; n];
    v.push(0);
    v
}
fn vars(value: &[u8]) -> Vec<u8> {
    let mut v = vec![0xa1, 1];
    v.extend_from_slice(value);
    v
}
fn ident() -> Vec<u8> {
    vec![0xa1, 2, 0xa1, 1, 1]
}
fn literal(n: i32) -> Vec<u8> {
    enc(|w| {
        w.map(1).uint(1).map(1).uint(1).int(n.into());
    })
}
fn list(expr: &[u8]) -> Vec<u8> {
    enc(|w| {
        w.map(1).uint(5).map(1).uint(1).array(1).raw(expr);
    })
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
        for arg in args {
            w.raw(arg);
        }
    })
}
fn run(ast: &[u8], context: &[u8], invoke: &mut impl Invoke) -> Result<Vec<u8>, Code> {
    let mut scratch = vec![0; 65536];
    let mut out = vec![0; 4096];
    eval(
        ast,
        context,
        &mut scratch,
        &mut out,
        Limits::default(),
        invoke,
    )
    .map(<[u8]>::to_vec)
}

#[test]
fn standalone_constructed_lists_enforce_value_depth() {
    let context = vars(&nested(31));
    let at_boundary = list(&ident());
    assert_eq!(run(&at_boundary, &context, &mut NoInvoke), Ok(nested(32)));
    assert_eq!(
        run(&list(&at_boundary), &context, &mut NoInvoke),
        Err(Code::Depth)
    );
}

struct Counting(usize);
impl Invoke for Counting {
    fn invoke<'a>(&mut self, _: i32, _: i32, _: &[u8], out: &'a mut [u8]) -> Result<&'a [u8], i32> {
        self.0 += 1;
        out[0] = 0xf6;
        Ok(&out[..1])
    }
}

#[test]
fn overdepth_intermediate_list_is_rejected_before_invocation() {
    // The context and final parameter map are valid, but temporary wrapping
    // exceeds the value bound before indexing removes those wrappers.
    let mut params = vec![0xa1, 1];
    params.extend(nested(30));
    let context = vars(&params);
    let wrapped = list(&list(&ident()));
    let unwrapped = call(18, &[call(18, &[wrapped, literal(0)]), literal(0)]);
    let ast = call(23, &[literal(12), literal(3), unwrapped]);
    let mut inv = Counting(0);
    assert_eq!(run(&ast, &context, &mut inv), Err(Code::Depth));
    assert_eq!(inv.0, 0);
    #[cfg(feature = "program")]
    {
        let mut runner = runner(ast, context);
        assert_eq!(
            runner.poll(0),
            micro_cel::program::Event::Failed {
                list: 0,
                error: Code::Depth
            }
        );
        assert_eq!(runner.poll(0), micro_cel::program::Event::Finished);
    }
}

#[cfg(feature = "program")]
fn runner(expr: Vec<u8>, context: Vec<u8>) -> micro_cel::program::Runner {
    use micro_cel::program::{Program, ProgramLimits, Rule, RuleList, Runner};
    Runner::new(
        Program {
            lists: vec![RuleList {
                name: "depth".into(),
                context,
                rules: vec![Rule::Eval { expr }],
            }],
        },
        ProgramLimits {
            max_frames: 64,
            ..ProgramLimits::default()
        },
    )
    .unwrap()
}

#[cfg(feature = "program")]
#[test]
fn iterative_constructed_lists_match_standalone_depth_boundary() {
    use micro_cel::program::Event;
    let context = vars(&nested(31));
    let at_boundary = list(&ident());
    assert_eq!(
        runner(at_boundary.clone(), context.clone()).poll(0),
        Event::Complete {
            list: 0,
            result: nested(32)
        }
    );
    assert_eq!(
        runner(list(&at_boundary), context).poll(0),
        Event::Failed {
            list: 0,
            error: Code::Depth
        }
    );
}
