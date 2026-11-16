#![cfg(feature = "translate")]

use micro_cel::{
    Invoke, Limits, check, eval,
    host::translate::{Schema, translate},
};

struct Fake {
    expected: Option<Vec<u8>>,
}
impl Invoke for Fake {
    fn invoke<'a>(
        &mut self,
        c: i32,
        m: i32,
        params: &[u8],
        out: &'a mut [u8],
    ) -> Result<&'a [u8], i32> {
        assert_eq!((c, m), (52, 1));
        assert_eq!(Some(params), self.expected.as_deref());
        self.expected = None;
        out[0] = 0xf6;
        Ok(&out[..1])
    }
}

fn run(src: &str, fake: &mut Fake) -> Vec<u8> {
    let ast = translate(src, &Schema::default()).unwrap();
    check(&ast, &Limits::default()).unwrap();
    let mut scratch = [0; 8192];
    let mut out = [0; 1024];
    eval(
        &ast,
        &[0xa0],
        &mut scratch,
        &mut out,
        Limits::default(),
        fake,
    )
    .unwrap()
    .to_vec()
}

#[test]
fn binary_roundtrip_and_call_params() {
    let mut fake = Fake { expected: None };
    assert_eq!(
        run(r#"b"\x00\x7f\x80\xFF\0""#, &mut fake),
        [0x45, 0, 0x7f, 0x80, 0xff, 0]
    );
    fake.expected = Some(vec![0xa1, 1, 0x45, 0, 0x7f, 0x80, 0xff, 0]);
    assert_eq!(
        run(r#"call(52, 1, {1: b"\x00\x7f\x80\xFF\0"})"#, &mut fake),
        [0xf6]
    );
    assert!(fake.expected.is_none());
    assert_eq!(run("b\"é\"", &mut fake), [0x42, 0xc3, 0xa9]);
}

#[test]
fn reject_raw_controls_and_binary_text_escapes() {
    let schema = Schema::default();
    for c in 0..32 {
        for prefix in ["", "b"] {
            let src = format!("{prefix}\"{}\"", char::from(c));
            assert!(translate(&src, &schema).is_err(), "accepted {src:?}");
        }
    }
    for src in [r#""\x00""#, r#""\0""#, r#"{"\0": 1}"#] {
        assert!(translate(src, &schema).is_err(), "accepted {src:?}");
    }
    let mut fake = Fake { expected: None };
    assert_eq!(
        run(r#"b"\n\r\t\0\x1f""#, &mut fake),
        [0x45, 10, 13, 9, 0, 31]
    );
    assert_eq!(run("b\"\u{7f}\"", &mut fake), [0x41, 0x7f]);
}

#[test]
fn malformed_and_existing_escapes() {
    let schema = Schema::default();
    for src in [
        "b\"\\x",
        "b\"\\x0",
        "b\"\\x0\"",
        "b\"\\xgg\"",
        "b\"\\xé\"",
        "b\"\\q\"",
        "b\"\\",
        "\"unterminated",
    ] {
        assert!(translate(src, &schema).is_err(), "accepted {src:?}");
    }
    let mut fake = Fake { expected: None };
    assert_eq!(
        run(r#""a\"b\\c""#, &mut fake),
        [0x65, b'a', b'"', b'b', b'\\', b'c']
    );
    assert_eq!(
        run(r#"b"a\"b\\c""#, &mut fake),
        [0x45, b'a', b'"', b'b', b'\\', b'c']
    );
    assert_eq!(run(r#"{"x": [b"\x41"]}.x[0]"#, &mut fake), [0x41, b'A']);
}
