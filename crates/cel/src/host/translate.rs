//! Host-side translator for the supported CEL subset.
use mesh_api::cbor::Writer;
use std::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
/// Mapping from expression identifiers to unsigned context tags.
#[derive(Clone, Debug, Default)]
pub struct Schema(pub Vec<(String, u64)>);
impl Schema {
    /// Parse name = tag lines, accepting comments and rejecting invalid or duplicate names.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut entries = Vec::new();
        for (line, text) in text.lines().enumerate() {
            let text = text.split('#').next().unwrap_or("").trim();
            if text.is_empty() {
                continue;
            }
            let (name, tag) = text
                .split_once('=')
                .ok_or_else(|| format!("schema line {}: expected name = tag", line + 1))?;
            let name = name.trim();
            if name.is_empty()
                || !name.bytes().enumerate().all(|(i, b)| {
                    b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit())
                })
            {
                return Err(format!("schema line {}: invalid name", line + 1));
            }
            let tag = tag
                .trim()
                .parse()
                .map_err(|_| format!("schema line {}: invalid tag", line + 1))?;
            if entries.iter().any(|(n, _)| n == name) {
                return Err(format!("schema line {}: duplicate name", line + 1));
            }
            entries.push((name.to_string(), tag));
        }
        Ok(Self(entries))
    }
}

enum MapKey {
    Int(i32),
    Text(String),
}

enum Expr {
    Int(i32),
    Bool(bool),
    Null,
    Text(String),
    Bytes(Vec<u8>),
    Ident(u64),
    List(Vec<Expr>),
    Map(Vec<(MapKey, Expr)>),
    Select(Box<Expr>, String),
    Call(u64, Vec<Expr>),
}
impl Expr {
    fn emit(&self, w: &mut Writer<'_>) {
        match self {
            Self::Int(n) => {
                w.map(1).uint(1).map(1).uint(1).int(*n as i64);
            }
            Self::Bool(b) => {
                w.map(1).uint(1).map(1).uint(3).boolean(*b);
            }
            Self::Null => {
                w.map(1).uint(1).map(1).uint(7).null();
            }
            Self::Text(s) => {
                w.map(1).uint(1).map(1).uint(5).text(s);
            }
            Self::Bytes(b) => {
                w.map(1).uint(1).map(1).uint(6).bytes(b);
            }
            Self::Ident(n) => {
                w.map(1).uint(2).map(1).uint(1).uint(*n);
            }
            Self::List(a) => {
                w.map(1).uint(5).map(1).uint(1).array(a.len());
                for x in a {
                    x.emit(w);
                }
            }
            Self::Map(a) => {
                w.map(1).uint(6).map(1).uint(1).array(a.len());
                for (k, v) in a {
                    w.array(2);
                    match k {
                        MapKey::Int(n) => {
                            w.int(*n as i64);
                        }
                        MapKey::Text(s) => {
                            w.text(s);
                        }
                    };
                    v.emit(w);
                }
            }
            Self::Select(e, s) => {
                w.map(1).uint(3).map(2).uint(1);
                e.emit(w);
                w.uint(2).text(s);
            }
            Self::Call(id, a) => {
                w.map(1)
                    .uint(4)
                    .map(2)
                    .uint(1)
                    .uint(*id)
                    .uint(2)
                    .array(a.len());
                for x in a {
                    x.emit(w);
                }
            }
        }
    }
}
struct Parser<'a> {
    src: &'a str,
    pos: usize,
    schema: &'a Schema,
    recursion: usize,
}
impl<'a> Parser<'a> {
    fn bounded(&self, expr: Expr) -> Result<Expr, String> {
        fn depth(e: &Expr) -> usize {
            1 + match e {
                Expr::Select(e, _) => depth(e),
                Expr::Call(_, a) | Expr::List(a) => a.iter().map(depth).max().unwrap_or(0),
                Expr::Map(a) => a.iter().map(|(_, v)| depth(v)).max().unwrap_or(0),
                _ => 0,
            }
        }
        if depth(&expr) > 128 {
            Err(self.err("expression depth limit exceeded"))
        } else {
            Ok(expr)
        }
    }
    fn err(&self, message: &str) -> String {
        format!("error at offset {}: {}", self.pos, message)
    }
    fn ws(&mut self) {
        while self
            .src
            .as_bytes()
            .get(self.pos)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.pos += 1;
        }
    }
    fn eat(&mut self, s: &str) -> bool {
        self.ws();
        if self.src[self.pos..].starts_with(s) {
            self.pos += s.len();
            true
        } else {
            false
        }
    }
    fn expect(&mut self, s: &str) -> Result<(), String> {
        if self.eat(s) {
            Ok(())
        } else {
            Err(self.err(&format!("expected {s}")))
        }
    }
    fn expr(&mut self) -> Result<Expr, String> {
        if self.recursion >= 128 {
            return Err(self.err("parser depth limit exceeded"));
        }
        self.recursion += 1;
        let result = self.expr_inner();
        self.recursion -= 1;
        result.and_then(|expr| self.bounded(expr))
    }
    fn expr_inner(&mut self) -> Result<Expr, String> {
        let cond = self.binary(1)?;
        if self.eat("?") {
            let yes = self.expr()?;
            self.expect(":")?;
            let no = self.expr()?;
            Ok(Expr::Call(4, std::vec![cond, yes, no]))
        } else {
            Ok(cond)
        }
    }
    fn binary(&mut self, min: u8) -> Result<Expr, String> {
        if self.recursion >= 128 {
            return Err(self.err("parser depth limit exceeded"));
        }
        self.recursion += 1;
        let result = self.binary_inner(min);
        self.recursion -= 1;
        result.and_then(|expr| self.bounded(expr))
    }
    fn binary_inner(&mut self, min: u8) -> Result<Expr, String> {
        let mut left = self.unary()?;
        loop {
            self.ws();
            let rest = &self.src[self.pos..];
            let ops = [
                ("||", 1, 1),
                ("&&", 2, 2),
                ("<=", 3, 8),
                (">=", 3, 10),
                ("==", 3, 5),
                ("!=", 3, 6),
                ("<", 3, 7),
                (">", 3, 9),
                ("in", 3, 11),
                ("+", 4, 12),
                ("-", 4, 14),
                ("*", 5, 15),
                ("/", 5, 16),
                ("%", 5, 17),
            ];
            let found = ops.iter().find(|(s, _, _)| {
                rest.starts_with(s)
                    && (*s != "in"
                        || !rest
                            .as_bytes()
                            .get(2)
                            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_'))
            });
            let Some(&(op, prec, id)) = found else { break };
            if prec < min {
                break;
            }
            self.pos += op.len();
            let right = self.binary(prec + 1)?;
            left = self.bounded(Expr::Call(id, std::vec![left, right]))?;
        }
        Ok(left)
    }
    fn unary(&mut self) -> Result<Expr, String> {
        if self.recursion >= 128 {
            return Err(self.err("parser depth limit exceeded"));
        }
        self.recursion += 1;
        let result = self.unary_inner();
        self.recursion -= 1;
        result.and_then(|expr| self.bounded(expr))
    }
    fn unary_inner(&mut self) -> Result<Expr, String> {
        if self.eat("!") {
            return Ok(Expr::Call(3, std::vec![self.unary()?]));
        }
        if self.eat("-") {
            self.ws();
            // Fold signed integer literals, including i32::MIN, for static call targets.
            if self
                .src
                .as_bytes()
                .get(self.pos)
                .is_some_and(u8::is_ascii_digit)
            {
                let start = self.pos;
                while self
                    .src
                    .as_bytes()
                    .get(self.pos)
                    .is_some_and(u8::is_ascii_digit)
                {
                    self.pos += 1;
                }
                let n: i64 = self.src[start..self.pos]
                    .parse()
                    .map_err(|_| self.err("integer literal out of i32 range"))?;
                let n =
                    i32::try_from(-n).map_err(|_| self.err("integer literal out of i32 range"))?;
                return Ok(Expr::Int(n));
            }
            return Ok(Expr::Call(13, std::vec![self.unary()?]));
        }
        let mut node = self.primary()?;
        loop {
            if self.eat("[") {
                let index = self.expr()?;
                self.expect("]")?;
                node = self.bounded(Expr::Call(18, std::vec![node, index]))?;
            } else if self.eat(".") {
                self.ws();
                let start = self.pos;
                if !self
                    .src
                    .as_bytes()
                    .get(self.pos)
                    .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
                {
                    return Err(self.err("expected field name"));
                }
                self.pos += 1;
                while self
                    .src
                    .as_bytes()
                    .get(self.pos)
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
                {
                    self.pos += 1;
                }
                node = self.bounded(Expr::Select(
                    Box::new(node),
                    self.src[start..self.pos].to_string(),
                ))?;
            } else {
                break;
            }
        }
        Ok(node)
    }
    fn sequence(&mut self, end: &str) -> Result<Vec<Expr>, String> {
        let mut a = Vec::new();
        if self.eat(end) {
            return Ok(a);
        }
        loop {
            a.push(self.expr()?);
            if self.eat(end) {
                return Ok(a);
            }
            self.expect(",")?;
        }
    }
    fn string(&mut self) -> Result<String, String> {
        let out = self.quoted(false)?;
        String::from_utf8(out).map_err(|_| self.err("invalid UTF-8 string"))
    }
    fn quoted(&mut self, bytes: bool) -> Result<Vec<u8>, String> {
        self.expect("\"")?;
        let mut out = Vec::new();
        loop {
            let ch = self.src[self.pos..]
                .chars()
                .next()
                .ok_or_else(|| self.err("unterminated string"))?;
            self.pos += ch.len_utf8();
            match ch {
                '"' => return Ok(out),
                '\\' => {
                    let c = self.src[self.pos..]
                        .chars()
                        .next()
                        .ok_or_else(|| self.err("unterminated string"))?;
                    self.pos += c.len_utf8();
                    let value = match c {
                        'n' => b'\n',
                        'r' => b'\r',
                        't' => b'\t',
                        '"' => b'"',
                        '\\' => b'\\',
                        '0' if bytes => 0,
                        'x' if bytes => {
                            let hex = self
                                .src
                                .as_bytes()
                                .get(self.pos..self.pos + 2)
                                .ok_or_else(|| self.err("invalid hex escape"))?;
                            let digit = |b: u8| (b as char).to_digit(16).map(|n| n as u8);
                            let hi = digit(hex[0]).ok_or_else(|| self.err("invalid hex escape"))?;
                            let lo = digit(hex[1]).ok_or_else(|| self.err("invalid hex escape"))?;
                            self.pos += 2;
                            hi * 16 + lo
                        }
                        _ => return Err(self.err("unsupported escape")),
                    };
                    out.push(value);
                }
                c if c < '\u{20}' => return Err(self.err("raw control character in string")),
                c => {
                    let mut buf = [0; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
            }
        }
    }
    fn primary(&mut self) -> Result<Expr, String> {
        if self.recursion >= 128 {
            return Err(self.err("parser depth limit exceeded"));
        }
        self.recursion += 1;
        let result = self.primary_inner();
        self.recursion -= 1;
        result.and_then(|expr| self.bounded(expr))
    }
    fn primary_inner(&mut self) -> Result<Expr, String> {
        self.ws();
        let rest = &self.src[self.pos..];
        if rest.starts_with("b\"") {
            self.pos += 1;
            return Ok(Expr::Bytes(self.quoted(true)?));
        }
        if rest.starts_with('"') {
            return Ok(Expr::Text(self.string()?));
        }
        if self.eat("(") {
            let e = self.expr()?;
            self.expect(")")?;
            return Ok(e);
        }
        if self.eat("[") {
            return Ok(Expr::List(self.sequence("]")?));
        }
        if self.eat("{") {
            let mut entries = Vec::new();
            if self.eat("}") {
                return Ok(Expr::Map(entries));
            }
            loop {
                self.ws();
                let key = if self.src[self.pos..].starts_with('"') {
                    MapKey::Text(self.string()?)
                } else {
                    let negative = self.eat("-");
                    self.ws();
                    let start = self.pos;
                    while self
                        .src
                        .as_bytes()
                        .get(self.pos)
                        .is_some_and(u8::is_ascii_digit)
                    {
                        self.pos += 1;
                    }
                    if start == self.pos {
                        return Err(self.err("map key must be a text or integer literal"));
                    }
                    let n: i64 = self.src[start..self.pos]
                        .parse()
                        .map_err(|_| self.err("integer literal out of i32 range"))?;
                    MapKey::Int(
                        i32::try_from(if negative { -n } else { n })
                            .map_err(|_| self.err("integer literal out of i32 range"))?,
                    )
                };
                self.expect(":")?;
                let value = self.expr()?;
                entries.push((key, value));
                if self.eat("}") {
                    break;
                }
                self.expect(",")?;
            }
            return Ok(Expr::Map(entries));
        }
        self.ws();
        let start = self.pos;
        if self
            .src
            .as_bytes()
            .get(self.pos)
            .is_some_and(u8::is_ascii_digit)
        {
            while self
                .src
                .as_bytes()
                .get(self.pos)
                .is_some_and(u8::is_ascii_digit)
            {
                self.pos += 1;
            }
            return Ok(Expr::Int(
                self.src[start..self.pos]
                    .parse()
                    .map_err(|_| self.err("integer literal out of i32 range"))?,
            ));
        }
        if self
            .src
            .as_bytes()
            .get(self.pos)
            .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        {
            self.pos += 1;
            while self
                .src
                .as_bytes()
                .get(self.pos)
                .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
            {
                self.pos += 1;
            }
            let name = &self.src[start..self.pos];
            if self.eat("(") {
                let id = match name {
                    "size" => 19,
                    "startsWith" => 20,
                    "endsWith" => 21,
                    "contains" => 22,
                    "call" => 23,
                    "has" => 24,
                    _ => return Err(self.err(&format!("unknown function {name}"))),
                };
                let args = self.sequence(")")?;
                if id == 23
                    && (args.len() != 3
                        || !matches!(args.first(), Some(Expr::Int(_)))
                        || !matches!(args.get(1), Some(Expr::Int(_))))
                {
                    return Err(self.err(concat!(
                        "call: component and method must be integer literals ",
                        "(and exactly three arguments required)"
                    )));
                }
                return Ok(Expr::Call(id, args));
            }
            return match name {
                "true" => Ok(Expr::Bool(true)),
                "false" => Ok(Expr::Bool(false)),
                "null" => Ok(Expr::Null),
                _ => self
                    .schema
                    .0
                    .iter()
                    .find(|(n, _)| n == name)
                    .map(|(_, n)| Expr::Ident(*n))
                    .ok_or_else(|| self.err(&format!("unknown identifier {name}"))),
            };
        }
        Err(self.err("unsupported syntax or expected expression"))
    }
}
/// Translate CEL text into the evaluator's definite-length CBOR AST.
/// Input is bounded by MAX_INPUT_BYTES, parser recursion by 128 entries,
/// and the generated AST by 128 levels. Invalid or excessive input returns an error.
pub fn translate(src: &str, schema: &Schema) -> Result<Vec<u8>, String> {
    if src.len() > crate::MAX_INPUT_BYTES {
        return Err("expression input exceeds MAX_INPUT_BYTES".into());
    }
    let mut p = Parser {
        src,
        pos: 0,
        schema,
        recursion: 0,
    };
    let e = p.expr()?;
    p.ws();
    if p.pos != src.len() {
        return Err(p.err("unsupported syntax or trailing input"));
    }
    // CBOR needs at most a small constant overhead per source byte.
    let capacity = src
        .len()
        .checked_mul(32)
        .and_then(|n| n.checked_add(128))
        .ok_or_else(|| p.err("expression too large"))?;
    let mut output = std::vec![0;capacity];
    let mut w = Writer::new(&mut output);
    e.emit(&mut w);
    let len = w
        .finish()
        .ok_or_else(|| p.err("encoded expression too large"))?
        .len();
    output.truncate(len);
    Ok(output)
}

#[cfg(all(test, feature = "translate"))]
mod tests {
    use super::*;
    use crate::{Invoke, Limits, check, eval};
    struct Fake;
    impl Invoke for Fake {
        fn invoke<'a>(
            &mut self,
            c: i32,
            m: i32,
            p: &[u8],
            out: &'a mut [u8],
        ) -> Result<&'a [u8], i32> {
            assert_eq!((c, m), (52, 1));
            assert_eq!(p, &[0xa0]);
            out[0] = 0xf6;
            Ok(&out[..1])
        }
    }
    fn run(src: &str) -> Vec<u8> {
        let schema = Schema::parse("v=1\nm=2\nparams=3").unwrap();
        let ast = translate(src, &schema).unwrap();
        check(&ast, &Limits::default()).unwrap();
        let mut vars = [0; 128];
        let mut w = Writer::new(&mut vars);
        w.map(3)
            .uint(1)
            .array(2)
            .int(42)
            .int(7)
            .uint(2)
            .map(1)
            .text("k")
            .int(9)
            .uint(3)
            .map(0);
        let vars = w.finish().unwrap();
        let mut scratch = [0; 8192];
        let mut out = [0; 1024];
        eval(
            &ast,
            vars,
            &mut scratch,
            &mut out,
            Limits::default(),
            &mut Fake,
        )
        .unwrap()
        .to_vec()
    }
    macro_rules! yes {
        ($name:ident,$src:expr) => {
            #[test]
            fn $name() {
                assert_eq!(run($src), [0xf5]);
            }
        };
    }
    yes!(precedence, "1+2*3==7");
    yes!(parentheses, "2*(3-1)==4");
    yes!(associativity, "10-3-2==5");
    yes!(unary, "-3 + 4 == 1 && !true==false");
    yes!(ternary, "true ? 1==1 : false");
    yes!(membership_list, "2 in [1,2,3]");
    yes!(membership_text, "\"bc\" in \"abcd\"");
    yes!(text_equality, "\"hello\" == \"hello\"");
    yes!(list_equality, "[1,[2]] == [1,[2]]");
    yes!(size, "size([1,2])==2");
    yes!(starts, "startsWith(\"abc\",\"ab\")");
    yes!(ends, "endsWith(\"abc\",\"bc\")");
    yes!(contains, "contains(\"abc\",\"b\")");
    yes!(null, "null==null");
    yes!(list_index, "v[0]==42");
    yes!(map_index, "m[\"k\"]==9");
    yes!(bytes, "b\"a\\n\" == \"a\\n\"");
    yes!(call, "call(52,1,params)==null");
    yes!(signed_min, "-2147483648 < 0");
    yes!(dot_select, "m.k == 9");
    yes!(
        map_construction,
        "{1: v[0], \"inner\": {\"x\": m.k}}.inner.x == 9"
    );
    yes!(presence, "!has(m.missing) && has(m.k)");
    yes!(logical_absorption, "m.missing || true");
    #[test]
    fn selection_map_and_presence_translation() {
        let schema = Schema::parse("event=1\nargs=2").unwrap();
        for src in [
            "event.method == args.x",
            "call(52,1,{1: args.x, \"nested\": {\"m\": event.method}})",
            "has(args.x) || false",
        ] {
            assert!(translate(src, &schema).is_ok(), "{src}");
        }
    }
    #[test]
    fn errors() {
        for (src, msg) in [
            ("unknown", "unknown identifier"),
            ("foo(1)", "unknown function"),
            (
                "call(v,1,params)",
                "call: component and method must be integer literals",
            ),
            ("1.2", "expected field name"),
            ("2147483648", "i32"),
            ("\"abc", "unterminated string"),
        ] {
            let err = translate(src, &Schema::parse("v=1\nparams=3").unwrap())
                .err()
                .unwrap();
            assert!(err.contains(msg), "{src}: {err}");
            assert!(err.starts_with("error at offset "));
        }
    }
    #[test]
    fn schema_parse() {
        assert_eq!(
            Schema::parse("# comment\n v = 12 # tag\n").unwrap().0,
            std::vec![("v".to_string(), 12)]
        );
        assert!(Schema::parse("x=no").is_err());
    }
}
