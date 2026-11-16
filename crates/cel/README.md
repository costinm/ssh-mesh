# micro-cel

A small CEL-inspired expression evaluator for embedded and host applications. It
uses a compact CBOR expression format, not the standard CEL protobuf format.
The crate is unpublished (`publish = false`); the program format and XIP
integration are experimental, version 1, and are not a stable ABI.

| Feature | Use |
| --- | --- |
| default | `no_std`, heap-free one-shot evaluation |
| `translate` | Host expression translator and `celc` |
| `program` | `no_std` + `alloc` owned cooperative sequences |
| `program-host` | TOML program compiler and local simulation (includes `translate` and `program`) |
| `service` | `no_std` + `alloc` program integration (includes `program`) |

For a repository-relative dependency, adjust the path to suit your project:

```toml
[dependencies]
micro-cel = { path = "../cel", features = ["translate"] }
```

Translate a host expression into CBOR:

```rust
use micro_cel::host::translate::{translate, Schema};

let schema = Schema::parse("count = 1")?;
let expression = translate("count + 1", &schema)?;
assert!(!expression.is_empty());
# Ok::<(), String>(())
```

From `crates/cel`, compile an expression or compile and simulate programs:

```sh
cargo run --features translate --bin celc -- '1 + 2'
cargo run --features program-host --bin celc -- --program examples/programs/basic.toml -o program.cbor
cargo run --features program-host --bin celc -- --program examples/programs/interleaved.toml --run --responses examples/programs/responses.toml
```

Without `-o`, `celc` prints hex, or base64 with `--base64`; `-o` writes raw
CBOR. Expression input also supports `-s schema.txt` and `-f expression.cel`.
Program input is TOML on the host; devices receive compiled CBOR. Simulation
uses virtual milliseconds and configured mock responses, not network calls.
See the [program examples](examples/programs/).

## Programs and expressions

Each program list has an isolated context and ordered rules. Lists cooperate:
a call waits for its actual response while other lists can progress; `set`
updates the list's context, `break_if` ends that list, and `after_ms` yields
until a monotonic deadline. A failure ends its list without rolling back prior
calls or updates. The older XIP expression method instead sends calls
fire-and-forget and substitutes null; use programs to consume responses.

The supported subset includes i32 integers, booleans, null, text, bytes,
lists, maps, selection, indexing, arithmetic, comparisons, logical operators,
ternaries, and selected functions. String matching is byte-oriented; `size(text)` counts Unicode scalar values,
while `size(bytes)` counts bytes. Byte literals support `\0` and `\xHH` as well as
common escapes; text literals reject binary escapes. Doubles, comprehensions,
and most CEL macros and types are unsupported. CBOR null is supported but
CBOR undefined is not. Host defaults and smaller device limits bound inputs,
containers, depth, nodes, and program resources; work is not fully metered.
The translator also caps parser recursion and generated AST depth at 128.
One-shot evaluation stays heap-free with every feature combination.
Mixed-type equality returns false, except that text and bytes with identical
contents compare equal. As a subset extension, `in` on text or bytes tests for
a substring; use list/map membership for CEL-style containment.

See the [component RPC contract](ABI.md) and [encoding reference](EXPRESSION-FORMAT.md).
The ESP XIP module implementation is maintained separately in esp-xip-modules.
