# `cel` component RPC API (52)

The experimental component is version 1; its contract may change. The ESP XIP implementation is provided separately by esp-xip-modules. It has no
mandatory dedicated port. Address component 52 and the method through an
existing runtime transport and envelope. This does not define an HTTP endpoint;
use HTTP only where an existing runtime or gateway actually provides it.
Payloads and envelope values are CBOR, not JSON.

## Requests and envelopes

An RPC envelope uses integer keys `{1: component, 2: method, 3: token,
5: parameters}`. A response echoes component, method and token and contains
exactly one of key 6 (result, a CBOR value) or key 7 (integer error). Tokens
must fit a positive signed i64. For calls made by CEL, program tokens reserve
bit 62; legacy tokens occupy the namespace below it. Invalid, mismatched,
duplicate or expired responses do not consume a live continuation. Do not
interpret a response as a new replyable request merely because it has a token.

Compile expressions on a trusted host, for example from `crates/cel`:

```sh
cargo run --features translate --bin celc -- '1 + 2'
cargo run --features program-host --bin celc -- --program examples/programs/basic.toml -o program.cbor
```

The first command prints encoded CBOR as hex. In the following diagnostic
notation `EXPRESSION` means the **decoded CBOR item** from that output, not a
literal string, hex text, or CBOR byte string. Insert the item as field 1:

```text
{1: 52, 2: 1, 3: 42, 5: {1: EXPRESSION, 2: {}}}
```

Encode the whole envelope as CBOR before sending. A successful reply has key 6
containing the result; an error has key 7 instead. For method 5, the decoded
CBOR item from `program.cbor` is the entire key 5 parameters value, not a byte
string containing the file. The compiled expression and program are opaque to
ordinary RPC clients; the [encoding reference](EXPRESSION-FORMAT.md) is for
experimental compiler interoperability.

## 1. Evaluate

Request parameters are `{1: expression, 2: variables, 3: limits}`. Fields 1
and 2 are required; variables is a CBOR map keyed by the host schema's unsigned
tags. Field 3 is optional `{1: maxDepth, 2: maxNodes}`. The response result is
the evaluated CBOR value. External calls are sent asynchronously and evaluate
to null immediately; their eventual responses arrive separately via method 3.
This legacy behavior does not wait for a remote result.

## 2. Unsupported

The old check operation is not supported and returns an error.

## 3. Legacy response event

An outgoing event to the application carries `{1: component, 2: method,
3: token, 6: result}` or key 7 integer error instead of key 6. It is not the
result of the original expression evaluation. Up to four legacy calls may be
pending; the default timeout is 10 seconds.

## 4. Evaluate policy

Uses the same parameters as method 1, but requires a boolean result and
rejects an actual external call during evaluation. A consumer making an
access-control decision must fail closed on every error, non-boolean result,
timeout or unavailable service; the component does not provide authorization
identity binding. Validate the complete expression and all branches on a trusted
host, including checking policy purity: device execution alone does not inspect
unselected branches. Structural decoding is not full semantic validation.

## 5. Start program

The request data itself is the compiled CBOR program item, not a wrapper map
or CBOR byte string. A null result means the program was admitted, **not** that
it completed. Only one program can be active. Lists execute cooperatively;
unlike method 1, program calls wait for correlated responses or timeouts.
Admission checks every expression, including unselected branches, for supported
AST structure, arity, static call targets, and expression resource bounds.
Host compilation performs the same semantic checks before deployment.
Call expiry uses the earlier of the program and transport timeout; both runner
and service correlation state use that deadline.

## 6. Poll / advance program

The response result is `{1: state}`: 0 means idle or finished, 1 means progress,
and 2 means waiting, with `{2: untilMs}` giving the monotonic millisecond
deadline. A poll advances execution and is also a manual recovery path if an
alarm fails. Admission or progress is not completion.

## 7. Program list completion event

The outgoing application event is `{1: listIndex, 2: discriminator, 3: value}`.
Discriminator 1 means the value is the result; 2 means it is an integer error.
Failed delivery is retained for retry. Each list can finish or fail separately.

## 8. Internal alarm

Reserved for the module's internal alarm; it is not a public application call.

## Values, limits and trust

CBOR byte strings are values distinct from text and from raw encoded CBOR items.
Null (`f6`) is a supported value; undefined (`f7`) is not null and is rejected.
This also applies inside result field 6; field 7 is an integer error, never an
alternative spelling of null. Errors include malformed input, unsupported
operations, resource exhaustion, type and invocation failures.

Current module defaults and maxima for expression depth and nodes are 8 and
512. The device program profile allows 4 lists, 4 pending calls, 64 rules,
16384 input bytes, 1536 context bytes, 256 bytes per value and 8 frames;
data nesting is limited to 8. Limits and default timeout are defined by the
current device configuration in `modules/mod_cel/src/lib.rs` and shared
program defaults; resource accounting does not meter all comparison and scan
work. These limits are not an authorization boundary. Authentication and
identity binding are not wired into this component.
