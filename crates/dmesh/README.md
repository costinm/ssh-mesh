# DMesh JNI (Android)

This 'mesh' project was originally an Android experiment based on 
VPN and peer-to-peer communication using Wifi AP and later NaN/Aware. Code was mostly java with gVisor or LWIP stacks for intercepting the streams. Eventually I moved to Istio and switched to a similar mesh - using iptables instead of TUN and sidecars.

I kept working on the original Android, porting concepts from Istio
and eventually replacing almost all java with Go - and now Rust.

Android Wifi and most interesting features are available in Java and
JNI as well as Binder interfaces (unsupported in many cases, but 
that's what Java is calling). For Rust to work on Android it does 
need some interactions - and JNI is the common path.

## Alternative to JNI

JNI problem is garbage collection and the associated overhead/complexity. One approach I used long ago in Tomcat was to just have
a pair of methods - passing along byes or file descriptors. It still
need a call from C to java. Later with JNI and 'off heap' this 
become simpler, with all data needed on both side kept off-heap.

In more recent years - WASM (and Zig) explicitly have the concept of multiple 'memories', each with its own allocation and ownership.
Rust to some extent has a similar lifecycle and features.

## Simpler alternative

Using a pipe/socket may be the simplest option for low volume data - with shared memory for the bulk data. Need to find a format that is easy to read from java and rust - flat buffers or similar, with a ring buffer library that works in both. In this mode JNI will be no different from IPC or binder - which is likely a good thing based on past perf testing with JNI, where
the overhead tended to be higher than simpler IPC.

## Plugins instead of FFI

Java/Python/etc use the FFI pattern - "C" functions are exported
and args are 'marshalled' to C or lang frames and internal type repr.

Another approach is to treat it as 'plugin', with a fixed interface.
This is similar to 'pipe' - with with more methods exposed and stucture. Instead of 'open/close/read/write' for a stream, it would
also have specialized methods that otherwise would be marshalled as messages in the 'pipe' model ( which should remain supported and
mapped to the new messages !).

Essentially each 'module' can be:
- linked in (same language)
- loaded from a .so (JNI/FFI)
- run as a standalone process in a sandbox (via mesh-init or other ways)
- compile to wasm and run in a different sandbox








