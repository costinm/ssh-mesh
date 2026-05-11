package com.github.costinm.dmeshnative;

public class Rust {

    private static boolean loaded = false;

    public synchronized static void loadLibrary() {
        if (loaded) return;

        // Try common workspace locations relative to repo root
        String[] paths = {
            "target/release/libdmesh.so",
            "target/debug/libdmesh.so",
            "target/x86_64-unknown-linux-gnu/release/libdmesh.so",
            "target/x86_64-unknown-linux-musl/release/libdmesh.so"
        };
        
        for (String path : paths) {
            try {
                System.load(new java.io.File(path).getAbsolutePath());
                loaded = true;
                return;
            } catch (UnsatisfiedLinkError e) {
                // Continue to next path
            }
        }
        
        // Fallback to System.loadLibrary
        System.loadLibrary("dmesh");
        loaded = true;
    }

    public static Rust load() {
        loadLibrary();
        return new Rust();
    }
    public static native void invokeCallbackViaJNI(Callback c);

    public static class Callback {
        public void callback(String s) {
            System.out.println("Callback received: " + s);
        };
    }

    public static void main(String[] args) {
        try {
            load(); // Try loading from standard target paths
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Could not load native library: " + e.getMessage());
            return;
        }
        invokeCallbackViaJNI(new Callback());
    }
}