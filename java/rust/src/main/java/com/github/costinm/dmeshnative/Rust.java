package com.github.costinm.dmeshnative;

import java.io.File;
import java.net.URI;

/**
 * Native library loader for the DMesh JNI bindings.
 *
 * <p>Discovers {@code libdmesh.so} using the following search order:
 * <ol>
 *   <li>Relative to the running JAR: {@code ../lib/<arch>/libdmesh.so}
 *       (production layout: {@code /opt/ssh-mesh/bin/dmesh.jar} →
 *       {@code /opt/ssh-mesh/lib/x86_64/libdmesh.so})</li>
 *   <li>Common Cargo workspace locations for local development</li>
 *   <li>{@code System.loadLibrary("dmesh")} as a final fallback
 *       (respects {@code java.library.path})</li>
 * </ol>
 *
 * <p>Architecture subdirectory names follow Android conventions:
 * {@code x86_64}, {@code arm64-v8a}, {@code armeabi-v7a}, {@code x86}.
 */
public class Rust {

    private static boolean loaded = false;

    /**
     * Map JVM {@code os.arch} values to Android/NDK directory names.
     */
    private static String nativeArch() {
        String arch = System.getProperty("os.arch", "");
        switch (arch) {
            case "amd64":
            case "x86_64":
                return "x86_64";
            case "aarch64":
                return "arm64-v8a";
            case "arm":
                return "armeabi-v7a";
            case "x86":
            case "i386":
            case "i686":
                return "x86";
            default:
                return arch;
        }
    }

    public synchronized static void loadLibrary() {
        if (loaded) return;

        String arch = nativeArch();

        // 1. Try relative to the JAR location: <jar_dir>/../lib/<arch>/libdmesh.so
        try {
            URI jarUri = Rust.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI();
            File jarFile = new File(jarUri);
            File jarDir = jarFile.isFile() ? jarFile.getParentFile() : jarFile;

            // Production layout: bin/dmesh.jar → lib/<arch>/libdmesh.so
            File libFromJar = new File(jarDir, "../lib/" + arch + "/libdmesh.so");
            if (libFromJar.exists()) {
                System.load(libFromJar.getCanonicalPath());
                loaded = true;
                return;
            }

            // Also check same directory (flat layout)
            File libSameDir = new File(jarDir, "libdmesh.so");
            if (libSameDir.exists()) {
                System.load(libSameDir.getCanonicalPath());
                loaded = true;
                return;
            }
        } catch (Exception e) {
            // Ignore — fall through to workspace paths
        }

        // 2. Try common Cargo workspace locations (for local development)
        String[] devPaths = {
                "target/release/libdmesh.so",
                "target/debug/libdmesh.so",
                "target/x86_64-unknown-linux-gnu/release/libdmesh.so",
                "target/x86_64-unknown-linux-gnu/debug/libdmesh.so",
                "target/lib/" + arch + "/libdmesh.so",
        };

        for (String path : devPaths) {
            try {
                File f = new File(path);
                if (f.exists()) {
                    System.load(f.getAbsolutePath());
                    loaded = true;
                    return;
                }
            } catch (UnsatisfiedLinkError e) {
                // Continue to next path
            }
        }

        // 3. Fallback to System.loadLibrary (respects java.library.path / LD_LIBRARY_PATH)
        System.loadLibrary("dmesh");
        loaded = true;
    }

    public static Rust load() {
        loadLibrary();
        return new Rust();
    }
}