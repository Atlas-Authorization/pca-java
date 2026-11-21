package net.atlasauth.pca.sandbox;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * The WebAssembly host contract. The only import module a sandboxed tool may name, and the only functions in it; anything else is
 * ambient authority. Running a module (a WebAssembly engine, a worker, a wasmtime child process) is not part of this port: the JDK
 * carries no WebAssembly runtime, so the host, the component runner and the HTTP proxy server stay with the other SDKs.
 */
public final class Host {
    private Host() {}

    public static final String IMPORT_MODULE = "pca:act";
    public static final List<String> ALLOWED_IMPORTS = Collections.unmodifiableList(Arrays.asList("invoke", "handle_count", "handle_verb"));
}
