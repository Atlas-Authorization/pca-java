package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.IntFunction;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/**
 * QRNG entropy as an ADD to key generation, never a trust dependency: every seed is {@code HKDF-SHA256(local CSPRNG || quantum)}, so a
 * hostile quantum source cannot lower the result below the local CSPRNG. Quantum bytes are never used raw. This is not a quantum root of
 * trust and makes no post-quantum claim. The library carries no network client: the HTTP source takes an injected transport.
 */
public final class Entropy {
    private Entropy() {}

    /** HKDF-SHA256 output cap: 255 * 32. */
    public static final int MAX_HKDF_OUTPUT = 255 * 32;
    /** Minimum local CSPRNG input the combiner accepts. */
    public static final int MIN_LOCAL_BYTES = 16;
    public static final int DEFAULT_SEED_BYTES = 32;
    public static final int DEFAULT_MAX_QRNG_BYTES = 1024;
    public static final int DEFAULT_TIMEOUT_MS = 5000;

    private static final String MIX_LABEL = "atlas-pca/entropy/mix/v1";
    private static final byte[] MIX_SALT = "atlas-pca/entropy/salt/v1".getBytes(StandardCharsets.UTF_8);

    /** A source of quantum random bytes: {@code fetch(n)} returns EXACTLY n bytes or throws. */
    public interface QrngSource {
        /** Short, log-safe identifier (never contains secrets). */
        String name();
        byte[] fetch(int numBytes) throws Exception;
    }

    /** A source that always fails with {@code QRNG unavailable: <reason>}. */
    public static final class NullQrngSource implements QrngSource {
        private final String reason;
        public NullQrngSource() { this("no QRNG source configured"); }
        public NullQrngSource(String reason) { this.reason = reason; }
        @Override public String name() { return "null-qrng"; }
        @Override public byte[] fetch(int numBytes) { throw new IllegalStateException("QRNG unavailable: " + reason); }
    }

    /** The shared unavailable source; a null reason means the default one. */
    public static QrngSource unavailableSource(String reason) { return reason == null ? new NullQrngSource() : new NullQrngSource(reason); }

    // ---- SP 800-90B 4.4 continuous health tests ----

    /** Health-test parameters: {@code h} = assessed min-entropy per byte (1..8), {@code window} = adaptive-proportion window. */
    public static final class HealthTestOptions {
        public final double h;
        public final double window;
        public HealthTestOptions(double h, double window) { this.h = h; this.window = window; }
        public HealthTestOptions() { this(8, 512); }
    }

    /** {@code test} is "repetition-count" or "adaptive-proportion" when not ok. */
    public record HealthVerdict(boolean ok, String test) {}

    /** SP 800-90B 4.4.1 cutoff: 1 + ceil(20 / h) (a double: h = 0 gives Infinity). */
    public static double repetitionCutoff(double h) { return 1 + Math.ceil(20 / h); }

    /** SP 800-90B 4.4.2 cutoff: 1 + CRITBINOM(w, 2^-h, 1 - 2^-20). StrictMath.pow is fdlibm, as V8's pow is. */
    public static double proportionCutoff(double h, double w) {
        double p = StrictMath.pow(2, -h);
        double target = 1 - StrictMath.pow(2, -20);
        double pmf = StrictMath.pow(1 - p, w);
        double cdf = pmf;
        int k = 0;
        while (cdf < target && k < w) {
            pmf *= ((w - k) / (k + 1)) * (p / (1 - p));
            k++;
            cdf += pmf;
        }
        return 1 + k;
    }

    public static HealthVerdict healthTestBytes(byte[] bytes) { return healthTestBytes(bytes, 8, 512); }

    /** Repetition-count and adaptive-proportion over one buffer; fails closed on bad parameters and on an empty buffer. */
    public static HealthVerdict healthTestBytes(byte[] bytes, double h, double window) {
        Objects.requireNonNull(bytes, "bytes");
        boolean badWindow = Double.isNaN(window) || Double.isInfinite(window) || window != Math.rint(window) || window < 2;
        if (!(h >= 1 && h <= 8) || badWindow || bytes.length == 0) return new HealthVerdict(false, "repetition-count");
        double rc = repetitionCutoff(h);
        int run = 1;
        for (int i = 1; i < bytes.length; i++) {
            run = bytes[i] == bytes[i - 1] ? run + 1 : 1;
            if (run >= rc) return new HealthVerdict(false, "repetition-count");
        }
        int w = (int) Math.min(window, bytes.length);
        double ac = proportionCutoff(h, w);
        for (int start = 0; start + w <= bytes.length; start += w) {
            byte first = bytes[start];
            int count = 0;
            for (int i = start; i < start + w; i++) if (bytes[i] == first) count++;
            if (count >= ac) return new HealthVerdict(false, "adaptive-proportion");
        }
        return new HealthVerdict(true, null);
    }

    // ---- parsers ----

    private static boolean isByte(Object v) {
        Double d = IntentJs.num(v);
        return d != null && !Double.isNaN(d) && !Double.isInfinite(d) && d == Math.rint(d) && d >= 0 && d <= 255;
    }

    /** ANU / hardware-REST JSON shape {@code {success?: boolean, data: number[]}}, each element a 0..255 integer. */
    public static byte[] parseAnuUint8(Object body) {
        if (!(body instanceof Map)) throw new IllegalArgumentException("QRNG: response body is not a JSON object");
        Map<?, ?> rec = (Map<?, ?>) body;
        if (rec.containsKey("success") && !Boolean.TRUE.equals(rec.get("success"))) throw new IllegalArgumentException("QRNG: response reports success=false");
        if (!(rec.get("data") instanceof List)) throw new IllegalArgumentException("QRNG: response `data` is not an array");
        List<?> data = (List<?>) rec.get("data");
        byte[] out = new byte[data.size()];
        for (int i = 0; i < out.length; i++) {
            if (!isByte(data.get(i))) throw new IllegalArgumentException("QRNG: response data[" + i + "] is not a 0..255 integer");
            out[i] = (byte) (int) IntentJs.num(data.get(i)).doubleValue();
        }
        return out;
    }

    private static int hexDigit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    /** A flat hex string; refuses odd length and non-hex characters. */
    public static byte[] parseHex(String text) {
        Objects.requireNonNull(text, "text");
        if (text.length() % 2 != 0) throw new IllegalArgumentException("QRNG: malformed hex payload");
        byte[] out = new byte[text.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int a = hexDigit(text.charAt(2 * i)), b = hexDigit(text.charAt(2 * i + 1));
            if (a < 0 || b < 0) throw new IllegalArgumentException("QRNG: malformed hex payload");
            out[i] = (byte) (a * 16 + b);
        }
        return out;
    }

    private static int b64Digit(char c) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    }

    /**
     * Standard base64 as the WHATWG forgiving-base64 decode ({@code atob}) reads it, after the same alphabet check: up to two trailing
     * '=' are stripped only when the length is a multiple of 4, a remainder of 1 mod 4 is invalid, missing padding is accepted and
     * non-canonical trailing bits are dropped.
     */
    public static byte[] parseBase64(String text) {
        Objects.requireNonNull(text, "text");
        int end = text.length();
        int pad = 0;
        while (end > 0 && text.charAt(end - 1) == '=') { end--; pad++; }
        if (pad > 2) throw new IllegalArgumentException("QRNG: malformed base64 payload");
        for (int i = 0; i < end; i++) if (b64Digit(text.charAt(i)) < 0) throw new IllegalArgumentException("QRNG: malformed base64 payload");
        int n = text.length();
        if (pad > 0 && n % 4 != 0) throw new IllegalArgumentException("QRNG: malformed base64 payload");
        if (end % 4 == 1) throw new IllegalArgumentException("QRNG: malformed base64 payload");
        byte[] out = new byte[end * 6 / 8];
        int acc = 0, bits = 0, o = 0;
        for (int i = 0; i < end; i++) {
            acc = (acc << 6) | b64Digit(text.charAt(i));
            bits += 6;
            if (bits >= 8) { bits -= 8; out[o++] = (byte) (acc >> bits); acc &= (1 << bits) - 1; }
        }
        return out;
    }

    // ---- combiner ----

    static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        HKDFBytesGenerator g = new HKDFBytesGenerator(new SHA256Digest());
        g.init(new HKDFParameters(ikm, salt, info));
        byte[] out = new byte[length];
        g.generateBytes(out, 0, length);
        return out;
    }

    /** {@code mixEntropy} with the local length as output length and no context. */
    public static byte[] mixEntropy(byte[] local, byte[] quantum) { return mixEntropy(local, quantum, null, null); }

    /**
     * Robust randomness combiner: {@code HKDF-SHA256(ikm = len(local) || len(quantum) || local || quantum, salt, info = label || context || len)}.
     * Fails closed on a local input under 16 bytes or a length outside 1..8160; the quantum input may be empty. A null or empty
     * context adds nothing to the label; a null length means the local length.
     */
    public static byte[] mixEntropy(byte[] local, byte[] quantum, Integer length, String context) {
        Objects.requireNonNull(local, "local");
        Objects.requireNonNull(quantum, "quantum");
        if (local.length < MIN_LOCAL_BYTES) throw new IllegalArgumentException("mixEntropy: local CSPRNG must be >= " + MIN_LOCAL_BYTES + " bytes (fail-closed)");
        int len = length == null ? local.length : length;
        if (len <= 0 || len > MAX_HKDF_OUTPUT) throw new IllegalArgumentException("mixEntropy: length must be an integer in 1.." + MAX_HKDF_OUTPUT);
        byte[] ikm = new byte[8 + local.length + quantum.length];
        putU32(ikm, 0, local.length);
        putU32(ikm, 4, quantum.length);
        System.arraycopy(local, 0, ikm, 8, local.length);
        System.arraycopy(quantum, 0, ikm, 8 + local.length, quantum.length);
        byte[] label = Json.utf8(context != null && !context.isEmpty() ? MIX_LABEL + "/" + context : MIX_LABEL);
        byte[] info = new byte[label.length + 4];
        System.arraycopy(label, 0, info, 0, label.length);
        putU32(info, label.length, len);
        byte[] out = hkdfSha256(ikm, MIX_SALT, info, len);
        java.util.Arrays.fill(ikm, (byte) 0);
        return out;
    }

    private static void putU32(byte[] b, int o, int v) {
        b[o] = (byte) (v >>> 24); b[o + 1] = (byte) (v >>> 16); b[o + 2] = (byte) (v >>> 8); b[o + 3] = (byte) v;
    }

    // ---- secureSeed ----

    /** Options for {@link #secureSeed}. Null fields take the reference defaults. */
    public static final class SecureSeedOptions {
        /** Output seed length (default 32). */
        public Integer length;
        /** QRNG source for best-effort quantum entropy; null = CSPRNG only. */
        public QrngSource source;
        /** Quantum bytes to request (default max(32, length)). */
        public Integer quantumBytes;
        /** Local CSPRNG bytes to draw (default max(32, length)). */
        public Integer localBytes;
        public String context;
        /** Throw {@link EntropyError} (quantum_required) instead of falling back to CSPRNG-only. */
        public boolean requireQuantum;
        /** SP 800-90B tests on every quantum buffer; null disables them (tests only). */
        public HealthTestOptions healthTest = new HealthTestOptions();
        /** Observability hook when the QRNG is skipped or fails; its own exceptions are swallowed. */
        public Consumer<Throwable> onQrngError;
        /** Inject a CSPRNG (tests); must return exactly n bytes. Default: the platform CSPRNG. */
        public IntFunction<byte[]> randomBytesImpl;

        SecureSeedOptions copy() {
            SecureSeedOptions o = new SecureSeedOptions();
            o.length = length; o.source = source; o.quantumBytes = quantumBytes; o.localBytes = localBytes; o.context = context;
            o.requireQuantum = requireQuantum; o.healthTest = healthTest; o.onQrngError = onQrngError; o.randomBytesImpl = randomBytesImpl;
            return o;
        }
    }

    /** {@code source} is the source name, or null when none was used. */
    public record SecureSeedResult(byte[] seed, boolean usedQuantum, int quantumByteCount, String source) {}

    private static final SecureRandom RNG = new SecureRandom();

    private static byte[] drawLocal(IntFunction<byte[]> impl, int n) {
        byte[] b;
        if (impl != null) b = impl.apply(n);
        else { b = new byte[n]; RNG.nextBytes(b); }
        if (b == null || b.length != n) throw new IllegalStateException("secureSeed: local CSPRNG did not return the requested bytes (fail-closed)");
        return b;
    }

    /**
     * {@code mixEntropy(CSPRNG, best-effort QRNG)}. A missing, failing, slow or adversarial QRNG never blocks and never lowers the seed
     * below CSPRNG strength: it falls back to CSPRNG-only (usedQuantum false). The only throws are configuration errors, a misbehaving
     * local CSPRNG, and {@code requireQuantum} without usable quantum bytes.
     */
    public static SecureSeedResult secureSeed(SecureSeedOptions opts) {
        int length = opts.length == null ? DEFAULT_SEED_BYTES : opts.length;
        if (length <= 0 || length > MAX_HKDF_OUTPUT) throw new IllegalArgumentException("secureSeed: length must be an integer in 1.." + MAX_HKDF_OUTPUT);
        int localBytes = opts.localBytes == null ? Math.max(DEFAULT_SEED_BYTES, length) : opts.localBytes;
        if (localBytes < MIN_LOCAL_BYTES) throw new IllegalArgumentException("secureSeed: localBytes must be an integer >= " + MIN_LOCAL_BYTES);
        int quantumBytes = opts.quantumBytes == null ? Math.max(DEFAULT_SEED_BYTES, length) : opts.quantumBytes;
        if (quantumBytes <= 0) throw new IllegalArgumentException("secureSeed: quantumBytes must be a positive integer");

        byte[] local = drawLocal(opts.randomBytesImpl, localBytes);
        byte[] quantum = new byte[0];
        boolean used = false;
        String sourceName = null;
        QrngSource source = opts.source;
        if (source != null) {
            sourceName = source.name();
            try {
                byte[] q = source.fetch(quantumBytes);
                if (q == null || q.length != quantumBytes) {
                    throw new IllegalStateException("QRNG: source returned " + (q == null ? "non-bytes" : String.valueOf(q.length)) + ", expected " + quantumBytes);
                }
                if (opts.healthTest != null) {
                    HealthVerdict v = healthTestBytes(q, opts.healthTest.h, opts.healthTest.window);
                    if (!v.ok()) throw new EntropyError("health_test_failed", "QRNG: " + (v.test() == null ? "health" : v.test()) + " test failed; source rejected");
                }
                quantum = q;
                used = true;
            } catch (Exception err) {
                used = false;
                quantum = new byte[0];
                if (opts.onQrngError != null) {
                    try { opts.onQrngError.accept(err); } catch (RuntimeException swallowed) { /* observability must never break key generation */ }
                }
            }
        }
        if (opts.requireQuantum && !used) {
            java.util.Arrays.fill(local, (byte) 0);
            throw new EntropyError("quantum_required", "secureSeed: quantum entropy is required but was not obtained (fail-closed)");
        }
        byte[] seed = mixEntropy(local, quantum, length, opts.context);
        java.util.Arrays.fill(local, (byte) 0);
        return new SecureSeedResult(seed, used, used ? quantum.length : 0, sourceName);
    }

    /** An Ed25519 key pair whose secret is a {@link #secureSeed}. */
    public record EntropyKeyPair(byte[] secretKey, byte[] publicKey, boolean usedQuantum) {}

    /**
     * Ed25519 key pair whose 32-byte secret is {@code secureSeed} (CSPRNG mixed with a health-tested QRNG). A caller length is ignored; a
     * null context becomes "ed25519-key", an explicit empty one stays empty. Honors requireQuantum.
     */
    public static EntropyKeyPair generateKeyPairWithEntropy(SecureSeedOptions opts) {
        SecureSeedOptions o = opts.copy();
        o.length = 32;
        if (o.context == null) o.context = "ed25519-key";
        SecureSeedResult r = secureSeed(o);
        return new EntropyKeyPair(r.seed(), Keys.edFromSeed(r.seed()).pub, r.usedQuantum());
    }
}
