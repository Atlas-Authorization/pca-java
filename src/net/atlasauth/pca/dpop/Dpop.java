package net.atlasauth.pca.dpop;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.jose.Jose;

/**
 * Sender-constrained proof-of-possession for PCA: RFC 9449 DPoP proofs (holder-key-signed {@code dpop+jwt} over the HTTP method and
 * target URI, key thumbprint {@code jkt}) and RFC 8705 mTLS {@code x5t#S256} confirmation, bound to a PCActn's real holder key
 * (the leaf of its capability chain, an Ed25519 key). Port of {@code @atlasauth/pca-dpop}; keys are JWK maps. Verification fails
 * closed with a {@link DpopVerificationError} whose {@code code} names the failed check.
 */
public final class Dpop {
    private Dpop() {}

    // ---- constants ----

    /** JWS algorithms a DPoP proof may use: asymmetric only, never none or a MAC (RFC 9449 s4.2). */
    public static final List<String> DPOP_ALLOWED_ALGS = List.of("EdDSA", "ES256", "ES384", "ES512", "PS256", "RS256");
    public static final String DPOP_JWT_TYP = "dpop+jwt";
    public static final double DPOP_DEFAULT_MAX_AGE_SEC = 300;
    public static final double DPOP_CLOCK_SKEW_SEC = 5;
    public static final int DPOP_MAX_PROOF_BYTES = 8192;
    public static final int DPOP_INMEMORY_MAX_ENTRIES = 100_000;

    // ---- errors ----

    /** A DPoP proof (or PCActn/DPoP binding) that failed to verify; {@code code} names the specific check. */
    public static final class DpopVerificationError extends RuntimeException {
        private final String code;
        public DpopVerificationError(String code, String message) {
            super(message);
            this.code = code;
        }
        public String code() { return code; }
    }

    // ---- replay stores ----

    /** A replay store for {@code jti} values. */
    public interface JtiSeenSet {
        boolean has(String jti);
        void add(String jti);
    }

    /**
     * A durable, atomic {@code jti} replay store: {@code addIfAbsent} must be atomic (of N concurrent calls with one key exactly one
     * returns true). The key is {@code <jkt>.<jti>}. An entry may be dropped once {@code nowSec >= expiresAtSec}.
     */
    public interface DpopReplayStore {
        boolean addIfAbsent(String key, double expiresAtSec, double nowSec);
    }

    /**
     * Single-process, explicitly bounded store: when {@code maxEntries} live entries are held a further new key makes
     * {@code addIfAbsent} throw (the verifier then refuses with {@code replay_store_error}) instead of evicting a live entry.
     * {@code maxEntries} null = {@link #DPOP_INMEMORY_MAX_ENTRIES}.
     */
    public static DpopReplayStore createInMemoryDpopReplayStore(Double maxEntries) {
        final double max = maxEntries == null ? DPOP_INMEMORY_MAX_ENTRIES : maxEntries;
        if (Double.isNaN(max) || Double.isInfinite(max) || max != Math.rint(max) || max < 1) {
            throw new DpopVerificationError("misconfigured", "maxEntries must be a positive integer");
        }
        final Map<String, Double> seen = new LinkedHashMap<>();
        return (key, expiresAtSec, nowSec) -> {
            if (!Double.isFinite(nowSec)) return false; // a non-finite clock admits nothing, whichever side it lands on
            synchronized (seen) {
                Double held = seen.get(key);
                if (held != null && !(nowSec >= held)) return false;
                if (held == null && seen.size() >= max) {
                    seen.values().removeIf(exp -> nowSec >= exp);
                    if (seen.size() >= max) throw new IllegalStateException("replay store is full");
                }
                seen.put(key, expiresAtSec);
                return true;
            }
        };
    }

    /** Conformance suite for a {@link DpopReplayStore}: the failed checks (empty = conformant). {@code make} returns a FRESH empty store. */
    public static List<String> runDpopReplayStoreConformance(Supplier<DpopReplayStore> make) {
        List<String> failures = new ArrayList<>();
        DpopReplayStore s = make.get();
        if (!s.addIfAbsent("a", 200, 100)) failures.add("first sight of a key returns true");
        if (s.addIfAbsent("a", 200, 101)) failures.add("second sight of the same key returns false");
        if (!s.addIfAbsent("b", 200, 101)) failures.add("a different key is independent");
        if (s.addIfAbsent("a", 200, 199)) failures.add("still seen one second before expiry");
        DpopReplayStore t = make.get();
        t.addIfAbsent("c", 200, 100);
        if (!t.addIfAbsent("c", 400, 200)) failures.add("an expired entry may be added again (nowSec >= expiresAtSec)");
        DpopReplayStore u = make.get();
        int wins = 0;
        ExecutorService pool = Executors.newFixedThreadPool(16);
        try {
            List<Future<Boolean>> fs = new ArrayList<>();
            for (int i = 0; i < 16; i++) {
                Callable<Boolean> c = () -> u.addIfAbsent("race", 200, 100);
                fs.add(pool.submit(c));
            }
            for (Future<Boolean> f : fs) {
                try {
                    if (f.get()) wins++;
                } catch (Exception e) {
                    // a store that throws under contention fails the check below
                }
            }
        } finally {
            pool.shutdown();
        }
        if (wins != 1) failures.add("16 concurrent adds of one key: exactly one wins (got " + wins + ")");
        return failures;
    }

    // ---- server nonces ----

    /** Issues and checks stateless server DPoP nonces (RFC 9449 s8/s9): a timestamp MACed with a server secret. */
    public interface DpopNonceIssuer {
        /** A fresh nonce for a {@code DPoP-Nonce} header ({@code nowSec} null = now). */
        String issue(Long nowSec);
        /** True only for a nonce this issuer minted that is at most {@code ttlSec} old and not from the future ({@code nowSec} null = now). */
        boolean check(Object nonce, Double nowSec);
    }

    private static byte[] hmac(byte[] secret, byte[] ts) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(secret, "HmacSHA256"));
            m.update("dpop-nonce\0".getBytes(StandardCharsets.UTF_8));
            m.update(ts);
            return Arrays.copyOf(m.doFinal(), 16);
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Creates a {@link DpopNonceIssuer}: {@code secret} at least 32 bytes, {@code ttlSec} the lifetime (null = 300). */
    public static DpopNonceIssuer createDpopNonceIssuer(byte[] secret, Double ttlSec) {
        if (secret == null || secret.length < 32) throw new DpopVerificationError("misconfigured", "nonce secret must be at least 32 bytes");
        final double ttl = ttlSec == null ? 300 : ttlSec;
        if (Double.isNaN(ttl) || Double.isInfinite(ttl) || ttl <= 0) throw new DpopVerificationError("misconfigured", "nonce ttlSec must be positive");
        final byte[] key = secret.clone();
        return new DpopNonceIssuer() {
            @Override public String issue(Long nowSec) {
                long n = nowSec != null ? nowSec : Math.floorDiv(System.currentTimeMillis(), 1000L);
                byte[] ts = new byte[8];
                for (int i = 0; i < 8; i++) ts[i] = (byte) (n >>> (56 - 8 * i));
                byte[] raw = new byte[24];
                System.arraycopy(ts, 0, raw, 0, 8);
                System.arraycopy(hmac(key, ts), 0, raw, 8, 16);
                return Jose.b64u(raw);
            }
            @Override public boolean check(Object nonce, Double nowSec) {
                if (!(nonce instanceof String)) return false;
                double now = nowSec != null ? nowSec : Math.floor(System.currentTimeMillis() / 1000.0);
                byte[] raw = net.atlasauth.pca.Pca.decodeB64uStrict(nonce, 24);
                if (raw == null) return false;
                byte[] ts = Arrays.copyOfRange(raw, 0, 8);
                if (!MessageDigest.isEqual(Arrays.copyOfRange(raw, 8, 24), hmac(key, ts))) return false;
                double issued = new BigInteger(1, ts).doubleValue();
                return Double.isFinite(now) && Double.isFinite(ttl) && issued <= now + DPOP_CLOCK_SKEW_SEC && now - issued <= ttl;
            }
        };
    }

    // ---- inputs / results ----

    /** Input of {@link #createDpopProof}. */
    public static final class CreateDpopProofInput {
        /** HTTP method (case-insensitive in; stored uppercased as {@code htm}). */
        public String method;
        /** Full request URL; {@code htu} is this with query and fragment removed. */
        public String url;
        /** The holder's PRIVATE JWK that signs the proof. */
        public Map<String, Object> privateKey;
        /** The holder's PUBLIC JWK, embedded in the proof header; drives the {@code alg}. */
        public Map<String, Object> publicJwk;
        public String nonce;
        public String ath;
        /** Issued-at override (epoch seconds); null = now. */
        public Double iat;
        /** Proof id override; null = a random UUID. */
        public String jti;
    }

    /** Options of {@link #verifyDpopProof}. */
    public static final class VerifyDpopProofOptions {
        public String method;
        public String url;
        /** Maximum accepted proof age in seconds (from {@code iat} to now). */
        public double maxAgeSec;
        public String expectedJkt;
        public JtiSeenSet seenJti;
        public DpopReplayStore replayStore;
        /** Default true: a verification with neither store is refused ({@code replay_store_required}). */
        public Boolean requireReplayStore;
        public DpopNonceIssuer nonceIssuer;
        /** Override "now" (epoch seconds). */
        public Double nowSec;
        public String expectedNonce;
        public String accessToken;
    }

    /** A verified proof: its claims, the embedded public JWK and that key's RFC 7638 thumbprint. */
    public static final class DpopVerifyResult {
        public final Map<String, Object> claims;
        public final Map<String, Object> jwk;
        public final String jkt;
        DpopVerifyResult(Map<String, Object> claims, Map<String, Object> jwk, String jkt) { this.claims = claims; this.jwk = jwk; this.jkt = jkt; }
    }

    // ---- helpers ----

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    /** The JavaScript read {@code jwk.member} (undefined for anything that is not an object; a TypeError for null). */
    private static Object member(Object jwk, String name) {
        if (jwk == null) throw new IllegalArgumentException("Cannot read properties of null (reading '" + name + "')");
        Map<String, Object> m = obj(jwk);
        return m == null ? null : m.get(name);
    }

    /** RFC 7638 JWK SHA-256 thumbprint (base64url). */
    public static String jwkThumbprint(Map<String, Object> jwk, String digest) { return Jose.jwkThumbprint(jwk, digest); }

    /** The JWS {@code alg} for a key, from its JWK kty / crv. Throws {@code unsupported_key} for an unsupported or MAC key. */
    public static String dpopAlgForJwk(Map<String, Object> jwk) {
        Object kty = member(jwk, "kty"), crv = member(jwk, "crv");
        if ("OKP".equals(kty)) {
            if ("Ed25519".equals(crv) || "Ed448".equals(crv)) return "EdDSA";
            throw new DpopVerificationError("unsupported_key", "unsupported OKP curve '" + jsStr(crv) + "' for DPoP");
        }
        if ("EC".equals(kty)) {
            if ("P-256".equals(crv)) return "ES256";
            if ("P-384".equals(crv)) return "ES384";
            if ("P-521".equals(crv)) return "ES512";
            throw new DpopVerificationError("unsupported_key", "unsupported EC curve '" + jsStr(crv) + "' for DPoP");
        }
        if ("RSA".equals(kty)) return "PS256";
        throw new DpopVerificationError("unsupported_key", "unsupported key type '" + jsStr(kty) + "' for DPoP");
    }

    private static String jsStr(Object o) {
        if (o == null) return "undefined";
        if (o instanceof String) return (String) o;
        try {
            return Json.canonicalize(o);
        } catch (RuntimeException e) {
            return String.valueOf(o);
        }
    }

    /** True when the allow-listed JWS {@code alg} belongs to the key type of {@code jwk}. Unknown algs never match. */
    public static boolean dpopAlgMatchesJwk(String alg, Object jwk) {
        if (alg == null || !List.of("EdDSA", "ES256", "ES384", "ES512", "PS256", "RS256").contains(alg)) return false; // the jwk is not read for an unknown alg
        Object kty = member(jwk, "kty"), crv = member(jwk, "crv");
        switch (alg) {
            case "EdDSA": return "OKP".equals(kty) && ("Ed25519".equals(crv) || "Ed448".equals(crv));
            case "ES256": return "EC".equals(kty) && "P-256".equals(crv);
            case "ES384": return "EC".equals(kty) && "P-384".equals(crv);
            case "ES512": return "EC".equals(kty) && "P-521".equals(crv);
            case "PS256": case "RS256": return "RSA".equals(kty);
            default: return false;
        }
    }

    private static Map<String, Object> toPublicJwk(Map<String, Object> jwk) {
        Map<String, Object> pub = new LinkedHashMap<>();
        if (jwk.containsKey("kty")) pub.put("kty", jwk.get("kty"));
        for (String k : new String[] {"crv", "x", "y", "n", "e"}) if (jwk.containsKey(k)) pub.put(k, jwk.get(k));
        return pub;
    }

    /** The access-token hash {@code ath}: base64url(SHA-256(access token)), RFC 9449 s4.2. */
    public static String athFor(String accessToken) { return Jose.b64u(Jose.sha256(Jose.utf8(accessToken))); }

    // ---- WHATWG-style URL reduction (protocol // host path) ----

    private static final List<String> SPECIAL = List.of("http", "https", "ws", "wss", "ftp");

    private static int defaultPort(String scheme) {
        switch (scheme) {
            case "http": case "ws": return 80;
            case "https": case "wss": return 443;
            case "ftp": return 21;
            default: return -1;
        }
    }

    private static final String HOST_FORBIDDEN = "\u0000\t\n\r #/:<>?@[\\]^|";

    private static boolean isHex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

    private static String percentEncode(String s, boolean pathSet) {
        StringBuilder sb = new StringBuilder();
        byte[] bytes = Jose.utf8(s);
        for (byte b : bytes) {
            int c = b & 0xff;
            boolean enc = c < 0x20 || c > 0x7e;
            if (!enc && pathSet && " \"#<>?`{}".indexOf(c) >= 0) enc = true;
            if (enc) sb.append('%').append(String.format("%02X", c));
            else sb.append((char) c);
        }
        return sb.toString();
    }

    private static String percentDecode(String s) {
        byte[] in = Jose.utf8(s);
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        for (int i = 0; i < in.length; i++) {
            if (in[i] == '%' && i + 2 < in.length && isHex((char) in[i + 1]) && isHex((char) in[i + 2])) {
                out.write(Integer.parseInt(new String(in, i + 1, 2, StandardCharsets.US_ASCII), 16));
                i += 2;
            } else out.write(in[i]);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private static BigInteger ipv4Number(String in) {
        if (in.isEmpty()) return null;
        int radix = 10;
        String s = in;
        if (s.length() >= 2 && (s.startsWith("0x") || s.startsWith("0X"))) { s = s.substring(2); radix = 16; }
        else if (s.length() >= 2 && s.charAt(0) == '0') { s = s.substring(1); radix = 8; }
        if (s.isEmpty()) return BigInteger.ZERO;
        for (int i = 0; i < s.length(); i++) if (Character.digit(s.charAt(i), radix) < 0 || s.charAt(i) > 'f') return null;
        return new BigInteger(s, radix);
    }

    private static boolean endsInNumber(String host) {
        List<String> parts = new ArrayList<>(Arrays.asList(host.split("\\.", -1)));
        if (parts.get(parts.size() - 1).isEmpty()) {
            if (parts.size() == 1) return false;
            parts.remove(parts.size() - 1);
        }
        String last = parts.get(parts.size() - 1);
        if (!last.isEmpty() && last.chars().allMatch(c -> c >= '0' && c <= '9')) return true;
        return ipv4Number(last) != null;
    }

    private static String ipv4Parse(String host) {
        List<String> parts = new ArrayList<>(Arrays.asList(host.split("\\.", -1)));
        if (parts.get(parts.size() - 1).isEmpty() && parts.size() > 1) parts.remove(parts.size() - 1);
        if (parts.size() > 4) throw new IllegalArgumentException("Invalid URL");
        List<BigInteger> nums = new ArrayList<>();
        for (String p : parts) {
            BigInteger n = ipv4Number(p);
            if (n == null) throw new IllegalArgumentException("Invalid URL");
            nums.add(n);
        }
        for (int i = 0; i < nums.size() - 1; i++) if (nums.get(i).compareTo(BigInteger.valueOf(255)) > 0) throw new IllegalArgumentException("Invalid URL");
        BigInteger lastN = nums.get(nums.size() - 1);
        if (lastN.compareTo(BigInteger.valueOf(256).pow(5 - nums.size())) >= 0) throw new IllegalArgumentException("Invalid URL");
        BigInteger ip = lastN;
        for (int i = 0; i < nums.size() - 1; i++) ip = ip.add(nums.get(i).multiply(BigInteger.valueOf(256).pow(3 - i)));
        long v = ip.longValue();
        return ((v >> 24) & 255) + "." + ((v >> 16) & 255) + "." + ((v >> 8) & 255) + "." + (v & 255);
    }

    private static String ipv6Parse(String in) {
        int[] a = new int[8];
        int piece = 0, compress = -1, p = 0, n = in.length();
        if (n > p && in.charAt(p) == ':') {
            if (n < 2 || in.charAt(1) != ':') throw new IllegalArgumentException("Invalid URL");
            p += 2;
            piece++;
            compress = piece;
        }
        while (p < n) {
            if (piece == 8) throw new IllegalArgumentException("Invalid URL");
            if (in.charAt(p) == ':') {
                if (compress != -1) throw new IllegalArgumentException("Invalid URL");
                p++;
                piece++;
                compress = piece;
                continue;
            }
            int value = 0, length = 0;
            while (length < 4 && p < n && isHex(in.charAt(p))) { value = value * 16 + Character.digit(in.charAt(p), 16); p++; length++; }
            if (p < n && in.charAt(p) == '.') {
                if (length == 0) throw new IllegalArgumentException("Invalid URL");
                p -= length;
                if (piece > 6) throw new IllegalArgumentException("Invalid URL");
                int seen = 0;
                while (p < n) {
                    int v4 = -1;
                    if (seen > 0) {
                        if (in.charAt(p) == '.' && seen < 4) p++;
                        else throw new IllegalArgumentException("Invalid URL");
                    }
                    if (p >= n || in.charAt(p) < '0' || in.charAt(p) > '9') throw new IllegalArgumentException("Invalid URL");
                    while (p < n && in.charAt(p) >= '0' && in.charAt(p) <= '9') {
                        int d = in.charAt(p) - '0';
                        if (v4 == -1) v4 = d;
                        else if (v4 == 0) throw new IllegalArgumentException("Invalid URL");
                        else v4 = v4 * 10 + d;
                        if (v4 > 255) throw new IllegalArgumentException("Invalid URL");
                        p++;
                    }
                    a[piece] = a[piece] * 256 + v4;
                    seen++;
                    if (seen == 2 || seen == 4) piece++;
                }
                if (seen != 4) throw new IllegalArgumentException("Invalid URL");
                break;
            } else if (p < n && in.charAt(p) == ':') {
                p++;
                if (p >= n) throw new IllegalArgumentException("Invalid URL");
            } else if (p < n) throw new IllegalArgumentException("Invalid URL");
            a[piece] = value;
            piece++;
        }
        if (compress != -1) {
            int swaps = piece - compress;
            piece = 7;
            while (piece != 0 && swaps > 0) {
                int t = a[compress + swaps - 1];
                a[compress + swaps - 1] = a[piece];
                a[piece] = t;
                piece--;
                swaps--;
            }
        } else if (piece != 8) throw new IllegalArgumentException("Invalid URL");
        int bestStart = -1, bestLen = 0;
        for (int i = 0; i < 8; ) {
            if (a[i] != 0) { i++; continue; }
            int j = i;
            while (j < 8 && a[j] == 0) j++;
            if (j - i > bestLen) { bestLen = j - i; bestStart = i; }
            i = j;
        }
        if (bestLen < 2) bestStart = -1;
        StringBuilder sb = new StringBuilder("[");
        boolean ignore0 = false;
        for (int i = 0; i < 8; i++) {
            if (ignore0 && a[i] == 0) continue;
            ignore0 = false;
            if (bestStart == i) { sb.append(i == 0 ? "::" : ":"); ignore0 = true; continue; }
            sb.append(Integer.toHexString(a[i]));
            if (i != 7) sb.append(':');
        }
        return sb.append(']').toString();
    }

    private static String parseHost(String raw, boolean special) {
        if (raw.startsWith("[")) {
            if (!raw.endsWith("]")) throw new IllegalArgumentException("Invalid URL");
            return ipv6Parse(raw.substring(1, raw.length() - 1));
        }
        if (!special) {
            for (int i = 0; i < raw.length(); i++) if (HOST_FORBIDDEN.indexOf(raw.charAt(i)) >= 0) throw new IllegalArgumentException("Invalid URL");
            return percentEncode(raw, false);
        }
        String domain = percentDecode(raw);
        if (net.atlasauth.pca.oauth.HostIdna.needsProcessing(domain)) {
            domain = net.atlasauth.pca.oauth.HostIdna.toAscii(domain);
            if (domain == null) throw new IllegalArgumentException("Invalid URL");
        } else domain = domain.toLowerCase(Locale.ROOT);
        if (domain.isEmpty()) throw new IllegalArgumentException("Invalid URL");
        for (int i = 0; i < domain.length(); i++) {
            char c = domain.charAt(i);
            if (HOST_FORBIDDEN.indexOf(c) >= 0 || c <= 0x1f || c == '%' || c == 0x7f) throw new IllegalArgumentException("Invalid URL");
        }
        return endsInNumber(domain) ? ipv4Parse(domain) : domain;
    }

    private static boolean isDot(String seg) { String l = seg.toLowerCase(Locale.ROOT); return l.equals(".") || l.equals("%2e"); }

    private static boolean isDotDot(String seg) {
        String l = seg.toLowerCase(Locale.ROOT);
        return l.equals("..") || l.equals(".%2e") || l.equals("%2e.") || l.equals("%2e%2e");
    }

    /** {@code protocol + "//" + host + pathname} of a URL as {@code new URL(url)} reads them (query, fragment and credentials dropped). */
    public static String normalizeHtu(String url) {
        String[] u = parseUrl(url);
        return u[0] + ":" + "//" + u[1] + u[2];
    }

    /** {@code new URL(url).host}: the host, with its port when it is not the scheme default (IPv6 in brackets, IDN as punycode). */
    public static String urlHost(String url) { return parseUrl(url)[1]; }

    /** {scheme, host[:port], pathname} of a URL as the WHATWG parser reads it; IllegalArgumentException when it does not parse. */
    private static String[] parseUrl(String url) {
        if (url == null) throw new IllegalArgumentException("Invalid URL");
        int st = 0, en = url.length();
        while (st < en && url.charAt(st) <= 0x20) st++;
        while (en > st && url.charAt(en - 1) <= 0x20) en--;
        String in = url.substring(st, en).replace("\t", "").replace("\n", "").replace("\r", "");
        Matcher m = Pattern.compile("^([A-Za-z][A-Za-z0-9+\\-.]*):").matcher(in);
        if (!m.find()) throw new IllegalArgumentException("Invalid URL");
        String scheme = m.group(1).toLowerCase(Locale.ROOT);
        String rest = in.substring(m.end());
        boolean special = SPECIAL.contains(scheme);
        String host = "", pathStr;
        int q = indexOfAny(rest, "?#", 0);
        String beforeQ = q < 0 ? rest : rest.substring(0, q);
        if (special) {
            int i = 0;
            while (i < beforeQ.length() && (beforeQ.charAt(i) == '/' || beforeQ.charAt(i) == '\\')) i++;
            String after = beforeQ.substring(i);
            int e = indexOfAny(after, "/\\", 0);
            String authority = e < 0 ? after : after.substring(0, e);
            pathStr = e < 0 ? "" : after.substring(e).replace('\\', '/');
            host = hostPort(authority, scheme, true);
            if (host.isEmpty()) throw new IllegalArgumentException("Invalid URL");
        } else if (beforeQ.startsWith("//")) {
            String after = beforeQ.substring(2);
            int e = after.indexOf('/');
            String authority = e < 0 ? after : after.substring(0, e);
            pathStr = e < 0 ? "" : after.substring(e);
            host = hostPort(authority, scheme, false);
        } else if (beforeQ.startsWith("/")) {
            pathStr = beforeQ;
        } else {
            return new String[] {scheme, "", percentEncode(beforeQ, false)}; // opaque path: protocol, empty host, pathname
        }
        String pathname;
        if (special || pathStr.startsWith("/")) {
            String body = pathStr.startsWith("/") ? pathStr.substring(1) : pathStr;
            List<String> path = new ArrayList<>();
            String[] segs = body.split("/", -1);
            for (int i = 0; i < segs.length; i++) {
                String seg = segs[i];
                boolean last = i == segs.length - 1;
                if (isDotDot(seg)) {
                    if (!path.isEmpty()) path.remove(path.size() - 1);
                    if (last) path.add("");
                } else if (isDot(seg)) {
                    if (last) path.add("");
                } else path.add(percentEncode(seg, true));
            }
            pathname = path.isEmpty() ? "" : "/" + String.join("/", path);
            if (special && pathname.isEmpty()) pathname = "/";
        } else pathname = "";
        return new String[] {scheme, host, pathname};
    }

    private static int indexOfAny(String s, String set, int from) {
        for (int i = from; i < s.length(); i++) if (set.indexOf(s.charAt(i)) >= 0) return i;
        return -1;
    }

    /** host[:port] of an authority (credentials dropped, default port dropped); IllegalArgumentException on failure. */
    private static String hostPort(String authority, String scheme, boolean special) {
        String a = authority;
        int at = a.lastIndexOf('@');
        if (at >= 0) {
            a = a.substring(at + 1);
            if (a.isEmpty()) throw new IllegalArgumentException("Invalid URL");
        }
        int colon = -1;
        boolean bracket = false;
        for (int i = 0; i < a.length(); i++) {
            char c = a.charAt(i);
            if (c == '[') bracket = true;
            else if (c == ']') bracket = false;
            else if (c == ':' && !bracket) { colon = i; break; }
        }
        String hostRaw = colon < 0 ? a : a.substring(0, colon);
        String portRaw = colon < 0 ? null : a.substring(colon + 1);
        String port = "";
        if (portRaw != null && !portRaw.isEmpty()) {
            for (int i = 0; i < portRaw.length(); i++) if (portRaw.charAt(i) < '0' || portRaw.charAt(i) > '9') throw new IllegalArgumentException("Invalid URL");
            BigInteger pv = new BigInteger(portRaw);
            if (pv.compareTo(BigInteger.valueOf(65535)) > 0) throw new IllegalArgumentException("Invalid URL");
            if (pv.intValue() != defaultPort(scheme)) port = ":" + pv;
        }
        if (hostRaw.isEmpty()) {
            if (special) throw new IllegalArgumentException("Invalid URL");
            if (!port.isEmpty() || (portRaw != null)) throw new IllegalArgumentException("Invalid URL");
            return "";
        }
        return parseHost(hostRaw, special) + port;
    }

    // ---- DPoP proof: create / verify ----

    private static Object iatValue(double v) {
        if (v == Math.rint(v) && Math.abs(v) < 1e21) return new Json.Num(new java.math.BigDecimal(v).toPlainString());
        return v;
    }

    /** Builds and signs a DPoP proof JWT ({@code typ: dpop+jwt}, embedded public {@code jwk}, claims htm / htu / iat / jti ...). */
    public static String createDpopProof(CreateDpopProofInput input) {
        Map<String, Object> publicJwk = toPublicJwk(input.publicJwk);
        String alg = dpopAlgForJwk(publicJwk);
        double iat = input.iat != null ? input.iat : Math.floor(System.currentTimeMillis() / 1000.0);
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("htm", input.method.toUpperCase(Locale.ROOT));
        claims.put("htu", normalizeHtu(input.url));
        claims.put("iat", iatValue(iat));
        claims.put("jti", input.jti != null ? input.jti : java.util.UUID.randomUUID().toString());
        if (input.nonce != null) claims.put("nonce", input.nonce);
        if (input.ath != null) claims.put("ath", input.ath);
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("typ", DPOP_JWT_TYP);
        header.put("alg", alg);
        header.put("jwk", publicJwk);
        return Jose.signJwt(header, claims, input.privateKey);
    }

    private static DpopVerificationError err(String code, String message) { return new DpopVerificationError(code, message); }

    /**
     * Verifies a DPoP proof: signature under the embedded {@code jwk}, {@code typ}, that {@code htm} / {@code htu} match the request,
     * {@code iat} freshness, optional {@code jkt}, nonce and access-token binding, and {@code jti} replay rejection. Throws
     * {@link DpopVerificationError} on any failure.
     */
    public static DpopVerifyResult verifyDpopProof(Object proof, VerifyDpopProofOptions opts) {
        // A NaN, infinite or negative max age would disable (or invert) the stale check: refuse it.
        if (Double.isNaN(opts.maxAgeSec) || Double.isInfinite(opts.maxAgeSec) || opts.maxAgeSec < 0) throw err("max_age", "maxAgeSec must be a finite, non-negative number of seconds");
        if (!Boolean.FALSE.equals(opts.requireReplayStore) && opts.replayStore == null && opts.seenJti == null) {
            throw err("replay_store_required", "no replay store configured; replay cannot be detected");
        }
        if (!(proof instanceof String) || ((String) proof).length() > DPOP_MAX_PROOF_BYTES) {
            throw err("oversize", "proof is not a string or exceeds " + DPOP_MAX_PROOF_BYTES + " bytes");
        }
        String token = (String) proof;
        Map<String, Object> header;
        try {
            header = Jose.assertCanonicalCompactJws(token).header;
        } catch (RuntimeException e) {
            throw err("malformed", "not a JWS: " + e.getMessage());
        }
        if (!DPOP_JWT_TYP.equals(header.get("typ"))) throw err("typ", "header typ must be '" + DPOP_JWT_TYP + "', got '" + jsStr(header.get("typ")) + "'");
        if (!header.containsKey("jwk")) throw err("no_jwk", "proof header has no embedded jwk");
        Object hj = header.get("jwk");
        if (hj instanceof Map) {
            for (String m : new String[] {"d", "p", "q", "dp", "dq", "qi", "k"}) {
                if (((Map<?, ?>) hj).containsKey(m)) throw err("private_jwk", "proof header jwk contains private key material");
            }
        }
        Object alg = header.get("alg");
        if (alg instanceof String && DPOP_ALLOWED_ALGS.contains(alg) && !dpopAlgMatchesJwk((String) alg, hj)) {
            throw err("alg_jwk_mismatch", "alg '" + alg + "' does not match the embedded jwk key type");
        }

        Map<String, Object> payload;
        Map<String, Object> jwk;
        try {
            Jose.JwtOptions jo = new Jose.JwtOptions();
            jo.algorithms = DPOP_ALLOWED_ALGS;
            jo.typ = DPOP_JWT_TYP;
            Jose.VerifiedJwt res = Jose.jwtVerify(token, Jose.EMBEDDED, jo);
            payload = res.payload;
            jwk = obj(res.protectedHeader.get("jwk"));
            if (jwk == null) throw err("no_jwk", "verified header has no embedded jwk");
        } catch (DpopVerificationError e) {
            throw e;
        } catch (RuntimeException e) {
            throw err("signature", "DPoP signature did not verify: " + e.getMessage());
        }

        Object htm = payload.get("htm"), htu = payload.get("htu"), jti = payload.get("jti");
        Double iat = Jose.num(payload.get("iat"));
        if (!(htm instanceof String)) throw err("htm", "htm is missing or not a string");
        if (!(htu instanceof String)) throw err("htu", "htu is missing or not a string");
        if (iat == null || iat.isNaN() || iat.isInfinite()) throw err("iat", "iat is missing or not a number");
        if (!(jti instanceof String) || ((String) jti).isEmpty()) throw err("jti", "jti is missing or empty");

        if (!htm.equals(opts.method.toUpperCase(Locale.ROOT))) throw err("htm", "htm '" + htm + "' does not match request method");
        if (!htu.equals(normalizeHtu(opts.url))) throw err("htu", "htu '" + htu + "' does not match request URL");

        double now = opts.nowSec != null ? opts.nowSec : Math.floor(System.currentTimeMillis() / 1000.0);
        if (Double.isNaN(now) || Double.isInfinite(now)) throw err("now", "nowSec must be a finite number");
        if (iat > now + DPOP_CLOCK_SKEW_SEC) throw err("iat_future", "iat is in the future");
        if (!(now - iat <= opts.maxAgeSec)) throw err("iat_stale", "proof is older than " + jsNum(opts.maxAgeSec) + "s");

        String jkt = Jose.jwkThumbprint(jwk, "sha256");
        if (opts.expectedJkt != null && !jkt.equals(opts.expectedJkt)) throw err("jkt", "embedded key thumbprint does not match expected jkt");

        if (opts.expectedNonce != null && !opts.expectedNonce.equals(payload.get("nonce"))) {
            throw err("nonce", "proof nonce is missing or does not match the expected nonce");
        }
        if (opts.nonceIssuer != null && !opts.nonceIssuer.check(payload.get("nonce"), now)) {
            throw err("nonce", "proof nonce is missing, forged or expired");
        }
        if (opts.accessToken != null && !athFor(opts.accessToken).equals(payload.get("ath"))) {
            throw err("ath", "proof ath is missing or does not match the access token");
        }

        if (opts.seenJti != null) {
            if (opts.seenJti.has((String) jti)) throw err("jti_replay", "jti '" + jti + "' has already been seen");
            opts.seenJti.add((String) jti);
        }
        if (opts.replayStore != null) {
            boolean fresh;
            try {
                fresh = opts.replayStore.addIfAbsent(jkt + "." + jti, iat + opts.maxAgeSec + DPOP_CLOCK_SKEW_SEC, now);
            } catch (RuntimeException e) {
                throw err("replay_store_error", "replay store failed: " + e.getMessage());
            }
            if (!fresh) throw err("jti_replay", "jti '" + jti + "' has already been seen");
        }

        Map<String, Object> claims = new LinkedHashMap<>(payload);
        claims.put("htm", htm);
        claims.put("htu", htu);
        claims.put("iat", payload.get("iat"));
        claims.put("jti", jti);
        if (payload.get("nonce") instanceof String) claims.put("nonce", payload.get("nonce"));
        if (payload.get("ath") instanceof String) claims.put("ath", payload.get("ath"));
        return new DpopVerifyResult(claims, jwk, jkt);
    }

    private static String jsNum(double d) {
        if (d == Math.rint(d) && Math.abs(d) < 1e21) return new java.math.BigDecimal(d).toPlainString();
        return Json.canonicalize(new Json.Num(Double.toString(d)));
    }

    // ---- RFC 8705 mTLS confirmation ----

    private static final Pattern PEM_BODY = Pattern.compile("-----BEGIN CERTIFICATE-----([\\s\\S]+?)-----END CERTIFICATE-----");

    /** Node-style lenient base64: stops at the first '=', ignores a dangling sextet. */
    private static byte[] nodeBase64(String body) {
        int eq = body.indexOf('=');
        String s = eq >= 0 ? body.substring(0, eq) : body;
        if (s.length() % 4 == 1) s = s.substring(0, s.length() - 1);
        while (s.length() % 4 != 0) s += "=";
        return Base64.getDecoder().decode(s);
    }

    private static byte[] pemToDer(String pem) {
        Matcher m = PEM_BODY.matcher(pem);
        String body = (m.find() ? m.group(1) : pem).replaceAll("[^A-Za-z0-9+/=]", "");
        return nodeBase64(body);
    }

    /** RFC 8705 s3.1 {@code cnf}: {@code {"x5t#S256": b64u(sha256(DER))}} for DER bytes. */
    public static Map<String, Object> mtlsCnf(byte[] certDer) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("x5t#S256", Jose.b64u(Jose.sha256(certDer)));
        return m;
    }

    /** RFC 8705 s3.1 {@code cnf} for a certificate given as PEM text (the DER body is hashed). */
    public static Map<String, Object> mtlsCnf(String certPem) { return mtlsCnf(pemToDer(certPem)); }

    /** The thumbprint of a certificate that PARSES as X.509 (DER bytes). Throws {@code cert} otherwise. */
    public static String mtlsThumbprint(byte[] certDer) {
        try {
            X509Certificate c = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certDer));
            return Jose.b64u(Jose.sha256(c.getEncoded()));
        } catch (Exception e) {
            throw err("cert", "not an X.509 certificate: " + e.getMessage());
        }
    }

    /** The thumbprint of a certificate given as PEM text; a string that is not a PEM certificate is refused as {@code cert}. */
    public static String mtlsThumbprint(String certPem) {
        try {
            if (!PEM_BODY.matcher(certPem).find()) throw new IllegalArgumentException("no PEM certificate");
            return mtlsThumbprint(pemToDer(certPem));
        } catch (DpopVerificationError e) {
            throw e;
        } catch (RuntimeException e) {
            throw err("cert", "not an X.509 certificate: " + e.getMessage());
        }
    }

    private static Map<String, Object> boundCnf(String got, Object cnf) {
        Object want = cnf instanceof Map ? ((Map<?, ?>) cnf).get("x5t#S256") : null;
        if (!(want instanceof String) || ((String) want).isEmpty()) throw err("x5t_missing", "cnf has no 'x5t#S256' thumbprint");
        if (!MessageDigest.isEqual(Json.utf8(got), Json.utf8(((String) want)))) {
            throw err("x5t", "client certificate thumbprint does not match cnf x5t#S256");
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("x5t#S256", got);
        return m;
    }

    /**
     * RFC 8705 s3.1 check: the presented client certificate (DER) must hash to the {@code x5t#S256} of the token's {@code cnf}.
     * Throws {@code x5t_missing} (no usable thumbprint in cnf), {@code cert} (unparseable certificate) or {@code x5t} (mismatch).
     */
    public static Map<String, Object> assertMtlsBound(byte[] certDer, Object cnf) {
        Object want = cnf instanceof Map ? ((Map<?, ?>) cnf).get("x5t#S256") : null;
        if (!(want instanceof String) || ((String) want).isEmpty()) throw err("x5t_missing", "cnf has no 'x5t#S256' thumbprint");
        return boundCnf(mtlsThumbprint(certDer), cnf);
    }

    /** {@link #assertMtlsBound(byte[], Object)} for a PEM certificate. */
    public static Map<String, Object> assertMtlsBound(String certPem, Object cnf) {
        Object want = cnf instanceof Map ? ((Map<?, ?>) cnf).get("x5t#S256") : null;
        if (!(want instanceof String) || ((String) want).isEmpty()) throw err("x5t_missing", "cnf has no 'x5t#S256' thumbprint");
        return boundCnf(mtlsThumbprint(certPem), cnf);
    }

    // ---- PCActn <-> DPoP binding ----

    /**
     * The OKP / Ed25519 public JWK of the PCActn's bound holder key: the LEAF of its capability chain ({@code cap_chain[last].holder}).
     * Throws {@code no_leaf} when the chain is empty.
     */
    public static Map<String, Object> leafHolderJwk(Map<String, Object> p) {
        Object chain = p.get("cap_chain");
        if (chain == null) throw new IllegalArgumentException("Cannot read properties of " + (p.containsKey("cap_chain") ? "null" : "undefined") + " (reading 'length')");
        // chain[chain.length - 1] with JavaScript indexing: an array, a string, or an object with a numeric length member
        boolean found = false;
        Object leaf = null;
        if (chain instanceof List) {
            List<?> l = (List<?>) chain;
            if (!l.isEmpty()) { found = true; leaf = l.get(l.size() - 1); }
        } else if (chain instanceof String) {
            String cs = (String) chain;
            if (!cs.isEmpty()) { found = true; leaf = cs.substring(cs.length() - 1); } // a character has no holder member
        } else if (chain instanceof Map) {
            Map<?, ?> cm = (Map<?, ?>) chain;
            Object lv = cm.get("length");
            Double n = null;
            try { if (lv instanceof Number) n = ((Number) lv).doubleValue(); else if (lv instanceof Json.Num) n = Double.parseDouble(((Json.Num) lv).raw); } catch (NumberFormatException e) { /* not a number: NaN index */ }
            if (n != null && !n.isNaN() && !n.isInfinite() && n - 1 == Math.rint(n - 1)) {
                String key = Long.toString((long) (n - 1));
                if (cm.containsKey(key)) { found = true; leaf = cm.get(key); }
            }
        }
        if (!found) throw err("no_leaf", "PCActn capability chain is empty; no bound holder key");
        if (leaf == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'holder')");
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "OKP");
        jwk.put("crv", "Ed25519");
        if (leaf instanceof Map && ((Map<?, ?>) leaf).containsKey("holder")) jwk.put("x", ((Map<?, ?>) leaf).get("holder")); // an absent holder stays absent
        return jwk;
    }

    /** The {@code cnf: {jkt}} confirmation for a PCActn's bound holder key (RFC 9449 s6). */
    public static Map<String, Object> bindPcaToDpop(Map<String, Object> p) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("jkt", Jose.jwkThumbprint(leafHolderJwk(p), "sha256"));
        return m;
    }

    /** Options of {@link #assertPcaDpop}: like {@link VerifyDpopProofOptions} with {@code maxAgeSec} optional (default 300) and no {@code expectedJkt}. */
    public static final class AssertPcaDpopOptions {
        public String method;
        public String url;
        public Double maxAgeSec;
        public JtiSeenSet seenJti;
        public DpopReplayStore replayStore;
        public Boolean requireReplayStore;
        public DpopNonceIssuer nonceIssuer;
        public Double nowSec;
        public String expectedNonce;
        public String accessToken;
    }

    /**
     * Confirms a presented DPoP proof is held by the PCActn's bound holder key AND is for the given HTTP target: verifies the proof with
     * {@code expectedJkt} fixed to the PCActn's leaf-holder thumbprint. Throws {@link DpopVerificationError} on any mismatch.
     */
    public static DpopVerifyResult assertPcaDpop(Map<String, Object> p, Object dpopProof, AssertPcaDpopOptions o) {
        String jkt = (String) bindPcaToDpop(p).get("jkt");
        VerifyDpopProofOptions v = new VerifyDpopProofOptions();
        v.method = o.method;
        v.url = o.url;
        v.maxAgeSec = o.maxAgeSec != null ? o.maxAgeSec : DPOP_DEFAULT_MAX_AGE_SEC;
        v.expectedJkt = jkt;
        v.seenJti = o.seenJti;
        v.replayStore = o.replayStore;
        v.requireReplayStore = o.requireReplayStore;
        v.nonceIssuer = o.nonceIssuer;
        v.nowSec = o.nowSec;
        v.expectedNonce = o.expectedNonce;
        v.accessToken = o.accessToken;
        return verifyDpopProof(dpopProof, v);
    }
}
