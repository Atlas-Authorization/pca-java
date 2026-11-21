package net.atlasauth.pca.doctor;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.DoubleSupplier;
import java.util.function.Function;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.Pq;

/**
 * Checks a live PCA deployment's assumptions: clock skew, replay store, trusted-proxy settings, signature-suite policy, root-caveat
 * enforcement and the verifier's required checks. Every check returns a {@link CheckResult} (pass / warn / fail / skip, what was
 * observed and what to do); {@link #runDoctor} merges them, {@link #verdictOf} reduces them, {@link #formatResults} prints them, and
 * nothing printed carries a credential ({@link #scrubText}). Configuration is a plain JSON object (sections {@code url},
 * {@code clock}, {@code store}, {@code proxy}, {@code verifier}); checks that cannot be observed from here say so instead of passing.
 */
public final class Doctor {
    private Doctor() {}

    // ---- results ----

    /** A deep copy of a config / result tree with absent (undefined) members dropped, the form the reference serialises. */
    @SuppressWarnings("unchecked")
    public static Object json(Object v) {
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) if (e.getValue() != Js.UNDEF) out.put(e.getKey(), json(e.getValue()));
            return out;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(x == Js.UNDEF ? null : json(x));
            return out;
        }
        return v;
    }

    /** One check's result: {@code id}, {@code status}, {@code detail}, optional {@code remediation} and {@code observed}. */
    public static final class CheckResult {
        public final Map<String, Object> json;
        CheckResult(Map<String, Object> json) { this.json = json; }

        public static CheckResult of(String id, String status, String detail) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("status", status);
            m.put("detail", detail);
            return new CheckResult(m);
        }
        public static CheckResult fromJson(Map<String, Object> m) { return new CheckResult(m); }

        CheckResult fix(String remediation) { json.put("remediation", remediation); return this; }
        CheckResult observed(Map<String, Object> o) { json.put("observed", o); return this; }
        public String id() { return Js.str(json.get("id")); }
        public String status() { return Js.str(json.get("status")); }
        public String detail() { return Js.str(json.get("detail")); }
        public String remediation() { Object r = json.get("remediation"); return Js.truthy(r) ? Js.str(r) : null; }
        public Map<String, Object> toJson() { return json; }
    }

    // ---- scrub ----

    private static final String S = "\\t\\n\\u000B\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff";
    private static final int CI = Pattern.CASE_INSENSITIVE;
    private static final Pattern SCRUB_JWT = Pattern.compile("(?<![A-Za-z0-9_])eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*");
    private static final Pattern SCRUB_AUTH = Pattern.compile("(?<![A-Za-z0-9_])(authorization[\"']?[" + S + "]*[:=][" + S + "]*)[^\\n\"']*", CI);
    private static final Pattern SCRUB_BEARER = Pattern.compile("(?<![A-Za-z0-9_])(Bearer|Basic|Token)[" + S + "]+[A-Za-z0-9_.~+/=-]{6,}", CI);
    private static final Pattern SCRUB_URL = Pattern.compile("([a-z][a-z0-9+.-]*://)[^" + S + "/@]*:[^" + S + "/@]*@", CI);
    private static final Pattern SCRUB_PAIR = Pattern.compile("(?<![A-Za-z0-9_])((?:token|secret|password|passwd|pwd|api[_-]?key|key|signature|sig|credential|auth|sslpassword)[\"']?["
        + S + "]*[:=][" + S + "]*)(\"[^\"]*\"|'[^']*'|[^" + S + "\"'&,;]+)", CI);
    private static final Pattern SCRUB_LONG = Pattern.compile("[A-Za-z0-9_-]{40,}");

    /** Remove credentials from text the doctor prints: URL userinfo, {@code token=} / {@code password=} pairs, bearer credentials, JWTs and long token runs. */
    public static String scrubText(Object text) {
        String t = Js.str(text);
        t = SCRUB_JWT.matcher(t).replaceAll("[redacted]");
        t = SCRUB_AUTH.matcher(t).replaceAll("$1[redacted]");
        t = SCRUB_BEARER.matcher(t).replaceAll("$1 [redacted]");
        t = SCRUB_URL.matcher(t).replaceAll("$1[redacted]@");
        t = SCRUB_PAIR.matcher(t).replaceAll("$1[redacted]");
        t = SCRUB_LONG.matcher(t).replaceAll("[redacted]");
        return t.length() > 600 ? t.substring(0, 600) + "..." : t;
    }

    /** Scrub every string inside a JSON-like value (nesting deeper than 8 is left as it is, as the reference does). */
    public static Object scrubDeep(Object v) { return scrubDeep(v, 0); }

    private static Object scrubDeep(Object v, int depth) {
        if (v instanceof String) return scrubText(v);
        if (depth > 8 || v == null || !(v instanceof Map || v instanceof List)) return v;
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<?>) v) out.add(scrubDeep(x, depth + 1));
            return out;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) out.put((String) e.getKey(), scrubDeep(e.getValue(), depth + 1));
        return out;
    }

    // ---- fetch ----

    /** One HTTP response: the status and a header by lower-case name (null when absent). */
    public interface Response {
        int status();
        String header(String lowerName);
    }

    /** The doctor's HTTP client: {@code method} is HEAD or GET; redirects are not followed. */
    public interface Fetch {
        Response fetch(String method, String url, Map<String, String> headers, long timeoutMs) throws Exception;
    }

    /** The default client over {@link java.net.http.HttpClient}. */
    public static final class HttpFetch implements Fetch {
        private final HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

        @Override public Response fetch(String method, String url, Map<String, String> headers, long timeoutMs) throws IOException, InterruptedException {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofMillis(timeoutMs));
            for (Map.Entry<String, String> h : headers.entrySet()) b.header(h.getKey(), h.getValue());
            b.method(method, HttpRequest.BodyPublishers.noBody());
            HttpResponse<Void> r = client.send(b.build(), HttpResponse.BodyHandlers.discarding());
            return new Response() {
                @Override public int status() { return r.statusCode(); }
                @Override public String header(String n) { return r.headers().firstValue(n).orElse(null); }
            };
        }
    }

    // ---- clock ----

    public static final String DEFAULT_REFERENCE_URL = "https://www.google.com/generate_204";
    public static final String CLOCK_REMEDIATION =
        "Synchronise every verifier, issuer and replay-store host with NTP (chrony or systemd-timesyncd) and alert on drift. PCA tolerates at most 60 s between any two clocks (PCACTN_MAX_SKEW_MS); replay retention is exp + skew, so a clock outside that bound can free a nonce early or reject fresh actions.";

    /** One reading of a server's clock relative to the local one: remote minus local (ms) and its uncertainty, or an error. */
    public static final class DateReading {
        public final double offsetMs, uncertaintyMs;
        public final String error;
        DateReading(double offsetMs, double uncertaintyMs, String error) { this.offsetMs = offsetMs; this.uncertaintyMs = uncertaintyMs; this.error = error; }
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            if (error != null) m.put("error", error);
            else { m.put("offsetMs", offsetMs); m.put("uncertaintyMs", uncertaintyMs); }
            return m;
        }
    }

    /** One reading of the server's clock from its Date header (one-second resolution: +-0.5 s plus half the round trip). */
    public static DateReading readDate(String url, Fetch fetch, LongSupplier now, long timeoutMs) {
        double t0 = now.getAsLong();
        Response res;
        try {
            res = fetch.fetch("HEAD", url, new LinkedHashMap<>(), timeoutMs);
        } catch (Exception e) {
            return new DateReading(0, 0, "request failed: " + e.getMessage());
        }
        double t1 = now.getAsLong();
        String date = res.header("date");
        double d = date == null ? Double.NaN : Js.parseDate(date);
        if (Double.isNaN(d) || Double.isInfinite(d)) return new DateReading(0, 0, date == null ? "no Date header" : "unparseable Date header '" + date + "'");
        return new DateReading(d + 500 - (t0 + t1) / 2, 500 + (t1 - t0) / 2, null);
    }

    private static String signed(double ms) { return (ms >= 0 ? "+" : "-") + Js.toFixed1(Math.abs(ms) / 1000) + " s"; }

    private static Object section(Map<String, Object> cfg, String name) { return Js.g(cfg, name); }

    /** Clock skew of the deployment against a reference (the Date headers of both, or this machine's clock). */
    public static CheckResult checkClock(Map<String, Object> cfg, Fetch fetch, LongSupplier now) {
        LongSupplier clock = now != null ? now : System::currentTimeMillis;
        Object url = Js.g(cfg, "url");
        if (!Js.truthy(url)) return CheckResult.of("clock", "skip", "no deployment URL given (--url)");
        Object clockCfg = section(cfg, "clock");
        double max = Js.toNumber(Js.or(Js.g(clockCfg, "maxSkewMs"), (double) Pca.MAX_SKEW_MS));
        double warnAt = max * Js.toNumber(Js.or(Js.g(clockCfg, "warnFraction"), 0.25));
        long timeout = (long) Js.toNumber(Js.or(Js.g(clockCfg, "timeoutMs"), 10_000.0));
        DateReading dep = readDate(Js.str(url), fetch, clock, timeout);
        if (dep.error != null) {
            return CheckResult.of("clock", "warn", "cannot observe the deployment's clock at " + Js.str(url) + ": " + dep.error)
                .fix("Make the deployment answer with a Date header (RFC 9110 requires one from an origin with a clock), or check its clock on the host. " + CLOCK_REMEDIATION);
        }
        String refUrl = Js.str(Js.or(Js.g(clockCfg, "referenceUrl"), DEFAULT_REFERENCE_URL));
        DateReading ref = new DateReading(0, 0, null);
        String refName = "this machine's clock";
        String refNote = "";
        if (!refUrl.equals("local")) {
            DateReading r = readDate(refUrl, fetch, clock, timeout);
            if (r.error != null) refNote = " (reference " + refUrl + " unusable: " + r.error + "; compared with this machine's clock instead)";
            else { ref = r; refName = refUrl; }
        }
        double skew = dep.offsetMs - ref.offsetMs;
        double unc = dep.uncertaintyMs + ref.uncertaintyMs;
        double lower = Math.abs(skew) - unc;
        double upper = Math.abs(skew) + unc;
        // a skew, uncertainty or threshold that is not a number can show nothing: fail, never pass
        boolean measurable = Double.isFinite(lower) && Double.isFinite(upper) && !Double.isNaN(max) && !Double.isNaN(warnAt);
        String status = !measurable ? "fail" : lower > max ? "fail" : Math.abs(skew) > warnAt || upper > max ? "warn" : "pass";
        String detail = "deployment clock " + signed(skew) + " relative to " + refName + refNote + " (+-" + Js.toFixed1(unc / 1000) + " s: Date has 1 s resolution, plus round trips); "
            + "fail beyond " + Js.numStr(max / 1000) + " s, warn above " + Js.numStr(warnAt / 1000) + " s. The Date header is written by whatever answers the request (a CDN or proxy may set it).";
        CheckResult res = CheckResult.of("clock", status, detail);
        if (!status.equals("pass")) res.fix(CLOCK_REMEDIATION);
        Map<String, Object> obs = new LinkedHashMap<>();
        obs.put("skewMs", skew);
        obs.put("uncertaintyMs", unc);
        obs.put("maxSkewMs", max);
        obs.put("warnAtMs", warnAt);
        obs.put("reference", refName);
        return res.observed(obs);
    }

    // ---- proxy ----

    public static final String PROXY_REMEDIATION =
        "Set TRUSTED_PROXY_COUNT to exactly the number of reverse proxies in front of the API that APPEND to the trusted header (1 behind one load balancer / ingress; 0 when clients connect directly), and TRUSTED_PROXY_HEADER to the header they write. Too high lets a client pick its own rate-limit bucket with extra X-Forwarded-For entries; too low merges every client into the proxy's bucket.";

    /** The stated TRUSTED_PROXY_COUNT / TRUSTED_PROXY_HEADER against the stated number of appending proxies. */
    public static CheckResult checkProxyConfig(Map<String, Object> cfg) {
        Object p = Js.g(cfg, "proxy");
        Object n = Js.g(p, "trustedProxyCount");
        if (Js.isUndef(n)) return CheckResult.of("proxy.config", "skip", "TRUSTED_PROXY_COUNT not given (config proxy.trustedProxyCount or env TRUSTED_PROXY_COUNT)");
        Object header = Js.or(Js.g(p, "header"), "x-forwarded-for");
        String hs = Js.str(header);
        String ns = Js.str(n);
        if (!Js.isInteger(n) || Js.num(n) < 0 || Js.isNegZero(n) || Js.num(n) > 16) return fail("proxy.config", "TRUSTED_PROXY_COUNT=" + ns + " is not an integer in 0..16", PROXY_REMEDIATION);
        double nv = Js.num(n);
        if ("x-real-ip".equals(header) && nv == 0) return fail("proxy.config", "TRUSTED_PROXY_HEADER=x-real-ip needs TRUSTED_PROXY_COUNT >= 1 (with 0 every forwarding header is ignored)", PROXY_REMEDIATION);
        Object hops = Js.g(p, "hops");
        if (Js.isUndef(hops)) {
            CheckResult r = CheckResult.of("proxy.config", nv == 0 ? "pass" : "warn", "TRUSTED_PROXY_COUNT=" + ns + " (" + hs + "); the real number of appending proxies was not stated (proxy.hops / PCA_TRUSTED_PROXY_HOPS), so it cannot be compared");
            return nv == 0 ? r : r.fix(PROXY_REMEDIATION);
        }
        double h = Js.toNumber(hops);
        String hp = Js.str(hops);
        if (nv > h) return fail("proxy.config", "TRUSTED_PROXY_COUNT=" + ns + " is larger than the " + hp + " proxies in front of the API: a client chooses its own address (and rate-limit bucket) with extra " + hs + " entries", PROXY_REMEDIATION);
        if (nv < h) return CheckResult.of("proxy.config", "warn", "TRUSTED_PROXY_COUNT=" + ns + " is smaller than the " + hp + " proxies in front of the API: clients are keyed by a proxy's address and share its bucket").fix(PROXY_REMEDIATION);
        return CheckResult.of("proxy.config", "pass", "TRUSTED_PROXY_COUNT=" + ns + " (" + hs + ") matches the stated " + hp + " appending proxies");
    }

    private static CheckResult fail(String id, String detail, String remediation) { return CheckResult.of(id, "fail", detail).fix(remediation); }

    /** mulberry32: the seeded PRNG the reference vectors use (returns values in [0, 1)). */
    public static DoubleSupplier mulberry32(long seed) {
        int[] a = {(int) seed};
        return () -> {
            a[0] += 0x6d2b79f5;
            int t = a[0];
            t = (t ^ (t >>> 15)) * (t | 1);
            t ^= t + (t ^ (t >>> 7)) * (t | 61);
            return ((t ^ (t >>> 14)) & 0xffffffffL) / 4294967296.0;
        };
    }

    /** A random documentation address (RFC 5737 TEST-NET-2 / -3): never a real client. */
    public static String testNetIp(DoubleSupplier rand) {
        DoubleSupplier r = rand != null ? rand : Math::random;
        String net = r.getAsDouble() < 0.5 ? "198.51.100" : "203.0.113";
        return net + "." + (1 + (int) Math.floor(r.getAsDouble() * 254));
    }

    /** Forged values for all three forwarding headers at once (the server trusts at most one of them). */
    public static Map<String, String> forgedHeaders(DoubleSupplier rand) {
        DoubleSupplier r = rand != null ? rand : Math::random;
        List<String> chain = new ArrayList<>();
        for (int i = 0; i < 17; i++) chain.add(testNetIp(r));
        List<String> fors = new ArrayList<>();
        for (String ip : chain) fors.add("for=" + ip);
        Map<String, String> m = new LinkedHashMap<>();
        m.put("x-forwarded-for", String.join(", ", chain));
        m.put("forwarded", String.join(", ", fors));
        m.put("x-real-ip", testNetIp(r));
        return m;
    }

    private static Double remaining(Fetch fetch, String url, Map<String, String> headers, long timeoutMs) throws Exception {
        Response r = fetch.fetch("GET", url, headers, timeoutMs);
        String v = r.header("ratelimit-remaining");
        double n = v == null ? Double.NaN : Js.toNumber(v);
        return Double.isNaN(n) || Double.isInfinite(n) ? null : n;
    }

    /** {@code new URL(path, base).href} for the shapes a probe path takes (absolute URL, rooted path, relative path). */
    private static String resolveHref(String path, String base) {
        URI b;
        try {
            b = URI.create(base);
            if (b.getScheme() == null || b.getHost() == null) throw new IllegalArgumentException("Invalid URL");
            if (b.getRawPath() == null || b.getRawPath().isEmpty()) b = b.resolve("/");
            return b.resolve(path).toString();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid URL");
        }
    }

    private static Object remainingJson(Double d) { return d == null ? null : (Object) d; }

    /** Forged forwarding headers sent to a public rate-limited path: a forged request landing in a FRESH bucket means client-written entries are trusted. */
    public static CheckResult checkProxyProbe(Map<String, Object> cfg, Fetch fetch, DoubleSupplier rand) {
        String id = "proxy.probe";
        Object url = Js.g(cfg, "url");
        if (!Js.truthy(url)) return CheckResult.of(id, "skip", "no deployment URL given (--url)");
        Object proxy = Js.g(cfg, "proxy");
        if (Boolean.FALSE.equals(Js.g(proxy, "probe"))) return CheckResult.of(id, "skip", "disabled (--no-probe)");
        String target = resolveHref(Js.str(Js.or(Js.g(proxy, "probePath"), "/v1/pca/suites")), Js.str(url));
        long t = (long) Js.toNumber(Js.or(Js.g(section(cfg, "clock"), "timeoutMs"), 10_000.0));
        Double a, b, f, c;
        try {
            a = remaining(fetch, target, new LinkedHashMap<>(), t);
            b = remaining(fetch, target, new LinkedHashMap<>(), t);
            f = remaining(fetch, target, forgedHeaders(rand), t);
            c = remaining(fetch, target, new LinkedHashMap<>(), t);
        } catch (Exception e) {
            return CheckResult.of(id, "warn", "probe request to " + target + " failed: " + e.getMessage()).fix("Set proxy.probePath to a public, rate-limited path of the deployment, or run with --no-probe.");
        }
        Map<String, Object> observed = new LinkedHashMap<>();
        observed.put("url", target);
        List<Object> seq = new ArrayList<>(Arrays.asList(remainingJson(a), remainingJson(b), remainingJson(f), remainingJson(c)));
        observed.put("remaining", seq);
        if (a == null || b == null || f == null || c == null) {
            return CheckResult.of(id, "skip", "not observable remotely: " + target + " does not return a RateLimit-Remaining header on every response").observed(observed);
        }
        String sa = Js.numStr(a), sb = Js.numStr(b), sf = Js.numStr(f), sc = Js.numStr(c);
        if (!(b < a && c < b)) {
            return CheckResult.of(id, "warn", "inconclusive: the plain requests' bucket did not drain monotonically (" + sa + ", " + sb + ", then " + sc
                + "): a window rollover, a shared bucket or concurrent traffic. Re-run.").observed(observed);
        }
        if (f > b) {
            return CheckResult.of(id, "fail", "a request with FORGED forwarding headers got a fresh rate-limit bucket (remaining " + sf + ", while the plain requests' bucket was at " + sb
                + "): the deployment trusts client-written forwarding entries").fix(PROXY_REMEDIATION).observed(observed);
        }
        return CheckResult.of(id, "pass", "forged X-Forwarded-For / Forwarded / X-Real-IP did not move the client to another bucket (remaining " + sa + ", " + sb + ", forged " + sf + ", " + sc
            + "). A count that is too LOW is not observable from one client.").observed(observed);
    }

    // ---- suites ----

    public static final String SUITES_REMEDIATION =
        "Set the verifier's allowedSuites to exactly the suites your issuers sign with (names from SIG_SUITES), e.g. ['ed25519'] or ['hybrid-ed25519-ml-dsa-65'].";
    public static final String PQ_REMEDIATION =
        "Never set allowUnboundPq. For pure-PQ or hybrid roots, configure pqPins (issuer Ed25519 identity -> PQ public key, from pqPinFor) or verify against your stored root grant (trustedRoot; requirePCA / verifyPCActnCore do this).";

    private static final Pattern B64U = Pattern.compile("[A-Za-z0-9_-]+");
    private static final Pattern ED25519_ID = Pattern.compile("[A-Za-z0-9_-]{43}");

    private static boolean isPq(Object alg) { return alg instanceof String && !alg.equals("ed25519") && Pq.REGISTERED_SUITES.contains(alg); }

    /** allowedSuites against the closed suite registry (the library's registered suite names, in registry order). */
    public static CheckResult checkAllowedSuites(Map<String, Object> cfg) { return checkAllowedSuites(cfg, Pq.REGISTERED_SUITES); }

    public static CheckResult checkAllowedSuites(Map<String, Object> cfg, List<String> registry) {
        String id = "suites.allowed";
        Object v = Js.g(cfg, "verifier");
        if (!Js.truthy(v)) return CheckResult.of(id, "skip", "no verifier configuration given (config verifier.*)");
        Object list = Js.g(v, "allowedSuites");
        String known = String.join(", ", registry);
        if (Js.isUndef(list)) {
            return CheckResult.of(id, "warn", "allowedSuites is unset: every registered suite is accepted (" + registry.size() + ": " + known + ")").fix(SUITES_REMEDIATION);
        }
        if (!(list instanceof List) || ((List<?>) list).isEmpty()) {
            return CheckResult.of(id, "fail", "allowedSuites is empty or not a list: no PCActn can verify").fix(SUITES_REMEDIATION);
        }
        List<String> unknown = new ArrayList<>();
        for (Object s : (List<?>) list) if (!(s instanceof String) || !registry.contains(s)) unknown.add(Js.str(s));
        if (!unknown.isEmpty()) {
            return CheckResult.of(id, "fail", "allowedSuites names suite(s) outside the registry: " + String.join(", ", unknown) + " (known: " + known + ")").fix(SUITES_REMEDIATION);
        }
        List<String> names = new ArrayList<>();
        for (Object x : (List<?>) list) names.add(Js.str(x));
        return CheckResult.of(id, "pass", "allowedSuites = " + String.join(", ", names));
    }

    /** allowUnboundPq / pqPins / trustedRoot sanity. */
    public static CheckResult checkPqBinding(Map<String, Object> cfg) {
        String id = "suites.pq-binding";
        Object v = Js.g(cfg, "verifier");
        if (!Js.truthy(v)) return CheckResult.of(id, "skip", "no verifier configuration given (config verifier.*)");
        if (Boolean.TRUE.equals(Js.g(v, "allowUnboundPq"))) {
            return fail(id, "allowUnboundPq is set: PQ keys are read from the artifact, so a hybrid gives no protection against an Ed25519 forger and a pure-PQ hop can be signed by any key", PQ_REMEDIATION);
        }
        Object pins = Js.g(v, "pqPins");
        if (!Js.isUndef(pins)) {
            if (!Js.truthy(pins) || !(pins instanceof Map)) return fail(id, "pqPins is not an object of { ed25519 identity: pq public key }", PQ_REMEDIATION);
            List<String> bad = new ArrayList<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) pins).entrySet()) {
                String k = (String) e.getKey();
                Object val = e.getValue();
                if (!ED25519_ID.matcher(k).matches() || !(val instanceof String) || !B64U.matcher((String) val).matches()) bad.add(k);
            }
            if (!bad.isEmpty()) {
                return fail(id, "pqPins has malformed entries (key must be a 43-char base64url Ed25519 identity, value a base64url PQ key): " + String.join(", ", bad), PQ_REMEDIATION);
            }
        }
        Object allowed = Js.or(Js.g(v, "allowedSuites"), new ArrayList<Object>(Pq.REGISTERED_SUITES));
        if (!(allowed instanceof List)) throw new IllegalStateException("allowedSuites is not a list");
        List<String> pq = new ArrayList<>();
        for (Object s : (List<?>) allowed) if (isPq(s)) pq.add((String) s);
        if (pq.isEmpty()) return CheckResult.of(id, "pass", "no post-quantum suite is accepted (Ed25519 only: no PQ binding needed, and no PQ protection)");
        boolean pinned = !Js.isUndef(pins) && !((Map<?, ?>) pins).isEmpty();
        if (!pinned && !Boolean.TRUE.equals(Js.g(v, "trustedRoot"))) {
            return CheckResult.of(id, "warn", "post-quantum suite(s) accepted (" + String.join(", ", pq)
                + ") with neither pqPins nor a stored trustedRoot: a non-Ed25519 root is refused (fail closed) or its PQ key is not pinned").fix(PQ_REMEDIATION);
        }
        return CheckResult.of(id, "pass", "PQ suites (" + String.join(", ", pq) + ") are bound: " + (pinned ? ((Map<?, ?>) pins).size() + " pin(s)" : "stored trustedRoot") + "; allowUnboundPq off");
    }

    // ---- replay store remediation texts ----

    public static final String ATOMICITY_REMEDIATION =
        "Make consumeOnce / advance one atomic operation on the shared store, e.g. Postgres INSERT .. ON CONFLICT (key) DO UPDATE .. WHERE until < $now RETURNING and UPDATE .. WHERE counter < $n RETURNING, Redis SET key NX PX or a Lua compare-and-set; never read, then write. Then run the full kit: pca-store-conformance --adapter <your adapter>.";
    public static final String DURABILITY_REMEDIATION =
        "Keep consumed keys and counters in a store with synchronous, persistent commits (Postgres synchronous_commit=on; Redis appendfsync always and maxmemory-policy noeviction), shared by every verifier instance. An in-memory store is only correct for a single process whose lifetime covers the action lifetime.";

    // ---- root caveats and enforcement ----

    public static final String ROOT_CAVEAT_MIN_VERSION = "0.4.1";
    public static final String CAVEAT_REMEDIATION =
        "Upgrade @atlasauth/pca to >= 0.4.1 in the deployed application (root caveats outside the envelope are enforced from 0.4.1), redeploy, and re-run pca-doctor with --pca-dir pointing at the application.";
    public static final List<String> DEFAULT_REQUIRED = List.of("counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound");

    /** The decision of one probe: whether the payment was allowed, and the reasons given. */
    public static final class Decision {
        public final boolean allowed;
        public final List<String> reasons;
        public Decision(boolean allowed, List<String> reasons) { this.allowed = allowed; this.reasons = reasons; }
        Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("allowed", allowed);
            m.put("reasons", new ArrayList<Object>(reasons));
            return m;
        }
    }

    /** Decide a payment of {@code amount} USD under a root grant carrying {@code rootCaveat}, through the library under test. */
    public interface Probe {
        Decision decide(Map<String, Object> rootCaveat, double amount) throws Exception;
    }

    /** The library under test: its version, where it was found, and how to probe it. */
    public static final class LoadedPca {
        public final String version, path;
        public final Probe probe;
        public LoadedPca(String version, String path, Probe probe) { this.version = version; this.path = path; this.probe = probe; }
    }

    /** -1 / 0 / 1 for a &lt; b / = / &gt; over major.minor.patch (pre-release tags ignored); NaN parts compare as -1. */
    public static int compareVersion(String a, String b) {
        String[] pa = a.split("[.+-]", -1), pb = b.split("[.+-]", -1);
        for (int i = 0; i < 3; i++) {
            double x = i < pa.length ? Js.toNumber(pa[i]) : Double.NaN;
            double y = i < pb.length ? Js.toNumber(pb[i]) : Double.NaN;
            if (Double.isNaN(x) || Double.isInfinite(x)) x = -1;
            if (Double.isNaN(y) || Double.isInfinite(y)) y = -1;
            if (x != y) return x < y ? -1 : 1;
        }
        return 0;
    }

    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    /** Root-caveat enforcement of the deployed library: version >= 0.4.1, and a probe (max_spend 100 denies 150 and allows 50; an unknown caveat type denies). */
    public static CheckResult checkRootCaveats(Map<String, Object> cfg, Function<String, LoadedPca> loadPca) {
        String id = "caveats.root";
        Object dir = Js.g(Js.g(cfg, "verifier"), "pcaDir");
        String pcaDir = Js.truthy(dir) ? Js.str(dir) : null;
        LoadedPca pca;
        try {
            Function<String, LoadedPca> ld = loadPca != null ? loadPca : Doctor::noLoader;
            pca = ld.apply(pcaDir);
        } catch (RuntimeException e) {
            return CheckResult.of(id, "fail", "cannot load @atlasauth/pca" + (pcaDir != null ? " from " + pcaDir : "") + ": " + e.getMessage()).fix(CAVEAT_REMEDIATION);
        }
        String where = "@atlasauth/pca " + pca.version + " at " + pca.path;
        if (compareVersion(pca.version, ROOT_CAVEAT_MIN_VERSION) < 0) {
            return CheckResult.of(id, "fail", where + ": root caveats outside the envelope are NOT enforced before " + ROOT_CAVEAT_MIN_VERSION + " (legacy behaviour)").fix(CAVEAT_REMEDIATION);
        }
        Decision over, under, unknown;
        try {
            over = pca.probe.decide(obj("type", "max_spend", "usd", 100), 150);
            under = pca.probe.decide(obj("type", "max_spend", "usd", 100), 50);
            unknown = pca.probe.decide(obj("type", "pca-doctor-unknown-caveat"), 50);
        } catch (Exception e) {
            return CheckResult.of(id, "fail", where + ": the enforcement probe could not run: " + e.getMessage()).fix(CAVEAT_REMEDIATION);
        }
        Map<String, Object> observed = obj("version", pca.version, "over", over.toJson(), "under", under.toJson(), "unknown", unknown.toJson());
        if (over.allowed || unknown.allowed) {
            return CheckResult.of(id, "fail", where + ": a root caveat was NOT enforced (" + (over.allowed ? "max_spend 100 allowed a 150 payment" : "an unknown root caveat type was allowed") + ")")
                .fix(CAVEAT_REMEDIATION).observed(observed);
        }
        if (!under.allowed) {
            return CheckResult.of(id, "warn", where + ": inconclusive: the control payment within the root max_spend was denied too (" + String.join("; ", under.reasons) + ")").observed(observed);
        }
        return CheckResult.of(id, "pass", where + ": root caveats enforced (max_spend 100 denies 150, allows 50; an unknown root caveat type denies)").observed(observed);
    }

    private static LoadedPca noLoader(String dir) {
        throw new IllegalStateException("no @atlasauth/pca loader is configured (the JVM cannot load the deployed library; supply a loader that probes it)");
    }

    /** requirePCA must not run with insecureAllowUnenforced, and a custom require list should keep the defaults. */
    public static CheckResult checkEnforcement(Map<String, Object> cfg) {
        String id = "verifier.enforcement";
        Object v = Js.g(cfg, "verifier");
        if (!Js.truthy(v)) return CheckResult.of(id, "skip", "no verifier configuration given (config verifier.*)");
        if (Boolean.TRUE.equals(Js.g(v, "insecureAllowUnenforced"))) {
            return fail(id, "requirePCA runs with insecureAllowUnenforced: required checks that are not enforced do not deny", "Remove insecureAllowUnenforced and supply the stores the required checks need (counter / revocation / budget).");
        }
        Object req = Js.g(v, "require");
        if (!Js.isUndef(req)) {
            if (req == null) throw new NullPointerException("Cannot read properties of null (reading 'includes')");
            List<String> missing = new ArrayList<>();
            for (String c : DEFAULT_REQUIRED) {
                boolean has;
                if (req instanceof List) has = ((List<?>) req).contains(c);
                else if (req instanceof String) has = ((String) req).contains(c);
                else throw new IllegalStateException("require.includes is not a function");
                if (!has) missing.add(c);
            }
            if (!missing.isEmpty()) {
                return CheckResult.of(id, "warn", "the require list drops default check(s): " + String.join(", ", missing)).fix("Keep every default required check (" + String.join(", ", DEFAULT_REQUIRED) + ") and add to it.");
            }
        }
        if (Js.truthy(req)) {
            if (!(req instanceof List)) throw new IllegalStateException("require.join is not a function");
            List<String> parts = new ArrayList<>();
            for (Object x : (List<?>) req) parts.add(Js.nullish(x) ? "" : Js.str(x));
            return CheckResult.of(id, "pass", "require = " + String.join(", ", parts));
        }
        return CheckResult.of(id, "pass", "default required checks; insecureAllowUnenforced off");
    }

    // ---- runDoctor ----

    public static final List<String> CHECK_GROUPS = List.of("clock", "store", "proxy", "suites", "caveats");

    /** Collaborators of {@link #runDoctor}; every member is optional (real HTTP, the wall clock, no library loader). */
    public static final class DoctorDeps {
        public Fetch fetch;
        public LongSupplier now;
        public Function<String, LoadedPca> loadPca;
        public DoubleSupplier rand;
    }

    private interface Run { List<CheckResult> run() throws Exception; }

    /** One check group that throws is a failed check, not a crashed run and not a skipped one. */
    private static List<CheckResult> guarded(String id, Run run) {
        try {
            return run.run();
        } catch (Exception e) {
            List<CheckResult> l = new ArrayList<>();
            l.add(CheckResult.of(id, "fail", id + " could not run: " + scrubText(e.getMessage() == null ? e.toString() : e.getMessage())).fix("Fix the configuration or the dependency named above and run the doctor again."));
            return l;
        }
    }

    private static List<CheckResult> one(CheckResult r) { List<CheckResult> l = new ArrayList<>(); l.add(r); return l; }

    /** Numeric settings that would make a check meaningless (NaN, negative, zero where a duration is needed) are configuration errors. */
    public static List<String> configProblems(Map<String, Object> cfg) {
        List<String> out = new ArrayList<>();
        Object clock = Js.g(cfg, "clock"), store = Js.g(cfg, "store"), proxy = Js.g(cfg, "proxy");
        pos(out, "clock.maxSkewMs", Js.g(clock, "maxSkewMs"), false);
        pos(out, "clock.timeoutMs", Js.g(clock, "timeoutMs"), false);
        Object wf = Js.g(clock, "warnFraction");
        if (!Js.isUndef(wf)) {
            Double d = Js.num(wf);
            if (!(d != null && d > 0 && d <= 1)) out.add("clock.warnFraction must be a number in (0, 1]");
        }
        pos(out, "store.concurrency", Js.g(store, "concurrency"), true);
        pos(out, "store.rounds", Js.g(store, "rounds"), true);
        nonneg(out, "proxy.trustedProxyCount", Js.g(proxy, "trustedProxyCount"));
        nonneg(out, "proxy.hops", Js.g(proxy, "hops"));
        Object url = Js.g(cfg, "url");
        if (!Js.isUndef(url)) {
            try {
                if (!(url instanceof String)) throw new IllegalArgumentException("not a URL");
                URI u = URI.create((String) url);
                if (u.getScheme() == null) throw new IllegalArgumentException("not a URL");
                String sch = u.getScheme().toLowerCase(java.util.Locale.ROOT);
                if (sch.equals("https") || sch.equals("http")) {
                    if (u.getHost() == null) throw new IllegalArgumentException("not a URL");
                } else out.add("url must be an http(s) URL");
            } catch (IllegalArgumentException e) {
                out.add("url is not a valid URL");
            }
        }
        return out;
    }

    private static void pos(List<String> out, String name, Object v, boolean integer) {
        if (Js.isUndef(v)) return;
        Double d = Js.num(v);
        if (d == null || Double.isNaN(d) || Double.isInfinite(d) || d <= 0 || (integer && !Js.isInteger(v))) out.add(name + " must be a positive " + (integer ? "integer" : "number"));
    }

    private static void nonneg(List<String> out, String name, Object v) {
        if (Js.isUndef(v)) return;
        if (!Js.isInteger(v) || Js.num(v) < 0 || Js.isNegZero(v)) out.add(name + " must be a non-negative integer");
    }

    /** Run the selected check groups (all by default) and scrub everything they report. */
    public static List<CheckResult> runDoctor(Map<String, Object> cfg, List<String> only, DoctorDeps deps) {
        DoctorDeps d = deps != null ? deps : new DoctorDeps();
        List<String> sel = only != null ? only : CHECK_GROUPS;
        List<String> problems = configProblems(cfg);
        if (!problems.isEmpty()) {
            List<CheckResult> out = new ArrayList<>();
            for (String p : problems) out.add(CheckResult.of("config", "fail", scrubText("invalid configuration: " + p)).fix("Correct the setting; no check was run."));
            return out;
        }
        Fetch fetch = d.fetch != null ? d.fetch : new HttpFetch();
        List<CheckResult> out = new ArrayList<>();
        if (sel.contains("clock")) out.addAll(guarded("clock", () -> one(checkClock(cfg, fetch, d.now))));
        if (sel.contains("store")) out.addAll(guarded("store", () -> DoctorStore.checkStore(cfg)));
        if (sel.contains("proxy")) {
            out.addAll(guarded("proxy.config", () -> one(checkProxyConfig(cfg))));
            out.addAll(guarded("proxy.probe", () -> one(checkProxyProbe(cfg, fetch, d.rand))));
        }
        if (sel.contains("suites")) {
            out.addAll(guarded("suites.allowed", () -> one(checkAllowedSuites(cfg))));
            out.addAll(guarded("suites.pq", () -> one(checkPqBinding(cfg))));
        }
        if (sel.contains("caveats")) {
            out.addAll(guarded("caveats.root", () -> one(checkRootCaveats(cfg, d.loadPca))));
            out.addAll(guarded("caveats.enforcement", () -> one(checkEnforcement(cfg))));
        }
        List<CheckResult> scrubbed = new ArrayList<>();
        for (CheckResult r : out) {
            @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) scrubDeep(r.json);
            scrubbed.add(CheckResult.fromJson(m));
        }
        return scrubbed;
    }

    /** fail if any check failed; warn if any warned (fail under strict); else pass. A run in which nothing was checked is a fail. */
    public static String verdictOf(List<CheckResult> results, boolean strict) {
        boolean any = false, fail = false, warn = false;
        for (CheckResult r : results) {
            String s = r.status();
            if (!s.equals("skip")) any = true;
            if (s.equals("fail")) fail = true;
            if (s.equals("warn")) warn = true;
        }
        if (!any) return "fail";
        if (fail) return "fail";
        if (warn) return strict ? "fail" : "warn";
        return "pass";
    }

    public static String formatResults(List<CheckResult> results, String target, boolean strict) {
        List<String> lines = new ArrayList<>();
        lines.add("pca-doctor" + (target != null && !target.isEmpty() ? ": " + target : ""));
        for (CheckResult r : results) {
            lines.add("  " + Js.padEnd(r.status().toUpperCase(java.util.Locale.ROOT), 4) + "  " + Js.padEnd(r.id(), 20) + " " + r.detail());
            if (r.remediation() != null) lines.add("  " + Js.padEnd("", 4) + "  " + Js.padEnd("", 20) + " fix: " + r.remediation());
        }
        boolean anyChecked = false;
        int[] n = new int[4];
        String[] names = {"pass", "warn", "fail", "skip"};
        for (CheckResult r : results) {
            if (!r.status().equals("skip")) anyChecked = true;
            for (int i = 0; i < 4; i++) if (r.status().equals(names[i])) n[i]++;
        }
        if (!anyChecked) lines.add("  FAIL  nothing checked        no check produced a result: nothing about this deployment was verified");
        lines.add("Summary: " + n[0] + " pass, " + n[1] + " warn, " + n[2] + " fail, " + n[3] + " skip -> " + verdictOf(results, strict).toUpperCase(java.util.Locale.ROOT));
        return String.join("\n", lines);
    }

    // ---- configuration ----

    private static final Pattern TRUTHY = Pattern.compile("1|true|yes|on", Pattern.CASE_INSENSITIVE);
    private static final List<String> PROXY_HEADERS = List.of("x-forwarded-for", "forwarded", "x-real-ip");

    private static Object envInt(String name, String v) {
        if (v == null || v.isEmpty()) return Js.UNDEF;
        double n = Js.toNumber(v);
        if (Double.isNaN(n) || Double.isInfinite(n) || n != Math.rint(n) || n < 0 || (n == 0 && 1 / n < 0)) throw new IllegalArgumentException(name + " must be a non-negative integer");
        return n;
    }

    private static boolean has(String v) { return v != null && !v.isEmpty(); }

    /** The deployment's own environment variable names (as the API and the guides use them). */
    public static Map<String, Object> configFromEnv(Map<String, String> env) {
        Map<String, Object> c = new LinkedHashMap<>();
        if (has(env.get("PCA_DOCTOR_URL"))) c.put("url", env.get("PCA_DOCTOR_URL"));
        if (has(env.get("PCA_DOCTOR_REFERENCE_URL"))) c.put("clock", obj("referenceUrl", env.get("PCA_DOCTOR_REFERENCE_URL")));
        if (has(env.get("PCA_DOCTOR_STORE"))) c.put("store", obj("adapter", env.get("PCA_DOCTOR_STORE")));
        Map<String, Object> proxy = new LinkedHashMap<>();
        if (env.get("TRUSTED_PROXY_COUNT") != null) proxy.put("trustedProxyCount", envInt("TRUSTED_PROXY_COUNT", env.get("TRUSTED_PROXY_COUNT")));
        if (has(env.get("TRUSTED_PROXY_HEADER"))) {
            String h = env.get("TRUSTED_PROXY_HEADER").toLowerCase(java.util.Locale.ROOT);
            if (!PROXY_HEADERS.contains(h)) throw new IllegalArgumentException("TRUSTED_PROXY_HEADER must be one of " + String.join(", ", PROXY_HEADERS));
            proxy.put("header", h);
        }
        if (env.get("PCA_TRUSTED_PROXY_HOPS") != null) proxy.put("hops", envInt("PCA_TRUSTED_PROXY_HOPS", env.get("PCA_TRUSTED_PROXY_HOPS")));
        if (!proxy.isEmpty()) c.put("proxy", proxy);
        Map<String, Object> v = new LinkedHashMap<>();
        if (env.get("PCA_ALLOWED_SUITES") != null) {
            List<Object> suites = new ArrayList<>();
            for (String s : env.get("PCA_ALLOWED_SUITES").split(",", -1)) { String t = Js.trim(s); if (!t.isEmpty()) suites.add(t); }
            v.put("allowedSuites", suites);
        }
        if (has(env.get("PCA_PQ_PINS"))) {
            Object pins;
            try {
                pins = Json.parseLenient(env.get("PCA_PQ_PINS"));
            } catch (RuntimeException e) {
                throw new IllegalArgumentException("PCA_PQ_PINS is not valid JSON"); // never echo the value
            }
            boolean ok = pins instanceof Map;
            if (ok) for (Object x : ((Map<?, ?>) pins).values()) if (!(x instanceof String)) ok = false;
            if (!ok) throw new IllegalArgumentException("PCA_PQ_PINS must be a JSON object of issuer -> public key strings");
            v.put("pqPins", pins);
        }
        if (env.get("PCA_ALLOW_UNBOUND_PQ") != null) v.put("allowUnboundPq", TRUTHY.matcher(env.get("PCA_ALLOW_UNBOUND_PQ")).matches());
        if (!v.isEmpty()) c.put("verifier", v);
        return c;
    }

    @SuppressWarnings("unchecked")
    private static void spreadInto(Map<String, Object> into, Object base) {
        if (base instanceof Map) into.putAll((Map<String, Object>) base);
        else if (base instanceof List) { List<Object> l = (List<Object>) base; for (int i = 0; i < l.size(); i++) into.put(Integer.toString(i), l.get(i)); }
        else if (base instanceof String) { String s = (String) base; for (int i = 0; i < s.length(); i++) into.put(Integer.toString(i), s.substring(i, i + 1)); }
    }

    /** Two-level merge: later sources win per field inside each section. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> mergeConfig(List<Map<String, Object>> cs) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map<String, Object> c : cs) {
            for (Map.Entry<String, Object> e : c.entrySet()) {
                String k = e.getKey();
                Object val = e.getValue();
                if (k.equals("__proto__") || k.equals("constructor") || k.equals("prototype")) throw new IllegalArgumentException("config key \"" + k + "\" is not allowed");
                if (val == Js.UNDEF) continue;
                if (Js.truthy(val) && val instanceof Map) {
                    Map<String, Object> merged = new LinkedHashMap<>();
                    Object prev = out.get(k);
                    if (prev != null && prev != Js.UNDEF) spreadInto(merged, prev);
                    merged.putAll((Map<String, Object>) val);
                    out.put(k, merged);
                } else out.put(k, val);
            }
        }
        return out;
    }

    /** A JSON file. shortcut: the reference also loads a JS module exporting the config; that has no JVM counterpart, upgrade by loading a Java class if ever needed. */
    public static Map<String, Object> loadConfigFile(String path) throws IOException {
        if (!path.endsWith(".json")) throw new UnsupportedOperationException("only a .json config file can be loaded: " + path);
        Object v = Json.parseLenient(Files.readString(Path.of(path), StandardCharsets.UTF_8));
        if (!(v instanceof Map)) throw new IllegalArgumentException("config file is not a JSON object: " + path);
        @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) v;
        return m;
    }

    // ---- CLI ----

    public static final String USAGE = "pca-doctor [--url <deployment>] [options]\n\n"
        + "  --url URL              the live deployment (base URL of the API that verifies PCActns)\n"
        + "  --config FILE          JSON or JS config (see the pca-doctor guide); env and flags override it\n"
        + "  --store MODULE         replay-store adapter module (store conformance kit interface) for the atomicity / durability checks\n"
        + "  --store-option k=v     passed to the adapter factory (repeatable)\n"
        + "  --reference URL|local  clock reference (default https://www.google.com/generate_204)\n"
        + "  --max-skew-ms N        clock fail threshold (default 60000)\n"
        + "  --trusted-proxy-count N, --proxy-header H, --proxy-hops N   the deployment's proxy settings and the real hop count\n"
        + "  --pca-dir DIR          the deployed application's directory (its installed @atlasauth/pca is probed)\n"
        + "  --only a,b | --skip a,b   check groups: " + String.join(", ", CHECK_GROUPS) + "\n"
        + "  --no-probe             do not send forged forwarding headers to the deployment\n"
        + "  --strict               warnings fail too\n"
        + "  --json                 machine-readable output\n\n"
        + "Env: PCA_DOCTOR_URL, PCA_DOCTOR_REFERENCE_URL, PCA_DOCTOR_STORE, TRUSTED_PROXY_COUNT, TRUSTED_PROXY_HEADER, PCA_TRUSTED_PROXY_HOPS,\n"
        + "     PCA_ALLOWED_SUITES (comma list), PCA_PQ_PINS (JSON), PCA_ALLOW_UNBOUND_PQ.";

    private static List<String> groups(String flag, String v) {
        List<String> g = new ArrayList<>();
        for (String x : (v == null ? "" : v).split(",", -1)) if (!x.isEmpty()) g.add(x);
        List<String> bad = new ArrayList<>();
        for (String x : g) if (!CHECK_GROUPS.contains(x)) bad.add(x);
        if (!bad.isEmpty() || g.isEmpty()) throw new IllegalArgumentException(flag + ": unknown check group(s) " + (bad.isEmpty() ? "(none given)" : String.join(", ", bad)));
        return g;
    }

    private static double numArg(String flag, String v) {
        double n = v == null || v.isEmpty() ? Double.NaN : Js.toNumber(v);
        if (Double.isNaN(n) || Double.isInfinite(n)) throw new IllegalArgumentException(flag + " needs a number");
        return n;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> sub(Map<String, Object> flags, String k) {
        Map<String, Object> m = new LinkedHashMap<>();
        Object cur = flags.get(k);
        if (cur instanceof Map) m.putAll((Map<String, Object>) cur);
        flags.put(k, m);
        return m;
    }

    /** The parsed command line: {@code flags} (a config), {@code only}, {@code json}, {@code strict}, {@code help} and an optional {@code config} path. */
    public static Map<String, Object> parseDoctorArgs(List<String> argv) {
        Map<String, Object> flags = new LinkedHashMap<>();
        List<String> only = new ArrayList<>(CHECK_GROUPS);
        boolean json = false, strict = false, help = false;
        String config = null;
        for (int i = 0; i < argv.size(); i++) {
            String k = argv.get(i);
            String nx = i + 1 < argv.size() ? argv.get(i + 1) : null; // next() consumes even when absent
            switch (k) {
                case "--url": i++; flags.put("url", nx == null ? Js.UNDEF : nx); break;
                case "--config": i++; config = nx; break;
                case "--store": i++; sub(flags, "store").put("adapter", nx == null ? Js.UNDEF : nx); break;
                case "--store-option": {
                    i++;
                    String kv = nx == null ? "" : nx;
                    int eq = kv.indexOf('=');
                    if (eq < 1) throw new IllegalArgumentException("--store-option needs k=v");
                    Map<String, Object> st = sub(flags, "store");
                    Map<String, Object> opts = new LinkedHashMap<>();
                    Object cur = st.get("options");
                    if (cur instanceof Map) { @SuppressWarnings("unchecked") Map<String, Object> cm = (Map<String, Object>) cur; opts.putAll(cm); }
                    opts.put(kv.substring(0, eq), kv.substring(eq + 1));
                    st.put("options", opts);
                    break;
                }
                case "--reference": i++; sub(flags, "clock").put("referenceUrl", nx == null ? Js.UNDEF : nx); break;
                case "--max-skew-ms": i++; sub(flags, "clock").put("maxSkewMs", numArg(k, nx)); break;
                case "--trusted-proxy-count": i++; sub(flags, "proxy").put("trustedProxyCount", numArg(k, nx)); break;
                case "--proxy-header": {
                    i++;
                    String h = (nx == null ? "" : nx).toLowerCase(java.util.Locale.ROOT);
                    if (!PROXY_HEADERS.contains(h)) throw new IllegalArgumentException("--proxy-header must be x-forwarded-for, forwarded or x-real-ip");
                    sub(flags, "proxy").put("header", h);
                    break;
                }
                case "--proxy-hops": i++; sub(flags, "proxy").put("hops", numArg(k, nx)); break;
                case "--no-probe": sub(flags, "proxy").put("probe", false); break;
                case "--pca-dir": i++; sub(flags, "verifier").put("pcaDir", nx == null ? Js.UNDEF : nx); break;
                case "--only": i++; only = groups(k, nx); break;
                case "--skip": {
                    i++;
                    List<String> s = groups(k, nx);
                    List<String> keep = new ArrayList<>();
                    for (String g : only) if (!s.contains(g)) keep.add(g);
                    only = keep;
                    break;
                }
                case "--strict": strict = true; break;
                case "--json": json = true; break;
                case "-h": case "--help": help = true; break;
                default: throw new IllegalArgumentException("unknown argument " + k);
            }
        }
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("flags", flags);
        a.put("only", new ArrayList<Object>(only));
        a.put("json", json);
        a.put("strict", strict);
        a.put("help", help);
        if (config != null) a.put("config", config);
        return a;
    }

    /** Run the CLI: exit code 1 on any fail (and on warn under --strict), 2 on usage errors, else 0. */
    @SuppressWarnings("unchecked")
    public static int main(List<String> argv, Map<String, String> env, Consumer<String> print, Consumer<String> printErr, DoctorDeps deps) {
        Map<String, Object> a;
        Map<String, Object> cfg;
        try {
            a = parseDoctorArgs(argv);
            if (Boolean.TRUE.equals(a.get("help"))) {
                print.accept(USAGE);
                return 0;
            }
            List<Map<String, Object>> sources = new ArrayList<>();
            sources.add(a.get("config") != null ? loadConfigFile((String) a.get("config")) : new LinkedHashMap<String, Object>());
            sources.add(configFromEnv(env));
            sources.add((Map<String, Object>) a.get("flags"));
            cfg = mergeConfig(sources);
        } catch (Exception e) {
            printErr.accept(scrubText(e.getMessage()) + "\n\n" + USAGE);
            return 2;
        }
        List<CheckResult> results = runDoctor(cfg, (List<String>) (List<?>) a.get("only"), deps);
        boolean strict = Boolean.TRUE.equals(a.get("strict"));
        String verdict = verdictOf(results, strict);
        Object url = Js.g(cfg, "url");
        if (Boolean.TRUE.equals(a.get("json"))) {
            List<Object> rs = new ArrayList<>();
            for (CheckResult r : results) rs.add(r.json);
            Map<String, Object> doc = new LinkedHashMap<>();
            doc.put("target", Js.nullish(url) ? null : url);
            doc.put("verdict", verdict);
            doc.put("results", rs);
            print.accept(Js.stringify(doc));
        } else {
            print.accept(formatResults(results, Js.truthy(url) ? Js.str(url) : null, strict));
        }
        return verdict.equals("fail") ? 1 : 0;
    }

    /** Command-line entry: {@code java net.atlasauth.pca.doctor.Doctor [options]}. */
    public static void main(String[] args) {
        int code = main(Arrays.asList(args), System.getenv(), System.out::println, System.err::println, null);
        System.exit(code);
    }
}
