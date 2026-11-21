package net.atlasauth.pca.notary;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import net.atlasauth.pca.GrantSigning;
import net.atlasauth.pca.IntentJs;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.W3Bridge;

/**
 * External-fact attestation for proof-carrying actions (the zkTLS / TLSNotary direction). A NOTARY witnesses one HTTP request/response
 * and signs a canonical record of it: method, URL, a digest of the request headers, the response status and a salted-Merkle
 * COMMITMENT to the response body. The prover can later disclose ONE field with an inclusion proof while every other field stays
 * hidden (each leaf carries a random salt), and bind the fact to a specific PCActn. Port of {@code @atlasauth/pca-notary}.
 *
 * <p>TRUST BOUNDARY: this relies on a trusted or semi-trusted notary that actually observed the TLS session. It is not trustless zkTLS
 * (MPC-TLS): a colluding or compromised notary can attest anything. Every verification fails CLOSED.
 *
 * <p>Values are JSON-shaped: maps with the reference's member names, {@link List}s, {@link String}s, {@link Json.Num} / {@link Long} /
 * {@link Integer} numbers. A key is a b64u {@link String}, raw {@code byte[]} (public key) or a {@link Keys.EdKey}.
 */
public final class Notary {
    private Notary() {}

    /** Algorithm tag for the body commitment (salted RFC-6962-shape Merkle tree over SHA-256). */
    public static final String BODY_COMMIT_ALG = "salted-merkle-sha256-v1";
    /** Caveat type tag for "this action is admitted only if a notarized external fact holds". */
    public static final String ATTESTED_FACT_CAVEAT = "attested_fact";

    private static final String NOTARY_DOMAIN = "atlas-pca/notary/v1\0";

    // ---- helpers ----

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> asList(Object o) { return o instanceof List ? (List<Object>) o : null; }

    /** Number.isSafeInteger over the JSON-shaped values (a -0 lexeme counts, as in JavaScript). */
    private static boolean isSafeIntJs(Object o) {
        if (o instanceof Json.Num && ((Json.Num) o).raw.equals("-0")) return true;
        return Json.isSafeInt(o);
    }

    private static boolean isNegZero(Object o) { return o instanceof Json.Num && ((Json.Num) o).raw.equals("-0"); }

    /** {@code o === 1} for a JSON-shaped value. */
    private static boolean isOne(Object o) { return Json.isSafeInt(o) && Json.asLong(o) == 1; }

    /** The JavaScript number a JSON-shaped number is, or null for a non-number. */
    private static Double jsNum(Object o) {
        if (o instanceof Json.Num) {
            try {
                return Double.parseDouble(((Json.Num) o).raw);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        if (o instanceof Number) return ((Number) o).doubleValue();
        return null;
    }

    private static boolean truthy(Object o) {
        if (o == null) return false;
        if (o instanceof Boolean) return (Boolean) o;
        if (o instanceof String) return !((String) o).isEmpty();
        Double d = jsNum(o);
        if (d != null) return d != 0.0 && !d.isNaN();
        return true;
    }

    private static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Canonical equality over JSON values (same strict canonical bytes). Fails closed (false) on any error. */
    private static boolean canonicalEqual(Object a, Object b) {
        try {
            return Pca.hashCanonical(a).equals(Pca.hashCanonical(b));
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static Object req(Map<String, Object> m, String k) {
        if (m == null || !m.containsKey(k)) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
        return m.get(k);
    }

    /** Normalize a disclosure path: a list is copied; a bare string is a single top-level key. */
    private static List<Object> normalizePath(Object path) {
        if (path instanceof String) {
            List<Object> l = new ArrayList<>();
            l.add(path);
            return l;
        }
        List<Object> l = asList(path);
        if (l == null) throw new IllegalArgumentException("path.slice is not a function");
        return new ArrayList<>(l);
    }

    /** The b64u public key of a key input: a b64u string, raw public-key bytes or a key pair. */
    private static String toPubB64u(Object key) {
        if (key instanceof String) return (String) key;
        if (key instanceof byte[]) return Keys.b64u((byte[]) key);
        if (key instanceof Keys.EdKey) return ((Keys.EdKey) key).id();
        throw new IllegalArgumentException("unsupported key");
    }

    // ---- body flattening ----

    private static final class BareLeaf {
        final List<Object> path;
        final Object value;

        BareLeaf(List<Object> path, Object value) { this.path = path; this.value = value; }
    }

    private static List<Object> plus(List<Object> prefix, Object seg) {
        List<Object> p = new ArrayList<>(prefix);
        p.add(seg);
        return p;
    }

    private static void flatten(Object value, List<Object> prefix, List<BareLeaf> out) {
        List<Object> arr = asList(value);
        if (arr != null) {
            if (arr.isEmpty()) { out.add(new BareLeaf(prefix, new ArrayList<Object>())); return; }
            for (int i = 0; i < arr.size(); i++) flatten(arr.get(i), plus(prefix, (long) i), out);
            return;
        }
        Map<String, Object> obj = asMap(value);
        if (obj != null) {
            List<String> keys = new ArrayList<>(obj.keySet());
            keys.sort(IntentJs::compareUtf8);
            if (keys.isEmpty()) { out.add(new BareLeaf(prefix, new LinkedHashMap<String, Object>())); return; }
            for (String k : keys) flatten(obj.get(k), plus(prefix, k), out);
            return;
        }
        out.add(new BareLeaf(prefix, value));
    }

    /** Split a string into {@code size}-character chunks (by code point, never splitting a surrogate pair). */
    private static List<BareLeaf> chunkString(String s, long size) {
        int[] cps = s.codePoints().toArray();
        List<BareLeaf> out = new ArrayList<>();
        if (cps.length == 0) {
            List<Object> p = new ArrayList<>();
            p.add("#chunk");
            p.add(0L);
            out.add(new BareLeaf(p, ""));
            return out;
        }
        long idx = 0;
        for (long i = 0; i < cps.length; i += size, idx++) {
            int n = (int) Math.min(size, cps.length - i);
            List<Object> p = new ArrayList<>();
            p.add("#chunk");
            p.add(idx);
            out.add(new BareLeaf(p, new String(cps, (int) i, n)));
        }
        return out;
    }

    private static Map<String, Object> leafObject(Object path, Object value, Object salt) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("p", path);
        m.put("v", value);
        m.put("s", salt);
        return m;
    }

    private static Map<String, Object> leafObjectOf(Object leaf) {
        Map<String, Object> l = asMap(leaf);
        if (l == null) throw new IllegalArgumentException("Cannot read properties of undefined");
        return leafObject(req(l, "path"), req(l, "value"), req(l, "salt"));
    }

    private static String requestHeadersDigest(Object headers) {
        Map<String, Object> norm = new LinkedHashMap<>();
        Map<String, Object> h = asMap(headers);
        if (h != null) for (Map.Entry<String, Object> e : h.entrySet()) norm.put(e.getKey().toLowerCase(java.util.Locale.ROOT), e.getValue());
        return Pca.hashCanonical(norm);
    }

    // ---- notaryMessage ----

    /** The canonical bytes the notary signs: {@code "atlas-pca/notary/v1\0" || sha256(canonical(session))}. */
    public static byte[] notaryMessage(Object session) {
        byte[] d = sha256(W3Bridge.canonBytes(session));
        byte[] pre = NOTARY_DOMAIN.getBytes(StandardCharsets.UTF_8);
        byte[] m = new byte[pre.length + d.length];
        System.arraycopy(pre, 0, m, 0, pre.length);
        System.arraycopy(d, 0, m, pre.length, d.length);
        return m;
    }

    // ---- notarizeResponse ----

    /** Options for {@link #notarizeResponse}. */
    public static final class NotarizeOptions {
        /** The notary's signing key (its public key becomes {@code attestation.notary}). */
        public final Keys.EdKey notaryKey;
        /** Epoch ms the notary observed the session (a JSON-shaped number); null = now. */
        public Object observedAt;
        /** When set (a number &gt;= 1) and the body is a string, commit it as chunks of this many characters. */
        public Object textChunkSize;
        /** Source of the 16-byte hiding salts (default: SecureRandom). */
        public Supplier<byte[]> salt;

        public NotarizeOptions(Keys.EdKey notaryKey) { this.notaryKey = notaryKey; }
    }

    /** The shareable attestation and the prover's private opening witness. */
    public static final class NotarizeResult {
        public final Map<String, Object> attestation;
        public final Map<String, Object> witness;

        NotarizeResult(Map<String, Object> attestation, Map<String, Object> witness) {
            this.attestation = attestation;
            this.witness = witness;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("attestation", attestation);
            m.put("witness", witness);
            return m;
        }
    }

    private static final SecureRandom RNG = new SecureRandom();

    /**
     * Witness a request/response ({@code input = {request: {method, url, headers?}, response: {status, body}}}) and produce a signed
     * attestation over the canonical session plus the response-body Merkle root, and the witness the prover keeps to disclose fields.
     */
    public static NotarizeResult notarizeResponse(Map<String, Object> input, NotarizeOptions opts) {
        Map<String, Object> request = asMap(input == null ? null : input.get("request"));
        Map<String, Object> response = asMap(input == null ? null : input.get("response"));
        if (request == null || response == null) throw new IllegalArgumentException("Cannot read properties of undefined");
        Object method = request.get("method");
        if (!(method instanceof String) || ((String) method).isEmpty()) throw new IllegalArgumentException("notarizeResponse: request.method is required");
        Object url = request.get("url");
        if (!(url instanceof String) || ((String) url).isEmpty()) throw new IllegalArgumentException("notarizeResponse: request.url is required");
        Object status = response.get("status");
        if (!isSafeIntJs(status)) throw new IllegalArgumentException("notarizeResponse: response.status must be an integer");

        Object body = response.get("body");
        Double chunk = opts.textChunkSize == null ? null : jsNum(opts.textChunkSize);
        List<BareLeaf> bare = new ArrayList<>();
        if (body instanceof String && chunk != null && chunk >= 1) chunkAll((String) body, chunk, bare);
        else flatten(body, new ArrayList<>(), bare);

        Supplier<byte[]> salts = opts.salt != null ? opts.salt : () -> { byte[] b = new byte[16]; RNG.nextBytes(b); return b; };
        List<Object> leaves = new ArrayList<>();
        List<Object> leafObjects = new ArrayList<>();
        for (BareLeaf l : bare) {
            String salt = Keys.b64u(salts.get());
            Map<String, Object> leaf = new LinkedHashMap<>();
            leaf.put("path", l.path);
            leaf.put("value", l.value);
            leaf.put("salt", salt);
            leaves.add(leaf);
            leafObjects.add(leafObject(l.path, l.value, salt));
        }
        String root = Pca.merkleRoot(leafObjects);

        Map<String, Object> commit = new LinkedHashMap<>();
        commit.put("alg", BODY_COMMIT_ALG);
        commit.put("root", root);
        commit.put("size", (long) leaves.size());
        Map<String, Object> session = new LinkedHashMap<>();
        session.put("v", 1L);
        session.put("method", ((String) method).toUpperCase(java.util.Locale.ROOT));
        session.put("url", url);
        session.put("requestHeadersDigest", requestHeadersDigest(request.get("headers")));
        session.put("responseStatus", status);
        session.put("responseBodyCommit", commit);
        session.put("observedAt", opts.observedAt != null ? opts.observedAt : (Object) System.currentTimeMillis());

        Map<String, Object> attestation = new LinkedHashMap<>();
        attestation.put("session", session);
        attestation.put("notary", opts.notaryKey.id());
        attestation.put("sig", Keys.b64u(opts.notaryKey.sign(notaryMessage(session))));
        Map<String, Object> witness = new LinkedHashMap<>();
        witness.put("session", session);
        witness.put("leaves", leaves);
        return new NotarizeResult(attestation, witness);
    }

    private static void chunkAll(String body, double chunk, List<BareLeaf> out) {
        out.addAll(chunkString(body, (long) Math.min(Math.floor(chunk), 4.0e18)));
    }

    // ---- discloseField ----

    /**
     * A redactable disclosure of ONE response field (by {@code path}: a list, or a bare string for a top-level key) with its Merkle
     * inclusion proof; every other field stays hidden. Throws when {@code path} names no committed leaf.
     */
    public static Map<String, Object> discloseField(Object attestation, Object witness, Object path) {
        List<Object> want = normalizePath(path);
        Map<String, Object> w = asMap(witness);
        List<Object> leaves = w == null ? null : asList(w.get("leaves"));
        if (leaves == null) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'leaves')");
        int idx = -1;
        for (int i = 0; i < leaves.size(); i++) {
            Map<String, Object> l = asMap(leaves.get(i));
            if (l == null) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'path')");
            if (canonicalEqual(l.get("path"), want)) { idx = i; break; }
        }
        if (idx < 0) throw new IllegalArgumentException("discloseField: no committed field at path " + Json.canonicalize(want));
        Map<String, Object> leaf = asMap(leaves.get(idx));
        List<Object> objs = new ArrayList<>();
        for (Object l : leaves) objs.add(leafObjectOf(l));
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("path", leaf.get("path"));
        d.put("value", leaf.get("value"));
        d.put("salt", leaf.get("salt"));
        d.put("proof", GrantSigning.merkleProof(objs, idx));
        return d;
    }

    // ---- verification (fail closed) ----

    private static boolean validCommit(Object c) {
        Map<String, Object> r = asMap(c);
        if (r == null) return false;
        return BODY_COMMIT_ALG.equals(r.get("alg")) && r.get("root") instanceof String && Pca.decodeB64uStrict(r.get("root"), 32) != null
            && isSafeIntJs(r.get("size")) && jsNum(r.get("size")) >= 1;
    }

    private static boolean validSession(Object s) {
        Map<String, Object> r = asMap(s);
        if (r == null) return false;
        return isOne(r.get("v")) && r.get("method") instanceof String && r.get("url") instanceof String && r.get("requestHeadersDigest") instanceof String
            && isSafeIntJs(r.get("responseStatus")) && !isNegZero(r.get("responseStatus"))
            && isSafeIntJs(r.get("observedAt")) && !isNegZero(r.get("observedAt"))
            && validCommit(r.get("responseBodyCommit"));
    }

    /**
     * Verify the notary signature AND the session's structural integrity. {@code notaryKey} is the TRUSTED notary's public key (b64u
     * string, raw bytes or key pair); the recorded signer must equal it and the signature must verify over the canonical session.
     */
    public static boolean verifyNotaryAttestation(Object attestation, Object notaryKey) {
        try {
            Map<String, Object> a = asMap(attestation);
            if (a == null) return false;
            if (!validSession(a.get("session"))) return false;
            if (!(a.get("notary") instanceof String) || !(a.get("sig") instanceof String)) return false;
            String expected = toPubB64u(notaryKey);
            if (!a.get("notary").equals(expected)) return false;
            return W3Bridge.verifyB64u((String) a.get("notary"), notaryMessage(a.get("session")), (String) a.get("sig"));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Verify a disclosed field: the attestation is authentic AND the disclosed leaf is included under the attested body root at a
     * position consistent with the committed size. A lie about the value, path or salt breaks inclusion.
     */
    public static boolean verifyDisclosedField(Object attestation, Object disclosure, Object notaryKey) {
        try {
            if (!verifyNotaryAttestation(attestation, notaryKey)) return false;
            Map<String, Object> d = asMap(disclosure);
            if (d == null) return false;
            if (!(d.get("path") instanceof List) || !(d.get("salt") instanceof String)) return false;
            Map<String, Object> proof = asMap(d.get("proof"));
            if (proof == null || !(proof.get("path") instanceof List)) return false;
            Map<String, Object> commit = asMap(asMap(asMap(attestation).get("session")).get("responseBodyCommit"));
            if (!Json.isSafeInt(proof.get("size")) || Json.asLong(proof.get("size")) != Json.asLong(commit.get("size"))) return false;
            if (!d.containsKey("value")) return false; // an undefined value cannot be canonicalised: the reference refuses it
            return Pca.verifyInclusion((String) commit.get("root"), proof, leafObject(d.get("path"), d.get("value"), d.get("salt")));
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ---- PCA binding ----

    /** A stable digest identifying this attested FACT (independent of any PCActn binding). */
    public static String factRef(Object attestation) {
        Map<String, Object> a = asMap(attestation);
        if (a == null) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'session')");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("fact", "atlas-pca-notary/v1");
        m.put("session", req(a, "session"));
        m.put("notary", req(a, "notary"));
        m.put("sig", req(a, "sig"));
        return Pca.hashCanonical(m);
    }

    /** Bind an attested fact to a specific PCActn by stamping the action's digest into the attestation (a new map; the input is untouched). */
    public static Map<String, Object> bindFactToPcActn(Object attestation, Object pcActn) {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> a = asMap(attestation);
        if (a != null) out.putAll(a);
        Map<String, Object> fb = new LinkedHashMap<>();
        fb.put("pcactn_digest", Pca.hashCanonical(pcActn));
        out.put("fact_binding", fb);
        return out;
    }

    /**
     * True iff the fact is bound to {@code pcActn} in BOTH directions: the fact names the action
     * ({@code fact_binding.pcactn_digest == digest(pcActn)}) AND the action commits to the fact
     * ({@code provenance.trusted_refs} includes {@link #factRef}). False if either side is missing.
     */
    public static boolean factMatchesPcActn(Object attestation, Object pcActn) {
        try {
            Map<String, Object> a = asMap(attestation);
            if (a == null) return false;
            Map<String, Object> binding = asMap(a.get("fact_binding"));
            if (binding == null || !(binding.get("pcactn_digest") instanceof String)) return false;
            if (!binding.get("pcactn_digest").equals(Pca.hashCanonical(pcActn))) return false;
            Map<String, Object> p = asMap(pcActn);
            Map<String, Object> prov = p == null ? null : asMap(p.get("provenance"));
            List<Object> refs = prov == null ? null : asList(prov.get("trusted_refs"));
            if (refs == null) return false;
            return refs.contains(factRef(attestation));
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ---- policy caveat ----

    /**
     * Build an attested_fact caveat: admit an action only when the agent discloses a notarized response field equal to {@code equals}.
     * {@code opts} = {notary (b64u string / bytes / key), path, equals, url?, bindToPcActn?}.
     */
    public static Map<String, Object> requireAttestedFact(Map<String, Object> opts) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", ATTESTED_FACT_CAVEAT);
        m.put("notary", toPubB64u(opts.get("notary")));
        m.put("path", opts.get("path") instanceof String ? opts.get("path") : (Object) normalizeList(opts.get("path"))); // "abc".slice() is the string itself
        if (opts.containsKey("equals")) m.put("equals", opts.get("equals"));
        if (opts.containsKey("url")) m.put("url", opts.get("url"));
        if (opts.containsKey("bindToPcActn")) m.put("bindToPcActn", opts.get("bindToPcActn"));
        return m;
    }

    private static List<Object> normalizeList(Object o) {
        List<Object> l = asList(o);
        if (l == null) throw new IllegalArgumentException("opts.path.slice is not a function");
        return new ArrayList<>(l);
    }

    /** The JavaScript comparison {@code observedAt >= bound} / {@code < bound} operand: a number, null (0), a boolean or a numeric string. */
    private static double toNumber(Object o) {
        if (o == null) return 0;
        if (o instanceof Boolean) return (Boolean) o ? 1 : 0;
        Double d = jsNum(o);
        if (d != null) return d;
        if (o instanceof String) {
            String s = ((String) o).trim();
            if (s.isEmpty()) return 0;
            try {
                return Double.parseDouble(s);
            } catch (NumberFormatException e) {
                return Double.NaN;
            }
        }
        return Double.NaN;
    }

    /** True iff {@code key} is listed in {@code ring}, not revoked, and {@code observedAt} lies in its [notBefore, notAfter) window. */
    public static boolean notaryKeyUsable(Object ring, Object key, Object observedAt) {
        List<Object> r = asList(ring);
        if (r == null || !isSafeIntJs(observedAt)) return false;
        double at = jsNum(observedAt);
        boolean any = false;
        boolean allLive = true;
        boolean someWindow = false;
        for (Object eo : r) {
            Map<String, Object> e = asMap(eo);
            if (e == null || !strictEq(e.get("key"), key)) continue;
            any = true;
            if (Boolean.TRUE.equals(e.get("revoked"))) allLive = false;
            boolean okBefore = !e.containsKey("notBefore") || at >= toNumber(e.get("notBefore"));
            boolean okAfter = !e.containsKey("notAfter") || at < toNumber(e.get("notAfter"));
            if (okBefore && okAfter) someWindow = true;
        }
        return any && allLive && someWindow;
    }

    /** JavaScript {@code a === b} over JSON-shaped scalars (numbers by value). */
    private static boolean strictEq(Object a, Object b) {
        if (a == null || b == null) return a == null && b == null;
        Double x = jsNum(a), y = jsNum(b);
        if (x != null || y != null) return x != null && y != null && x.doubleValue() == y.doubleValue();
        if (a instanceof String || b instanceof String || a instanceof Boolean || b instanceof Boolean) return a.equals(b);
        return false;
    }

    private static Map<String, Object> result(boolean ok, String reason, boolean trust) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", ok);
        if (reason != null) m.put("reason", reason);
        if (trust) m.put("trust", "notary-trusted");
        return m;
    }

    /**
     * Evaluate an attested_fact caveat against disclosed evidence ({attestation, disclosure, pcActn?}) under an optional policy
     * ({now?, maxAgeMs?, keyring?}). Admits ({@code ok: true, trust: "notary-trusted"}) only when, failing closed at every step: the
     * attestation is authentic under the caveat's notary; the keyring (if given) trusts the signer at the observation time; the
     * attestation is fresh (if {@code maxAgeMs}); the URL matches (if set); the disclosed field verifies; its path equals the caveat's
     * path; its value canonically equals {@code equals}; and (if {@code bindToPcActn}) the fact is two-way bound to the PCActn.
     */
    public static Map<String, Object> evaluateAttestedFactCaveat(Object caveat, Object evidence, Map<String, Object> policy) {
        try {
            Map<String, Object> cv = asMap(caveat);
            if (cv == null || !ATTESTED_FACT_CAVEAT.equals(cv.get("type"))) return result(false, "not an attested_fact caveat", false);
            if (!(cv.get("notary") instanceof String) || !(cv.get("path") instanceof List)) return result(false, "caveat is malformed (notary/path)", false);
            if (evidence == null) throw new IllegalArgumentException("Cannot destructure property 'attestation' of 'evidence' as it is null.");
            Map<String, Object> ev = asMap(evidence);
            Object attestation = ev == null ? null : ev.get("attestation");
            Object disclosure = ev == null ? null : ev.get("disclosure");
            Object pcActn = ev == null ? null : ev.get("pcActn");
            if (!verifyNotaryAttestation(attestation, cv.get("notary"))) return result(false, "notary attestation does not verify (fail closed)", false);
            Map<String, Object> att = asMap(attestation);
            Map<String, Object> session = asMap(att.get("session"));
            if (policy == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'keyring')");
            Map<String, Object> pol = policy;
            if (pol.containsKey("keyring") && !notaryKeyUsable(pol.get("keyring"), att.get("notary"), session.get("observedAt"))) {
                return result(false, "notary key is not trusted for this observation time (unlisted, revoked or out of window)", false);
            }
            if (pol.containsKey("maxAgeMs")) {
                Object nowO = pol.get("now");
                Object now = nowO != null ? nowO : (Object) System.currentTimeMillis();
                Double max = jsNum(pol.get("maxAgeMs"));
                Double nowN = jsNum(now);
                boolean stale = max == null || max.isInfinite() || max.isNaN() || nowN == null || nowN.isInfinite() || nowN.isNaN();
                if (!stale) {
                    double age = nowN - jsNum(session.get("observedAt"));
                    stale = age < 0 || age > max;
                }
                if (stale) return result(false, "attestation is stale or from the future", false);
            }
            if (cv.containsKey("url") && !java.util.Objects.equals(session.get("url"), cv.get("url"))) {
                return result(false, "attested session URL does not match the caveat", false);
            }
            if (!verifyDisclosedField(attestation, disclosure, cv.get("notary"))) return result(false, "disclosed field does not verify under the attested root", false);
            Map<String, Object> d = asMap(disclosure);
            if (!canonicalEqual(d.get("path"), cv.get("path"))) return result(false, "disclosed field is not the path the caveat requires", false);
            if (!cv.containsKey("equals") || !canonicalEqual(d.get("value"), cv.get("equals"))) {
                return result(false, "disclosed field value does not satisfy the caveat", false);
            }
            if (truthy(cv.get("bindToPcActn"))) {
                if (!truthy(pcActn)) return result(false, "caveat requires PCActn binding but no PCActn was supplied", false);
                if (!factMatchesPcActn(attestation, pcActn)) return result(false, "fact is not bound to this PCActn", false);
            }
            return result(true, null, true);
        } catch (RuntimeException e) {
            return result(false, "attested_fact evaluation error (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()), false);
        }
    }

    public static Map<String, Object> evaluateAttestedFactCaveat(Object caveat, Object evidence) { return evaluateAttestedFactCaveat(caveat, evidence, new LinkedHashMap<String, Object>()); }

    /** Type guard: a bare caveat object is an attested_fact caveat. */
    public static boolean isAttestedFactCaveat(Object cv) {
        Map<String, Object> m = asMap(cv);
        return m != null && ATTESTED_FACT_CAVEAT.equals(m.get("type")) && m.get("notary") instanceof String && m.get("path") instanceof List;
    }
}
