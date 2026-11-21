package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import net.atlasauth.pca.sandbox.Confine;
import net.atlasauth.pca.sandbox.Egress;
import net.atlasauth.pca.sandbox.Handles;
import net.atlasauth.pca.sandbox.Host;
import net.atlasauth.pca.sandbox.Profiles;
import net.atlasauth.pca.sandbox.ReferenceComponent;
import net.atlasauth.pca.sandbox.ReferenceTool;
import net.atlasauth.pca.sandbox.Receipts;
import net.atlasauth.pca.sandbox.RuntimeClaims;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the sandbox package through the native port. */
public class SandboxDiffTest {
    private static final String M = "ref-sandbox";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    private static Map<String, Object> err() {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("$err", Boolean.TRUE);
        return e;
    }

    private static byte[] bytes(Object o) { return Keys.unb64u((String) m(o).get("$bytes")); }

    /** The deterministic test seed of a label: sha256 of the conformance prefix and the label. */
    private static byte[] seedOf(String label) {
        try { return java.security.MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8)); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    private static long idx(Object o) {
        Double d = IntentJs.num(o);
        return d == null || d != Math.rint(d) ? 0 : (long) (double) d;
    }

    /** What the reference's authorization result looks like for {allow, bind}: an operation bound to the digest of bind.params. */
    private static Authorize.AuthorizeResult result(boolean allow, Object bind) {
        Authorize.AuthorizedOperation op = null;
        if (bind != null) {
            Map<String, Object> b = m(bind);
            Object id = b.get("id");
            op = new Authorize.AuthorizedOperation((String) b.get("verb"), (String) b.get("resource"), Pca.hashCanonical(b.get("params")), id == null ? "op" : (String) id);
        }
        return new Authorize.AuthorizeResult(allow, allow ? 200 : 403, new LinkedHashMap<String, String>(), new ArrayList<String>(), null, op, null, null, new ArrayList<String>());
    }

    /** The reference refuses an operation whose params are not an object (validOperation); the typed API cannot hold one. */
    @SuppressWarnings("unchecked")
    private static Authorize.Operation operation(Object o) {
        Map<String, Object> op = m(o);
        if (!(op.get("params") instanceof Map)) throw new IllegalArgumentException("not_authorized: bad operation");
        return new Authorize.Operation((String) op.get("verb"), (String) op.get("resource"), (Map<String, Object>) op.get("params"));
    }

    @Test void consts() throws Exception {
        OracleCases.each(M, "moduleConsts", a -> {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("IMPORT_MODULE", Host.IMPORT_MODULE);
            o.put("ALLOWED_IMPORTS", Host.ALLOWED_IMPORTS);
            o.put("USE_ERR", Handles.USE_ERR);
            o.put("GENESIS", Receipts.GENESIS);
            o.put("RUNTIME_CLASSES", Receipts.RUNTIME_CLASSES);
            o.put("DOMAIN", RuntimeClaims.RUNTIME_CLAIM_DOMAIN);
            return o;
        });
    }

    @Test void satisfies() throws Exception { OracleCases.each(M, "satisfiesRuntimeClass", a -> Receipts.satisfiesRuntimeClass(a.get(0), a.get(1))); }

    @Test void receiptLog() throws Exception {
        OracleCases.each(M, "receiptLog", a -> {
            Map<String, Object> spec = m(a.get(0));
            Object[] t = {Long.valueOf(0)};
            Supplier<Object> now = () -> t[0];
            Receipts.ReceiptLog log = new Receipts.ReceiptLog(now, Boolean.TRUE.equals(spec.get("sign")) ? d -> "sig:" + d : null);
            List<Object> outs = new ArrayList<>();
            for (Object s : l(spec.get("appends"))) {
                Map<String, Object> st = m(s);
                t[0] = st.get("t");
                try { outs.add(log.append((String) st.get("rc"), m(st.get("body")))); } catch (RuntimeException e) { outs.add(err()); }
            }
            return outs;
        });
    }

    @Test void receiptChain() throws Exception {
        OracleCases.each(M, "verifyReceiptChain", a -> Receipts.verifyReceiptChain(a.get(0), "tag".equals(a.get(1)) ? (d, s) -> s.equals("sig:" + d) : null));
    }

    @Test void policyFromNeeds() throws Exception { OracleCases.each(M, "policyFromNeeds", a -> Profiles.policyFromNeeds(a.get(0), arg(a, 1))); }

    @Test void compilePolicy() throws Exception {
        OracleCases.each(M, "compilePolicy", a -> {
            Map<String, Object> spec = m(a.get(0));
            List<Profiles.AuthorizedOp> items = new ArrayList<>();
            for (Object o : l(spec.get("items"))) {
                Map<String, Object> it = m(o);
                items.add(new Profiles.AuthorizedOp(result(Boolean.TRUE.equals(it.get("allow")), it.get("bind")), operation(it.get("operation"))));
            }
            Map<String, Object> needs = m(spec.get("needs"));
            return Profiles.compilePolicy(items, op -> needs.get(op.verb + " " + op.resource), spec.get("proxyPort"));
        });
    }

    @Test void profiles() throws Exception {
        OracleCases.each(M, "seccompProfile", a -> Profiles.seccompProfile(m(a.get(0))));
        OracleCases.each(M, "landlockRuleset", a -> Profiles.landlockRuleset(m(a.get(0))));
        OracleCases.each(M, "macosProfile", a -> Profiles.macosProfile(m(a.get(0))));
        OracleCases.each(M, "confineArgs", a -> Confine.confineArgs(m(a.get(0))));
    }

    /**
     * These vectors predate the address check that classifies the parsed address: they read these loopback / unspecified / v4-mapped /
     * zoned / reserved (outside 2000::/3) spellings as public, and a non-string as a throw. The native check, like the current
     * reference, calls all of them private.
     */
    static final java.util.Set<String> STRICTER_PRIVATE = java.util.Set.of("0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:0", "::ffff:7f00:1", "::ffff:0:0",
        "::1%eth0", "::127.0.0.1", "::ffff:1.2.3.4%x", "::2", "fec0::1", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:1.2.3.4", "f::");

    @Test void privateAddress() throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : OracleCases.of(M, "isPrivateAddress")) {
            Object ip = l(c.get("args")).get(0);
            if (!(ip instanceof String) || STRICTER_PRIVATE.contains(ip)) {
                if (!Egress.isPrivateAddress(ip)) bad.add(c.get("name") + " is not private");
            } else {
                String d = OracleCases.diff(c, c.get("out"), a -> Egress.isPrivateAddress(a.get(0)));
                if (d != null) bad.add(d);
            }
        }
        assertTrue(bad.isEmpty(), String.join("\n", bad));
        for (String ip : new String[] {"0::1", "::FFFF:7F00:0001", "::7f00:1", "64:ff9b::7f00:1", "64:ff9b::10.0.0.1", "fe80::1%25eth0", "2606:4700::1111%eth0",
            "FE80::1", "fc::1", "1fff::1", "4000::1", "1::2::3", "::00001", "::01.2.3.4", "[::1]", " ::1"}) assertTrue(Egress.isPrivateAddress(ip), ip);
        for (String ip : new String[] {"2606:4700:0:0:0:0:0:1111", "2001:DB8::1", "::ffff:808:808", "::ffff:8.8.8.8", "64:ff9b::8.8.8.8", "2000::", "3fff::1", "8.8.8.8"})
            assertEquals(false, Egress.isPrivateAddress(ip), ip);
        assertTrue(Egress.isPrivateAddress(null));
    }

    @Test void egress() throws Exception {
        OracleCases.each(M, "egress", a -> {
            double[] t = {0};
            Egress.EgressPolicy p = new Egress.EgressPolicy(() -> t[0]);
            List<Object> outs = new ArrayList<>();
            for (Object s : l(m(a.get(0)).get("steps"))) {
                Map<String, Object> st = m(s);
                try {
                    String op = (String) st.get("op");
                    if (op.equals("now")) { t[0] = IntentJs.num(st.get("t")); outs.add(null); }
                    else if (op.equals("admit")) {
                        Object tmpl = st.get("template");
                        Map<String, Object> opts = st.get("opts") == null ? new LinkedHashMap<String, Object>() : m(st.get("opts"));
                        p.admit(result(Boolean.TRUE.equals(st.get("allow")), st.get("bind")), operation(st.get("operation")), o -> {
                            if (tmpl == null) return null;
                            if (!(tmpl instanceof Map)) throw new IllegalArgumentException("bad_template");
                            return m(tmpl);
                        }, opts.get("uses"), opts.get("expiresAt"));
                        outs.add("ok");
                    } else {
                        Map<String, Object> req = m(st.get("req"));
                        outs.add(p.claim(req.get("method"), req.get("url"), req.get("body") == null ? null : bytes(req.get("body"))));
                    }
                } catch (RuntimeException e) { outs.add(err()); }
            }
            return outs;
        });
    }

    /** JSON.stringify of an operation: insertion order, compact, numbers as JavaScript prints them. */
    private static void js(Object v, StringBuilder sb) {
        if (v == null) sb.append("null");
        else if (v instanceof String) sb.append(Json.canonicalize(v));
        else if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : m(v).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                sb.append(Json.canonicalize(e.getKey())).append(':');
                js(e.getValue(), sb);
            }
            sb.append('}');
        } else if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : l(v)) {
                if (!first) sb.append(',');
                first = false;
                js(x, sb);
            }
            sb.append(']');
        } else sb.append(v);
    }

    private static final Map<String, Handles.Executor> EXEC = new LinkedHashMap<>();
    static {
        EXEC.put("fs.read", (verb, resource, params) -> new byte[] {1, 2, 3});
        EXEC.put("fs.echo", (verb, resource, params) -> {
            Map<String, Object> op = new LinkedHashMap<>();
            op.put("verb", verb);
            op.put("resource", resource);
            op.put("params", params);
            StringBuilder sb = new StringBuilder();
            js(IntentJs.normalize(op), sb);
            return sb.toString().getBytes(StandardCharsets.UTF_8);
        });
        EXEC.put("fs.throw", (verb, resource, params) -> { throw new IllegalStateException("boom"); });
        EXEC.put("fs.notbytes", (verb, resource, params) -> null);
    }

    @Test void handles() throws Exception {
        OracleCases.each(M, "handles", a -> {
            Map<String, Object> spec = m(a.get(0));
            Object[] t = {Long.valueOf(0)};
            Receipts.ReceiptLog log = new Receipts.ReceiptLog(() -> t[0], null);
            Handles.HandleTable table = new Handles.HandleTable((String) spec.get("cls"), log, EXEC, () -> IntentJs.num(t[0]));
            List<Object> outs = new ArrayList<>();
            for (Object s : l(spec.get("steps"))) {
                Map<String, Object> st = m(s);
                try {
                    switch ((String) st.get("op")) {
                        case "now": t[0] = st.get("t"); outs.add(null); break;
                        case "mint": {
                            Object bind;
                            if (st.containsKey("bind")) bind = st.get("bind");
                            else {
                                Map<String, Object> b = new LinkedHashMap<>(m(st.get("operation")));
                                b.put("id", st.get("id") == null ? "op-h" : st.get("id"));
                                bind = b;
                            }
                            Handles.MintOptions o = new Handles.MintOptions();
                            Map<String, Object> opts = st.get("opts") == null ? new LinkedHashMap<String, Object>() : m(st.get("opts"));
                            o.uses = opts.get("uses");
                            o.expiresAt = opts.get("expiresAt");
                            o.requires = (String) opts.get("requires");
                            boolean allow = st.get("allow") == null || Boolean.TRUE.equals(st.get("allow"));
                            outs.add(Long.valueOf(table.mint(result(allow, bind), operation(st.get("operation")), o)));
                            break;
                        }
                        case "attenuate": {
                            Map<String, Object> n = st.get("narrower") == null ? new LinkedHashMap<String, Object>() : m(st.get("narrower"));
                            outs.add(Long.valueOf(table.attenuate(idx(st.get("index")), n.get("uses"), n.get("expiresAt"))));
                            break;
                        }
                        case "revoke": table.revoke(idx(st.get("index"))); outs.add(null); break;
                        case "use": outs.add(table.use(idx(st.get("index"))).toMap()); break;
                        case "verbOf": outs.add(table.verbOf(idx(st.get("index")))); break;
                        default: outs.add(Long.valueOf(table.size()));
                    }
                } catch (RuntimeException e) { outs.add(err()); }
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("outs", outs);
            out.put("log", log.entries());
            return out;
        });
    }

    @Test void runtimeClaims() throws Exception {
        OracleCases.each(M, "signRuntimeClaim", a -> {
            Object k = a.get(0);
            byte[] sk = k instanceof String ? seedOf((String) k) : new byte[IntentJs.num(m(k).get("short")).intValue()];
            return RuntimeClaims.signRuntimeClaim(sk, Keys.edFromSeed(seedOf((String) a.get(1))).pub, m(a.get(2)));
        });
        OracleCases.each(M, "verifiedRuntimeClass", a -> RuntimeClaims.verifiedRuntimeClass(a.get(0), a.get(1)));
        OracleCases.each(M, "passportDigest", a -> RuntimeClaims.passportDigest(a.get(0)));
        OracleCases.each(M, "evidenceDigest", a -> RuntimeClaims.evidenceDigest(a.get(0)));
    }

    /** Negative times and empty or over-long digests are none even when correctly signed and trusted. */
    @Test void runtimeClaimStrictForm() {
        byte[] seed = seedOf("strict-attestor");
        byte[] pub = Keys.edFromSeed(seed).pub;
        java.util.function.BiFunction<Map<String, Object>, Map<String, Object>, String> run = (over, tOver) -> {
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("class", "os_confined");
            c.put("passport_digest", "pd");
            c.put("evidence_digest", "ev");
            c.put("iat", 0L);
            c.put("exp", 100L);
            c.putAll(over);
            Map<String, Object> claim = RuntimeClaims.signRuntimeClaim(seed, pub, c);
            Map<String, Object> t = new LinkedHashMap<>();
            t.put("pinnedAttestors", List.of(claim.get("attestor")));
            t.put("passportDigest", claim.get("passport_digest"));
            t.put("verifiedEvidenceDigests", List.of(claim.get("evidence_digest")));
            t.put("now", 50L);
            t.putAll(tOver);
            return RuntimeClaims.verifiedRuntimeClass(claim, t);
        };
        assertEquals("os_confined", run.apply(Map.of(), Map.of()));
        assertEquals("none", run.apply(Map.of("iat", -5L), Map.of()), "negative iat");
        assertEquals("none", run.apply(Map.of("iat", -10L, "exp", -1L), Map.of("now", -5L)), "negative times");
        assertEquals("none", run.apply(Map.of("iat", -10L), Map.of("now", -1L)), "negative now");
        assertEquals("none", run.apply(Map.of("evidence_digest", ""), Map.of()), "empty evidence digest");
        assertEquals("none", run.apply(Map.of("passport_digest", ""), Map.of()), "empty passport digest");
        assertEquals("none", run.apply(Map.of("evidence_digest", "d".repeat(129)), Map.of()), "129-character evidence digest");
        assertEquals("none", run.apply(Map.of("passport_digest", "d".repeat(129)), Map.of()), "129-character passport digest");
        assertEquals("none", run.apply(Map.of(), Map.of("now", 9007199254740992.0)), "unsafe-integer now");
        assertEquals("os_confined", run.apply(Map.of("evidence_digest", "d".repeat(128), "passport_digest", "p".repeat(128)), Map.of()), "128 is the limit");
    }

    @Test void referenceModules() throws Exception {
        OracleCases.each(M, "buildTool", a -> ReferenceTool.buildTool(m(a.get(0))));
        OracleCases.each(M, "buildProbeTool", a -> ReferenceTool.buildProbeTool(arg(a, 0)));
        OracleCases.each(M, "referenceComponentWat", a -> ReferenceComponent.referenceComponentWat(a.isEmpty() ? null : m(a.get(0))));
    }

    @Test void trustFromAttestationAdmitsOnlyBoundEvidence() {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("format", "x");
        Map<String, Object> good = new LinkedHashMap<>();
        good.put("ok", Boolean.TRUE);
        good.put("bound", Boolean.TRUE);
        Map<String, Object> unbound = new LinkedHashMap<>(good);
        unbound.put("bound", Boolean.FALSE);
        List<String> pinned = List.of("k");
        assertEquals(List.of(RuntimeClaims.evidenceDigest(doc)), RuntimeClaims.trustFromAttestation(doc, () -> good, 5L, pinned, "p").get("verifiedEvidenceDigests"));
        assertTrue(((List<?>) RuntimeClaims.trustFromAttestation(doc, () -> unbound, 5L, pinned, "p").get("verifiedEvidenceDigests")).isEmpty());
        assertTrue(((List<?>) RuntimeClaims.trustFromAttestation(doc, () -> { throw new IllegalStateException("x"); }, 5L, pinned, "p").get("verifiedEvidenceDigests")).isEmpty());
        assertTrue(((List<?>) RuntimeClaims.trustFromAttestation(doc, () -> "nope", 5L, pinned, "p").get("verifiedEvidenceDigests")).isEmpty());
    }
}
