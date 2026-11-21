package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import net.atlasauth.pca.sdjwt.Sdjwt;
import org.junit.jupiter.api.Test;

/**
 * Differential test of {@link Sdjwt} against the TypeScript reference (test-data/ref-sdjwt.json.gz): constants, key helpers,
 * issuance (compared in normalized form: random salts), presentation (exact strings: Ed25519 key-binding signatures are deterministic),
 * verification and recovery through the core. A verification refusal reason is compared exactly only when it is this package's own
 * (or the canonical gate's); a reason in the JOSE library's wording only has to be a refusal.
 */
public class SdjwtDiffTest {
    static final String M = "ref-sdjwt";

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    /** {"$bytes": b64u} members (at any depth) become byte[]. */
    @SuppressWarnings("unchecked")
    static Object rev(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(rev(x));
            return out;
        }
        if (v instanceof Map) {
            Map<String, Object> mm = (Map<String, Object>) v;
            if (mm.size() == 1 && mm.get("$bytes") instanceof String) return Keys.unb64u((String) mm.get("$bytes"));
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : mm.entrySet()) out.put(e.getKey(), rev(e.getValue()));
            return out;
        }
        return v;
    }

    interface Cmp { boolean ok(Object got, Object want); }

    /** Replays every case of {@code fn} with {@code cmp}; a reference throw requires a throw. */
    static void eachCmp(String fn, OracleCases.Fn f, Cmp cmp, Predicate<String> skip) throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : OracleCases.of(M, fn)) {
            String name = (String) c.get("name");
            if (skip != null && skip.test(name)) continue;
            Object want = c.get("out");
            Object got = null;
            Throwable err = null;
            try { got = f.apply((List<?>) c.get("args")); } catch (Throwable t) { err = t; }
            Map<String, Object> wm = m(want);
            if (wm != null && wm.containsKey("$throws")) {
                if (err == null) bad.add(name + ": want a throw, got " + got);
                continue;
            }
            if (err != null) { bad.add(name + ": threw " + err); continue; }
            Object norm = IntentJs.normalize(OracleCases.toJson(got));
            if (!cmp.ok(norm, want)) bad.add(name + "\n  want: " + Json.canonicalize(want) + "\n  got:  " + Json.canonicalize(norm));
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s) of " + fn + ":\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 30))));
    }

    static final List<String> OWN = List.of("pca-sdjwt:", "non-canonical compact JWS", "required disclosure", "KB-JWT ", "cnf key does not", "key binding required",
        "duplicate disclosure", "unsupported _sd_alg", "a presented disclosure", "a digest appears", "an array", "an object-property", "disclosure claim", "_sd must be", "'");

    static String clip(String r) { return r.startsWith("non-canonical compact JWS: bad-json") ? r.split(" \\(")[0] : r; }

    static boolean cmpVerify(Object got, Object want) {
        Map<String, Object> g = m(got), w = m(want);
        if (Boolean.FALSE.equals(w.get("ok"))) {
            if (!Boolean.FALSE.equals(g.get("ok"))) return false;
            String r = (String) w.get("reason"), gr = (String) g.get("reason");
            if (r.startsWith("KB-JWT signature/claims invalid")) return gr.startsWith("KB-JWT signature/claims invalid");
            for (String p : OWN) if (r.startsWith(p)) return clip(gr).equals(clip(r));
            return true;
        }
        return IntentJs.jsonEquals(want, got);
    }

    static boolean cmpExact(Object got, Object want) { return IntentJs.jsonEquals(want, got); }

    static final Map<String, String> CAMEL = new LinkedHashMap<>();
    static {
        String[][] t = {{"required_disclosures", "requiredDisclosures"}, {"expected_audience", "expectedAudience"}, {"expected_kb_audience", "expectedKbAudience"},
            {"expected_nonce", "expectedNonce"}, {"require_key_binding", "requireKeyBinding"}, {"algorithms", "algorithms"}, {"kb_algorithms", "kbAlgorithms"},
            {"now", "now"}, {"kb_max_age_sec", "kbMaxAgeSec"}, {"clock_tolerance_sec", "clockToleranceSec"}, {"key_binding_key", "keyBindingKey"}};
        for (String[] p : t) CAMEL.put(p[0], p[1]);
    }

    @Test void constants() throws Exception {
        OracleCases.each(M, "constants", a -> {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("SD_ALG", Sdjwt.SD_ALG);
            r.put("PCA_SD_JWT_TYP", Sdjwt.PCA_SD_JWT_TYP);
            r.put("KB_JWT_TYP", Sdjwt.KB_JWT_TYP);
            r.put("DEFAULT_SIGNING_ALG", Sdjwt.DEFAULT_SIGNING_ALG);
            r.put("PCA_CAPABILITY_CLAIMS", Sdjwt.PCA_CAPABILITY_CLAIMS);
            return r;
        });
    }

    @Test void ed25519PublicJwk() throws Exception {
        OracleCases.each(M, "ed25519PublicJwk", a -> Sdjwt.ed25519PublicJwk((byte[]) rev(a.get(0))));
    }

    @Test void importEd25519PrivateKey() throws Exception {
        OracleCases.each(M, "importEd25519PrivateKey", a -> { Sdjwt.importEd25519PrivateKey((byte[]) rev(a.get(0))); return "ok"; });
    }

    @Test void importEd25519PublicKey() throws Exception {
        OracleCases.each(M, "importEd25519PublicKey", a -> { Sdjwt.importEd25519PublicKey((byte[]) rev(a.get(0))); return "ok"; });
    }

    /** The reference's normalized view of an issued SD-JWT (salts are random). */
    static Map<String, Object> normalizeIssued(String sd, byte[] seed) {
        String[] parts = sd.split("~", -1);
        List<String> ds = new ArrayList<>();
        for (int i = 1; i < parts.length - 1; i++) ds.add(parts[i]);
        String[] hp = parts[0].split("\\.");
        Map<String, Object> h = m(Json.parseLenient(new String(Base64.getUrlDecoder().decode(hp[0]), StandardCharsets.UTF_8)));
        Map<String, Object> p = m(Json.parseLenient(new String(Base64.getUrlDecoder().decode(hp[1]), StandardCharsets.UTF_8)));
        List<List<Object>> disc = new ArrayList<>();
        List<String> dig = new ArrayList<>();
        for (String d : ds) {
            List<?> t = (List<?>) Json.parseLenient(new String(Base64.getUrlDecoder().decode(d), StandardCharsets.UTF_8));
            List<Object> pair = new ArrayList<>();
            pair.add(t.get(1));
            pair.add(t.get(2));
            disc.add(pair);
            dig.add(Jose_sha(d));
        }
        Collections.sort(dig);
        disc.sort((x, y) -> ((String) x.get(0)).compareTo((String) y.get(0)));
        List<String> sdl = new ArrayList<>();
        if (p.get("_sd") instanceof List) for (Object x : (List<?>) p.get("_sd")) sdl.add((String) x);
        Collections.sort(sdl);
        Map<String, Object> rest = new LinkedHashMap<>(p);
        rest.remove("_sd");
        Map<String, Object> vo = new LinkedHashMap<>();
        vo.put("issuerKey", Sdjwt.importEd25519PublicKey(Keys.edFromSeed(seed).pub));
        vo.put("now", Jose_num(p.get("iat")) * 1000);
        Map<String, Object> ver = Sdjwt.verifyPcaSdJwt(sd, vo);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("end", parts[parts.length - 1]);
        out.put("header", h);
        out.put("payload", rest);
        out.put("n", ds.size());
        out.put("digestsOk", dig.equals(sdl));
        out.put("disclosures", disc);
        out.put("verified", ver.get("ok"));
        return out;
    }

    static String Jose_sha(String ascii) {
        byte[] b = new byte[ascii.length()];
        for (int i = 0; i < b.length; i++) b[i] = (byte) ascii.charAt(i);
        return net.atlasauth.pca.jose.Jose.b64u(net.atlasauth.pca.jose.Jose.sha256(b));
    }

    static double Jose_num(Object o) { return net.atlasauth.pca.jose.Jose.num(o); }

    @Test void issuePcaSdJwt() throws Exception {
        eachCmp("issuePcaSdJwt", a -> {
            Map<String, Object> pc = m(a.get(0));
            if (pc == null) throw new IllegalArgumentException("pca-sdjwt: pcActn must be an object");
            Map<String, Object> opt = m(a.get(1));
            byte[] seed = (byte[]) rev(opt.get("issuer_seed"));
            Map<String, Object> o2 = new LinkedHashMap<>();
            o2.put("issuerKey", Sdjwt.importEd25519PrivateKey(seed));
            for (String k : new String[] {"disclosable", "iss", "sub", "typ"}) if (opt.containsKey(k)) o2.put(k, opt.get(k));
            if (opt.containsKey("signing_alg")) o2.put("signingAlg", opt.get("signing_alg"));
            if (opt.containsKey("key_binding")) {
                Object kb = opt.get("key_binding");
                Map<String, Object> kbm = m(kb);
                if (kbm != null && kbm.containsKey("holder_public_key")) {
                    Map<String, Object> x = new LinkedHashMap<>();
                    x.put("holderPublicKey", rev(kbm.get("holder_public_key")));
                    o2.put("keyBinding", x);
                } else o2.put("keyBinding", rev(kb));
            }
            return normalizeIssued(Sdjwt.issuePcaSdJwt(pc, o2), seed);
        }, SdjwtDiffTest::cmpExact, null);
    }

    @Test void present() throws Exception {
        OracleCases.each(M, "present", a -> {
            Map<String, Object> options = new LinkedHashMap<>();
            Map<String, Object> opt = a.size() > 2 ? m(a.get(2)) : null;
            if (opt != null && opt.containsKey("key_binding")) {
                Map<String, Object> kb = m(opt.get("key_binding"));
                Map<String, Object> k = new LinkedHashMap<>();
                k.put("holderKey", Sdjwt.importEd25519PrivateKey((byte[]) rev(kb.get("holder_seed"))));
                for (String n : new String[] {"audience", "nonce", "iat", "alg"}) if (kb.containsKey(n)) k.put(n, kb.get(n));
                options.put("keyBinding", k);
            }
            return Sdjwt.present(a.get(0), a.get(1), options);
        });
    }

    @Test void verifyPcaSdJwt() throws Exception {
        eachCmp("verifyPcaSdJwt", a -> {
            Map<String, Object> opt = m(a.get(1));
            Object ik = rev(opt.get("issuer_key"));
            Map<String, Object> o2 = new LinkedHashMap<>();
            o2.put("issuerKey", ik instanceof byte[] ? Sdjwt.importEd25519PublicKey((byte[]) ik) : m(ik));
            for (Map.Entry<String, String> e : CAMEL.entrySet()) if (opt.containsKey(e.getKey())) o2.put(e.getValue(), rev(opt.get(e.getKey())));
            return Sdjwt.verifyPcaSdJwt(a.get(0), o2);
        }, SdjwtDiffTest::cmpVerify, null);
    }

    @Test void verifyRecovered() throws Exception {
        eachCmp("verifyRecovered", a -> {
            Map<String, Object> opt = m(a.get(1));
            Object aud = opt.get("audience");
            Double now = opt.containsKey("now") ? Jose_num(opt.get("now")) : null;
            Sdjwt.RecoveredResult r = Sdjwt.verifyRecovered(m(a.get(0)), m(opt.get("grant")), opt.containsKey("audience"), aud instanceof String ? (String) aud : null,
                now == null ? null : (long) (double) now, Boolean.TRUE.equals(opt.get("insecure_skip_plan_root_check")));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("allow", r.allow);
            out.put("reason", r.reason);
            return out;
        }, (got, want) -> {
            Map<String, Object> g = m(got), w = m(want);
            if (!java.util.Objects.equals(g.get("allow"), w.get("allow"))) return false;
            Object r = w.get("reason");
            return !(r instanceof String && ((String) r).startsWith("pca-sdjwt:")) || r.equals(g.get("reason"));
        }, null);
    }
}
