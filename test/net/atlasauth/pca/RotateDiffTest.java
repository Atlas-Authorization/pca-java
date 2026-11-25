package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.revoke.JsVal;
import net.atlasauth.pca.revoke.RevocationEntry;
import net.atlasauth.pca.revoke.RevocationRegistry;
import net.atlasauth.pca.rotate.RevocationRecord;
import net.atlasauth.pca.rotate.RevocationSink;
import net.atlasauth.pca.rotate.Rotate;
import org.junit.jupiter.api.Test;

class RotateDiffTest {
    private static final String M = "ref-rotate";
    /** The frozen clock the corpus generator ran under (its header's clockMs). */
    private static final double CLOCK_MS = BaseOracle.clockMs(M);

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    private static Keys.EdKey key(Object seed) { return seed == null ? null : Keys.edFromSeed(Keys.unb64u((String) seed)); }

    /** The reference wrapper's `now`: absent is null; present but not a finite number is NaN (refused). */
    private static Double now(Map<String, Object> o) {
        if (!o.containsKey("now")) return CLOCK_MS; // the reference ran at the header's frozen clock
        Double d = JsVal.num(o.get("now"));
        return d == null ? Double.NaN : d;
    }

    private static String reason(Map<String, Object> o) { return (String) o.get("reason"); }

    private static String holder(Object h) { return h instanceof String ? (String) h : null; }

    /** An entry whose revokedAt is within two minutes of the corpus generator's frozen clock (the header's clockMs) prints as "<now>" (the reference does the same). */
    @SuppressWarnings("unchecked")
    private static Object norm(Object v) {
        if (v instanceof List) { List<Object> o = new ArrayList<>(); for (Object x : (List<Object>) v) o.add(norm(x)); return o; }
        if (v instanceof Map) {
            Map<String, Object> o = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                Double d = JsVal.num(e.getValue());
                o.put(e.getKey(), e.getKey().equals("revokedAt") && d != null && Math.abs(d - CLOCK_MS) < 120_000 ? "<now>" : norm(e.getValue()));
            }
            return o;
        }
        return v;
    }

    private static Object result(Rotate.RotationResult r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("chain", new ArrayList<Object>(r.chain));
        m.put("revocation", r.revocation.toMap());
        return norm(m);
    }

    @Test void rotateAgentKey() throws Exception {
        OracleCases.each(M, "rotateAgentKey", a -> {
            Map<String, Object> op = map(a.get(1));
            return result(Rotate.rotateAgentKey(a.get(0), key(op.get("oldSeed")), key(op.get("newSeed")), reason(op), now(op)));
        });
    }

    @Test void rotatePrincipalKey() throws Exception {
        OracleCases.each(M, "rotatePrincipalKey", a -> {
            Map<String, Object> o = map(a.get(0));
            List<Keys.EdKey> hs = null;
            if (o.get("holderSeeds") != null) { hs = new ArrayList<>(); for (Object s : (List<?>) o.get("holderSeeds")) hs.add(key(s)); }
            return result(Rotate.rotatePrincipalKey(o.get("chain"), o.get("oldRoot"), key(o.get("oldSeed")), key(o.get("newSeed")), hs, reason(o), now(o)));
        });
    }

    @Test void revokeAndReissueSubtree() throws Exception {
        OracleCases.each(M, "revokeAndReissueSubtree", a -> {
            Map<String, Object> op = map(a.get(2));
            return result(Rotate.revokeAndReissueSubtree(a.get(0), holder(a.get(1)), key(op.get("newSeed")), key(op.get("ancestorSeed")), reason(op), now(op)));
        });
    }

    @Test void compromisedKeyFlow() throws Exception {
        OracleCases.each(M, "compromisedKeyFlow", a -> {
            Map<String, Object> op = map(a.get(2));
            Rotate.CompromisedFlow f = Rotate.compromisedKeyFlow(a.get(0), holder(a.get(1)), key(op.get("newSeed")), key(op.get("ancestorSeed")), reason(op), now(op));
            List<Object> recs = new ArrayList<>();
            for (RevocationRecord r : f.revocations) recs.add(r.toMap());
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("revocations", recs);
            m.put("reissued", new ArrayList<Object>(f.reissued));
            return norm(m);
        });
    }

    @Test void applyRotation() throws Exception {
        OracleCases.each(M, "applyRotationScenario", a -> {
            Map<String, Object> spec = map(a.get(0));
            RevocationRegistry reg = new RevocationRegistry(new net.atlasauth.pca.revoke.InMemoryRevocationStore(), () -> (long) CLOCK_MS);
            if (spec.get("pre") != null) {
                for (Object id : (List<?>) spec.get("pre")) {
                    Map<String, Object> in = new LinkedHashMap<>();
                    in.put("kind", "cap"); in.put("value", id); in.put("reason", "pre"); in.put("revokedAt", new Json.Num("1800000000000")); // the oracle's fixed scenario time T0 (a case constant, not the clock)
                    reg.revoke(in);
                }
            }
            Double failAt = JsVal.num(spec.get("failAt"));
            boolean failUnrevoke = Boolean.TRUE.equals(spec.get("failUnrevoke"));
            int[] calls = {0};
            RevocationSink sink = new RevocationSink() {
                @Override public void revoke(Map<String, Object> input) {
                    calls[0]++;
                    if (failAt != null && failAt == calls[0]) throw new IllegalStateException("sink down");
                    reg.revoke(input);
                }
                @Override public boolean unrevoke(Map<String, Object> k) {
                    if (failUnrevoke) throw new IllegalStateException("unrevoke down");
                    return reg.unrevoke(k);
                }
                @Override public Object lookup(String k, String v) { return reg.lookup(k, v); }
            };
            Object res;
            try {
                res = Rotate.applyRotation(sink, spec.get("records"), spec.get("reissued"));
            } catch (RuntimeException e) {
                Map<String, Object> err = new LinkedHashMap<>();
                err.put("$err", true);
                res = err;
            }
            List<Object> list = new ArrayList<>();
            for (RevocationEntry e : reg.list()) list.add(e.toMap());
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("result", res);
            out.put("list", norm(list));
            return out;
        });
    }
}
