package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiPredicate;
import net.atlasauth.pca.intent.IntentJit;
import net.atlasauth.pca.intent.IntentLearner;
import net.atlasauth.pca.intent.IntentMapKit;
import net.atlasauth.pca.intent.IntentMapKit.MapLearnerOptions;
import net.atlasauth.pca.intent.IntentOmega;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;
import org.junit.jupiter.api.Test;

class IntentJitDiffTest {
    private static final String M = "ref-intent-jit";
    private static final String A = "action.params.";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mp(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> ls(Object o) { return (List<Object>) o; }

    private static IntentLearner make(Object omega, Object mapOpts, Object obs) {
        IntentLearner l = IntentMapKit.createLearner(IntentOmega.omegaFromJson(omega), MapLearnerOptions.fromJson(mapOpts));
        for (Object xo : ls(obs)) {
            Map<String, Object> x = mp(xo);
            l.observe(IntentOmega.outcomeFromJson(x), (int) IntentOmega.dbl(x.get("y")), (String) x.get("source"), null);
        }
        return l;
    }

    private static int[] ints(Object o) {
        List<Object> l = ls(o);
        int[] a = new int[l.size()];
        for (int i = 0; i < a.length; i++) a[i] = (int) IntentOmega.dbl(l.get(i));
        return a;
    }

    private static BiPredicate<VerbSpace, Outcome> ceiling(String name) {
        switch (name) {
            case "all": return (vs, o) -> true;
            case "none": return (vs, o) -> false;
            case "amountLe60": return (vs, o) -> !(o.values().get(A + "amount") instanceof Double) || (Double) o.values().get(A + "amount") <= 60;
            default: return (vs, o) -> !o.verb().equals("gmail.send");
        }
    }

    private static VerbSpace verb(Omega om, String v) {
        for (VerbSpace x : om.verbs) if (x.verb.equals(v)) return x;
        return null;
    }

    @Test void visitScenario() throws Exception {
        OracleCases.each(M, "visitScenario", a -> {
            List<BiPredicate<VerbSpace, Outcome>> cs = new ArrayList<>();
            for (Object c : ls(a.get(5))) cs.add(ceiling((String) c));
            return IntentJit.decideVisit(make(a.get(0), a.get(1), a.get(2)), IntentOmega.outcomeFromJson(a.get(3)), mp(a.get(4)), cs, Boolean.TRUE.equals(a.get(6)));
        });
    }

    @Test void cellCoords() throws Exception {
        OracleCases.each(M, "cellCoords", a -> IntentJit.cellCoords(IntentOmega.verbSpaceFromJson(a.get(0)), ints(a.get(1))));
    }

    @Test void cellFromCoords() throws Exception {
        OracleCases.each(M, "cellFromCoords", a -> {
            double[] r = IntentJit.cellFromCoords(IntentOmega.verbSpaceFromJson(a.get(0)), mp(a.get(1)));
            if (r == null) return null;
            List<Object> out = new ArrayList<>();
            for (double d : r) out.add(d);
            return out;
        });
    }

    @Test void deltaScenario() throws Exception {
        OracleCases.each(M, "deltaScenario", a -> {
            List<Object> both = new ArrayList<>(ls(a.get(2)));
            both.addAll(ls(a.get(3)));
            IntentLearner prev = make(a.get(0), a.get(1), a.get(2));
            IntentLearner next = make(a.get(0), a.get(1), both);
            Map<String, byte[]> d = IntentJit.deltaCells(prev, next);
            Map<String, Object> cells = new LinkedHashMap<>();
            for (Map.Entry<String, byte[]> e : d.entrySet()) {
                List<Object> row = new ArrayList<>();
                for (byte b : e.getValue()) row.add((double) b);
                cells.put(e.getKey(), row);
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("cells", cells);
            out.put("predicates", IntentJit.deltaPredicates(next.omega, d));
            return out;
        });
    }

    @Test void requiredScenario() throws Exception {
        OracleCases.each(M, "requiredScenario", a -> {
            Omega om = IntentOmega.omegaFromJson(a.get(0));
            VerbSpace vs = verb(om, (String) a.get(1));
            int[] cell = ints(a.get(2));
            Map<String, Object> inp = mp(a.get(3));
            Keys.SuiteKey site = Keys.ed25519(Keys.edFromSeed(Keys.unb64u((String) a.get(4))));
            Map<String, Object> out = new LinkedHashMap<>();
            Map<String, Object> body = IntentJit.intentRequiredBody(inp, vs, cell);
            out.put("signed", IntentJit.signedIntentRequired(inp, vs, cell, "site-1", site));
            out.put("body", body);
            return out;
        });
    }

    @Test void walletScenario() throws Exception {
        OracleCases.each(M, "walletScenario", a -> {
            Omega om = IntentOmega.omegaFromJson(a.get(0));
            Map<String, Object> inp = mp(a.get(1));
            String mutation = (String) a.get(2);
            Keys.EdKey siteKey = Keys.edFromSeed(Keys.unb64u((String) a.get(7)));
            Map<String, Object> signed = IntentJit.signedIntentRequired(inp, verb(om, "stripe.refund"), new int[] {1, 0}, "site-1", Keys.ed25519(siteKey));
            Object body = IntentJs.normalize(signed);
            Map<String, Object> b = mp(body);
            switch (mutation) {
                case "coords": mp(mp(b.get("cell")).get("coords")).put(A + "amount", new ArrayList<Object>(List.of(new Json.Num("2"), new Json.Num("2")))); break;
                case "verb": mp(b.get("cell")).put("verb", "gmail.send"); break;
                case "sig": { String v = (String) mp(b.get("sig")).get("value"); mp(b.get("sig")).put("value", v.substring(0, v.length() - 2) + "AA"); break; }
                case "kid": mp(b.get("sig")).put("kid", "other"); break;
                case "session": b.put("session", Pca.b64(Pca.sha("other".getBytes()))); break;
                case "action": b.put("action_digest", Pca.b64(Pca.sha("other".getBytes()))); break;
                case "null": body = null; break;
                default: break;
            }
            Map<String, Object> key = new LinkedHashMap<>();
            key.put("kid", "site-1");
            key.put("alg", "ed25519");
            key.put("pk", siteKey.id());
            List<Object> keys = new ArrayList<>();
            keys.add(key);
            double now = IntentOmega.dbl(a.get(3));
            if (now != Math.floor(now)) return IntentJit.walletCheckIntentRequired(body, keys, Long.MIN_VALUE, (String) a.get(5), (String) a.get(6), om, IntentOmega.outcomeFromJson(a.get(4)), mp(inp.get("pcactn")));
            return IntentJit.walletCheckIntentRequired(body, keys, (long) now, (String) a.get(5), (String) a.get(6), om, IntentOmega.outcomeFromJson(a.get(4)), mp(inp.get("pcactn")));
        });
    }

    @Test void mintScenario() throws Exception {
        OracleCases.each(M, "mintScenario", a -> {
            List<Object> both = new ArrayList<>(ls(a.get(2)));
            both.addAll(ls(a.get(3)));
            IntentLearner prev = make(a.get(0), a.get(1), a.get(2));
            IntentLearner next = make(a.get(0), a.get(1), both);
            Keys.SuiteKey principal = Keys.ed25519(Keys.edFromSeed(Keys.unb64u((String) a.get(5))));
            return IntentJit.mintDelta(prev, next, mp(a.get(4)), principal);
        });
    }
}
