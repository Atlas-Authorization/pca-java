package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The action pin's signing half against the reference corpus (ref-action-pin, 111 cases): the constants, registry document and evolution record
 * signing under three suites, key entries, the principal's re-approval, and the verification of what they sign. A corpus argument cannot carry a
 * signed zero, so the case body8 gets -0.
 */
class ActionPinRefDiffTest {
    static final String MODULE = "ref-action-pin";
    static final int TOTAL = 111;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    @SuppressWarnings("unchecked")
    private static Object nums(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(nums(x));
            return out;
        }
        Map<String, Object> map = m(v);
        if (map == null) return v;
        if (map.size() == 1 && map.get("$num") instanceof String) return Double.parseDouble((String) map.get("$num"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : map.entrySet()) out.put(e.getKey(), nums(e.getValue()));
        return out;
    }

    private static byte[] bytes(Object o) { return Keys.unb64u((String) m(o).get("$bytes")); }

    private static Pq.SignerSuiteOpts suite(Object o) {
        Map<String, Object> s = m(o);
        if (s == null) return null;
        Pq.SignerSuiteOpts out = new Pq.SignerSuiteOpts();
        out.alg = (String) s.get("alg");
        if (s.containsKey("pqSeed")) out.mlDsa = Pq.mlDsa65Keygen(bytes(s.get("pqSeed")));
        return out;
    }

    private static Object verdict(String why) { return why == null ? Issue.obj("ok", true) : Issue.obj("ok", false, "reason", why); }

    /** A refusal that carries the reference's canonicalization text keeps only the prefix before it. */
    private static Object cut(Object v) {
        Map<String, Object> map = m(v);
        if (map == null || !(map.get("reason") instanceof String)) return v;
        String r = (String) map.get("reason");
        int i = r.indexOf("canonicalize:");
        if (i < 0) return v;
        Map<String, Object> out = new LinkedHashMap<>(map);
        out.put("reason", r.substring(0, i + "canonicalize:".length()));
        return out;
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("ACTION_PIN_ON_NEW", new ArrayList<Object>(ActionRegistry.ACTION_PIN_ON_NEW));
            o.put("EVOLUTION_CLASSES", new ArrayList<Object>(ActionRegistry.EVOLUTION_CLASSES));
            o.put("EVOLUTION_RECORD_KIND", ActionRegistry.EVOLUTION_RECORD_KIND);
            o.put("REAPPROVAL_KIND", ActionRegistry.REAPPROVAL_KIND);
            o.put("EVOLUTION_DOMAIN", ActionRegistry.EVOLUTION_DOMAIN);
            o.put("EVOLUTION_DIFF_DOMAIN", ActionRegistry.EVOLUTION_DIFF_DOMAIN);
            o.put("REAPPROVAL_DOMAIN", ActionRegistry.REAPPROVAL_DOMAIN);
            o.put("MAX_EVOLUTION_STEPS", ActionRegistry.MAX_EVOLUTION_STEPS);
            o.put("MAX_ESC_TIER", ActionRegistry.MAX_ESC_TIER);
            return o;
        });
        f.put("signRegistryDoc", x -> ActionRegistry.signRegistryDoc((String) arg(x, 0), nums(arg(x, 1)), (String) arg(x, 2), bytes(arg(x, 3)), suite(arg(x, 4))));
        f.put("signEvolutionRecord", x -> ActionRegistry.signEvolutionRecord(nums(arg(x, 0)), (String) arg(x, 1), bytes(arg(x, 2)), suite(arg(x, 3))));
        f.put("registryKeyOf", x -> ActionRegistry.registryKeyOf((String) arg(x, 0), bytes(arg(x, 1)), suite(arg(x, 2))));
        f.put("signReapproval", x -> {
            Map<String, Object> a = m(arg(x, 0));
            return ActionRegistry.signReapproval((String) a.get("grantId"), m(nums(a.get("record"))), bytes(a.get("principalSecret")));
        });
        f.put("verifyRegistrySig", x -> verdict(ActionRegistry.verifyRegistrySig((String) arg(x, 0), nums(arg(x, 1)), m(nums(arg(x, 2))), nums(arg(x, 3)))));
        f.put("verifyEvolutionRecord", x -> verdict(ActionRegistry.verifyEvolutionRecord(nums(arg(x, 0)), nums(arg(x, 1)))));
        f.put("reapprovalValid", x -> ActionRegistry.reapprovalValid(nums(arg(x, 0)), arg(x, 1), arg(x, 2), arg(x, 3), arg(x, 4)));

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);

        List<String> bad = new ArrayList<>();
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) {
            for (Map<String, Object> c : OracleCases.of(MODULE, e.getKey())) {
                OracleCases.Fn fn = e.getValue();
                if (e.getKey().equals("signRegistryDoc") && ((String) c.get("name")).contains("/body8")) {
                    fn = a -> ActionRegistry.signRegistryDoc((String) arg(a, 0), Issue.obj("n", -0.0), (String) arg(a, 2), bytes(arg(a, 3)), suite(arg(a, 4))); // a signed zero cannot be spelled in the corpus
                }
                OracleCases.Fn run = fn;
                String d = OracleCases.diff(c, cut(c.get("out")), a -> cut(run.apply(a)));
                if (d != null) bad.add(d);
            }
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }
}
