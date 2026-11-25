package net.atlasauth.pca.actions;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Predicate;
import net.atlasauth.pca.ActionRegistry;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;

/**
 * The signed per-definition changes between two versions of a pack (an evolution record per changed verb). A grant that pinned a
 * definition digest follows a record chain only through steps the registry signed as {@code equal} or {@code narrow}; everything else
 * needs the principal. Signing supports every suite the core signer does.
 */
public final class ActionEvolve {
    private ActionEvolve() {}

    public static final String EVOLUTION_RECORD_KIND = "pca-evolution-record";
    private static final String EVOLUTION_DOMAIN = "atlas-pca/action-evolution/v1\0";

    private static TreeMap<String, Map<String, Object>> byVerb(List<?> defs) {
        TreeMap<String, Map<String, Object>> m = new TreeMap<>();
        for (Object d : defs) {
            String v = (String) J.get(d, "verb");
            if (m.containsKey(v)) throw new Actions.ActionKitError("duplicate_def", "verb '" + v + "' appears twice");
            m.put(v, J.m(d));
        }
        return m;
    }

    /** The unsigned records that take {@code prev} to {@code next} (sorted by verb). A verb rename is {@code removed} + {@code added}. */
    public static List<Object> evolutionRecords(String ns, List<?> prev, List<?> next, Actions.Registry reg, Predicate<Map<String, Object>> attestationVerified) {
        TreeMap<String, Map<String, Object>> a = byVerb(prev), b = byVerb(next);
        TreeSet<String> verbs = new TreeSet<>(a.keySet());
        verbs.addAll(b.keySet());
        List<Object> out = new ArrayList<>();
        for (String verb : verbs) {
            Map<String, Object> o = a.get(verb), n = b.get(verb);
            Map<String, Object> base = J.obj("v", J.n(1), "kind", EVOLUTION_RECORD_KIND, "ns", ns, "verb", verb);
            Map<String, Object> r = new LinkedHashMap<>(base);
            if (o == null) { r.put("from", null); r.put("to", Actions.defDigest(n)); r.put("class", "added"); r.put("reasons", new ArrayList<>()); }
            else if (n == null) { r.put("from", Actions.defDigest(o)); r.put("to", null); r.put("class", "removed"); r.put("reasons", new ArrayList<>()); }
            else {
                String from = Actions.defDigest(o), to = Actions.defDigest(n);
                if (from.equals(to)) continue;
                Map<String, Object> d = ActionDiff.diffDefs(o, n, reg, attestationVerified);
                r.put("from", from); r.put("to", to); r.put("class", d.get("class")); r.put("reasons", d.get("reasons"));
            }
            out.add(r);
        }
        return out;
    }

    /** Sign the records as the registry with an Ed25519 seed ({@code kid} names the pinned key entry). */
    public static List<Object> signEvolution(List<?> records, String kid, byte[] secret) {
        return signEvolution(records, kid, Keys.ed25519(Keys.edFromSeed(secret)));
    }

    /** Sign the records as the registry under any signature suite the core supports (Ed25519, hybrids, pure PQ). */
    public static List<Object> signEvolution(List<?> records, String kid, Keys.SuiteKey key) {
        List<Object> out = new ArrayList<>();
        for (Object r : records) {
            String bad = ActionRegistry.evolutionRecordError(r, false);
            if (bad != null) throw new IllegalArgumentException("signEvolutionRecord: " + bad);
            byte[] dom = EVOLUTION_DOMAIN.getBytes(StandardCharsets.UTF_8), body = Json.canonicalizeStrict(r).getBytes(StandardCharsets.UTF_8);
            byte[] msg = new byte[dom.length + body.length];
            System.arraycopy(dom, 0, msg, 0, dom.length);
            System.arraycopy(body, 0, msg, dom.length, body.length);
            String[] parts = key.sign(msg);
            Map<String, Object> sig = J.obj("alg", key.alg, "kid", kid, "value", parts[0]);
            if (parts[1] != null) sig.put("pq_value", parts[1]);
            Map<String, Object> s = new LinkedHashMap<>(J.m(r));
            s.put("sig", sig);
            out.add(s);
        }
        return out;
    }

    private static String key(Map<String, Object> r) {
        return r.get("verb") + "|" + J.jsStr(r.get("from")) + "|" + J.jsStr(r.get("to")) + "|" + r.get("class") + "|" + ActionRegistry.evolutionDiffDigest(r);
    }

    /**
     * Does {@code records} EXACTLY describe the change from {@code prev} to {@code next}? Every record verifies under the pinned registry keys and names
     * {@code ns}; none is missing and none is extra; the class of each is the one the diff computes. Null = consistent, else the reason.
     */
    public static String evolutionError(String ns, List<?> prev, List<?> next, List<?> records, List<?> keys, Actions.Registry reg, Predicate<Map<String, Object>> attestationVerified) {
        try {
            for (Object r : records) {
                String v = ActionRegistry.verifyEvolutionRecord(r, keys);
                if (v != null) return "evolution record: " + v;
                if (!ns.equals(J.get(r, "ns"))) return "evolution record names namespace '" + J.jsStr(J.get(r, "ns")) + "', not '" + ns + "'";
            }
            List<String> want = new ArrayList<>(), have = new ArrayList<>();
            for (Object r : evolutionRecords(ns, prev, next, reg, attestationVerified)) want.add(key(J.m(r)));
            for (Object r : records) { Map<String, Object> u = new LinkedHashMap<>(J.m(r)); u.remove("sig"); have.add(key(u)); }
            want.sort(null);
            have.sort(null);
            if (want.size() != have.size()) return "evolution has " + have.size() + " records, the change needs " + want.size();
            for (int i = 0; i < want.size(); i++) if (!want.get(i).equals(have.get(i))) return "evolution records do not match the computed change (a missing, extra or mis-classified record)";
            return null;
        } catch (RuntimeException e) {
            return "evolution error: " + e.getMessage();
        }
    }
}
