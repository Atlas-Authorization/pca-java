package net.atlasauth.pca.goal;

import net.atlasauth.pca.Json;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Runtime drift monitoring, tighten-only. A monitor compares the action stream to the goal's expected profile (verbs, resources,
 * magnitude, rate, novelty). Anomalies convert allow to escalate; the strike counter is a ratchet; at {@code lockdown} strikes every
 * allow becomes escalate. {@link #applyDrift} can never relax a decision.
 */
public final class GoalDrift {
    private GoalDrift() {}

    /** Defaults: windowMs 60000, maxPerWindow 20, maxNovel 3, magnitudeFactor 3, warmup 5, lockdown 5. */
    public static Map<String, Object> defaults() {
        return G.map("windowMs", G.num(60000), "maxPerWindow", G.num(20), "maxNovel", G.num(3), "magnitudeFactor", G.num(3), "warmup", G.num(5), "lockdown", G.num(5));
    }

    private static Map<String, Object> mm(Object o) { return G.m(o); }

    /** The verbs of the goal's grants. */
    public static Set<String> expectedVerbs(Map<String, Object> g) {
        Set<String> out = new LinkedHashSet<>();
        for (Object gr : G.arr(g.get("grants"), "grants")) out.add((String) G.get(gr, "verb"));
        return out;
    }

    private static void resIds(Map<String, Object> s, Set<String> out) {
        switch (G.kind(s)) {
            case "exact": out.add((String) s.get("id")); break;
            case "oneof": for (Object i : G.arr(s.get("ids"), "ids")) out.add((String) i); break;
            case "all_of": for (Object p : G.arr(s.get("parts"), "parts")) resIds(mm(p), out); break;
            default: break;
        }
    }

    private static Set<String> knownResources(Map<String, Object> g) {
        Set<String> out = new LinkedHashSet<>();
        for (Object gr : G.arr(g.get("grants"), "grants")) resIds(mm(G.get(gr, "res")), out);
        return out;
    }

    private static String numStr(Object o) {
        Double d = G.dbl(o);
        if (d == null) return G.jsStr(o);
        if (d == Math.rint(d) && Math.abs(d) < 1e21) return new BigDecimal(d).toPlainString();
        return G.jsStr(o);
    }

    private static Map<String, Object> freshState() {
        return G.map("strikes", G.num(0), "times", new ArrayList<Object>(), "novel", new ArrayList<Object>(), "seen", new LinkedHashMap<String, Object>());
    }

    private static byte[] hmac(byte[] key, String text) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key.length == 0 ? new byte[1] : key, "HmacSHA256"));
            return m.doFinal(Json.utf8(text));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    /** Node's Buffer.from(s, 'hex'): decoding stops at the first non-hex pair. */
    private static byte[] hexLenient(String s) {
        List<Byte> out = new ArrayList<>();
        for (int i = 0; i + 1 < s.length(); i += 2) {
            int hi = Character.digit(s.charAt(i), 16), lo = Character.digit(s.charAt(i + 1), 16);
            if (hi < 0 || lo < 0 || s.charAt(i) > 127 || s.charAt(i + 1) > 127) break;
            out.add((byte) (hi * 16 + lo));
        }
        byte[] r = new byte[out.size()];
        for (int i = 0; i < r.length; i++) r[i] = out.get(i);
        return r;
    }

    /** One drift monitor over a goal. */
    public static final class Monitor {
        private final Map<String, Object> goal;
        private final Map<String, Object> o;
        private Map<String, Object> st = freshState();

        public Monitor(Map<String, Object> goal, Map<String, Object> opts) {
            this.goal = goal;
            this.o = defaults();
            if (opts != null) o.putAll(opts);
        }

        private double opt(String k) { return G.toNum(o.get(k)); }

        /** Observe an action at time {@code t}: {anomalous, strikes, lockdown, reasons}. */
        public Map<String, Object> observe(Map<String, Object> a, Object t) {
            List<Object> reasons = new ArrayList<>();
            if (!expectedVerbs(goal).contains(a.get("verb"))) reasons.add("verb " + G.jsStr(a.get("verb")) + " outside the goal profile");
            Set<String> known = knownResources(goal);
            List<Object> novel = G.l(st.get("novel"));
            if (!known.isEmpty() && !known.contains(a.get("res")) && !novel.contains(a.get("res"))) novel.add(a.get("res"));
            if (novel.size() > opt("maxNovel")) reasons.add("novel resources beyond the allowance");
            List<Object> times = new ArrayList<>();
            for (Object x : G.arr(st.get("times"), "times")) if (G.toNum(x) > G.toNum(t) - opt("windowMs")) times.add(x);
            times.add(t);
            st.put("times", times);
            if (times.size() > opt("maxPerWindow")) reasons.add("rate above the profile");
            Map<String, Object> params = mm(a.get("params"));
            if (params == null) throw new IrError("params expected");
            Map<String, Object> seen = mm(st.get("seen"));
            for (Map.Entry<String, Object> e : params.entrySet()) {
                Map<String, Object> l = mm(e.getValue());
                if (!G.kind(l).equals("q")) continue;
                String p = e.getKey();
                List<Object> hist = seen.get(p) == null ? new ArrayList<>() : G.l(seen.get(p));
                Object v = mm(l.get("q")).get("n");
                if (hist.size() >= opt("warmup")) {
                    double sum = 0;
                    for (Object x : hist) sum += G.toNum(x);
                    double mean = sum / hist.size();
                    if (mean > 0 && G.toNum(v) > mean * opt("magnitudeFactor")) reasons.add(p + " magnitude " + numStr(o.get("magnitudeFactor")) + "x above the running mean");
                }
                List<Object> next = new ArrayList<>(hist);
                next.add(v);
                seen.put(p, new ArrayList<>(next.subList(Math.max(0, next.size() - 50), next.size())));
            }
            if (!reasons.isEmpty()) st.put("strikes", G.num(G.safeInt(st.get("strikes")) + 1));
            long strikes = G.safeInt(st.get("strikes"));
            return G.map("anomalous", !reasons.isEmpty(), "strikes", G.num(strikes), "lockdown", strikes >= opt("lockdown"), "reasons", reasons);
        }

        public Map<String, Object> state() { return st; }

        /** Sealed state: {state, mac} (HMAC-SHA256 over the state's JSON text, hex). */
        public Map<String, Object> seal(byte[] key) { return G.map("state", st, "mac", hex(hmac(key, G.stringify(st)))); }

        /** Restore; a state that fails its MAC locks down (fail closed). */
        public static Monitor restore(Map<String, Object> goal, Map<String, Object> sealed, byte[] key, Map<String, Object> opts) {
            Monitor m = new Monitor(goal, opts);
            byte[] want = hmac(key, G.stringify(sealed.get("state")));
            byte[] got = hexLenient(String.valueOf(sealed.get("mac")));
            if (got.length == want.length && MessageDigest.isEqual(got, want)) m.st = mm(sealed.get("state"));
            else {
                m.st = freshState();
                m.st.put("strikes", G.num((long) m.opt("lockdown")));
            }
            return m;
        }
    }

    /** Tighten-only: allow becomes escalate on an anomaly or lockdown; nothing else changes. */
    public static String applyDrift(String d, Map<String, Object> signal) {
        return "allow".equals(d) && (G.truthy(signal.get("anomalous")) || G.truthy(signal.get("lockdown"))) ? "escalate" : d;
    }

    /** Decide, observe, tighten: {decision, signal}. {@code c} = {act, rels, hist?}. */
    public static Map<String, Object> guardedDecide(Map<String, Object> goal, Map<String, Object> ont, Monitor mon, Map<String, Object> c, Object t) {
        String base = (String) GoalExamples.decideCase(goal, ont, c).get("decision");
        Map<String, Object> signal = mon.observe(mm(c.get("act")), t);
        return G.map("decision", applyDrift(base, signal), "signal", signal);
    }
}
