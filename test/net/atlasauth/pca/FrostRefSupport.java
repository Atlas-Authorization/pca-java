package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.Supplier;

/**
 * Shared support of the networked FROST and FROST DKG corpus replays: corpus-form argument resolution ({"$bytes"}, {"$share"} dealer
 * shares, {"$num"} non-finite doubles, a trailing {"$rng"} script of the 32-byte values the reference drew), the typed-error capture and
 * the comparison that leaves a reason alone where the corpus marks it as lane-specific text.
 */
final class FrostRefSupport {
    private FrostRefSupport() {}

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    static List<Object> l(Object o) { return o instanceof List ? (List<Object>) o : null; }

    static long lng(Object o) { return IntentJs.lng(o); }

    /** A scripted source of 32-byte draws; a draw past the script fails the case. */
    static final class Script implements Supplier<byte[]> {
        final List<byte[]> vals;
        int pos;
        Script(List<byte[]> vals) { this.vals = vals; }
        @Override public synchronized byte[] get() {
            if (pos >= vals.size()) throw new IllegalStateException("unscripted randomness draw");
            return vals.get(pos++).clone();
        }
    }

    @SuppressWarnings("unchecked")
    static Script script(Object o) {
        List<byte[]> v = new ArrayList<>();
        for (Object x : (List<Object>) o) v.add((byte[]) x);
        return new Script(v);
    }

    private static final Map<String, byte[]> SHARES = new HashMap<>();

    /** The trusted-dealer share of participant {@code id}: the lane's own dealer keygen on the descriptor's seeds. */
    @SuppressWarnings("unchecked")
    static synchronized byte[] resolveShare(Map<String, Object> d) {
        String key = Json.canonicalize(d);
        byte[] s = SHARES.get(key);
        if (s != null) return s;
        Frost.FrostKeygenOpts o = new Frost.FrostKeygenOpts();
        Object secret = un(d.get("secret"));
        o.secret = secret instanceof byte[] ? (byte[]) secret : null;
        if (d.get("coefficients") != null) { o.coefficients = new ArrayList<>(); for (Object c : (List<Object>) un(d.get("coefficients"))) o.coefficients.add((byte[]) c); }
        if (d.get("identifiers") != null) {
            List<Object> ids = (List<Object>) d.get("identifiers");
            o.identifiers = new long[ids.size()];
            for (int i = 0; i < ids.size(); i++) o.identifiers[i] = lng(ids.get(i));
        }
        Frost.FrostKeygenResult kg = Frost.trustedDealerKeygen((int) lng(d.get("t")), (int) lng(d.get("n")), o);
        long id = lng(d.get("id"));
        for (Frost.FrostParticipantShare p : kg.participantShares) if (p.identifier == id) s = p.share;
        SHARES.put(key, s);
        return s;
    }

    /** Corpus form to values: bytes, dealer shares and non-finite numbers resolved, everything else kept. */
    static Object un(Object v) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<?>) v) out.add(un(x));
            return out;
        }
        Map<String, Object> mm = m(v);
        if (mm == null) return v;
        if (mm.size() == 1 && mm.get("$bytes") instanceof String) return Keys.unb64u((String) mm.get("$bytes"));
        if (mm.size() == 1 && mm.get("$share") != null) return resolveShare(m(mm.get("$share")));
        if (mm.size() == 1 && mm.get("$num") instanceof String) {
            String x = (String) mm.get("$num");
            return x.equals("Infinity") ? Double.POSITIVE_INFINITY : x.equals("-Infinity") ? Double.NEGATIVE_INFINITY : Double.NaN;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : mm.entrySet()) out.put(e.getKey(), un(e.getValue()));
        return out;
    }

    /** The arguments of a case, resolved, with a trailing {"$rng"} stripped into a script (null when the case draws nothing). */
    static Object[] args(Map<String, Object> c, Script[] rngOut) {
        List<Object> a = l(un(c.get("args")));
        rngOut[0] = null;
        if (!a.isEmpty()) {
            Map<String, Object> last = m(a.get(a.size() - 1));
            if (last != null && last.size() == 1 && last.containsKey("$rng")) {
                rngOut[0] = script(last.get("$rng"));
                a = new ArrayList<>(a.subList(0, a.size() - 1));
            }
        }
        return a.toArray();
    }

    static Object arg(Object[] a, int i) { return i < a.length ? a[i] : null; }

    // ---- error capture -----------------------------------------------------------------------------------------

    static Map<String, Object> errOut(Throwable e) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("$throws", e.getMessage() != null ? e.getMessage() : e.toString());
        if (e instanceof FrostNet.PoPError) {
            o.put("class", "PoPError");
            if (((FrostNet.PoPError) e).identifier != null) o.put("identifier", ((FrostNet.PoPError) e).identifier);
        } else if (e instanceof FrostNet.EquivocationError) {
            FrostNet.EquivocationError q = (FrostNet.EquivocationError) e;
            o.put("class", "EquivocationError");
            o.put("session_id", q.sessionId); o.put("round", q.round); o.put("identifier", q.identifier);
            o.put("previousDigest", q.previousDigest); o.put("offendingDigest", q.offendingDigest);
        } else if (e instanceof FrostNet.CoordinatorTimeoutError) {
            o.put("class", "CoordinatorTimeoutError");
            o.put("refusals", ((FrostNet.CoordinatorError) e).refusals);
            o.put("timeoutMs", ((FrostNet.CoordinatorTimeoutError) e).timeoutMs);
        } else if (e instanceof FrostNet.CoordinatorError) {
            o.put("class", "CoordinatorError");
            o.put("refusals", ((FrostNet.CoordinatorError) e).refusals);
        } else if (e instanceof FrostDkgChannel.DkgChannelError) {
            FrostDkgChannel.DkgChannelError q = (FrostDkgChannel.DkgChannelError) e;
            o.put("code", q.code);
            o.put("class", "DkgChannelError");
            o.put("peer", q.peer);
        }
        return o;
    }

    // ---- comparison ---------------------------------------------------------------------------------------------

    /** Where the corpus marks a reason open (lane-specific text) the reason is not compared; a refusal's message text never is. */
    @SuppressWarnings("unchecked")
    static void prune(Object want, Object got) {
        if (want instanceof Map && got instanceof Map) {
            Map<String, Object> w = (Map<String, Object>) want, g = (Map<String, Object>) got;
            if (Boolean.TRUE.equals(w.get("reasonOpen"))) { w.remove("reasonOpen"); w.remove("reason"); g.remove("reason"); }
            if (w.containsKey("$throws") && g.containsKey("$throws")) g.put("$throws", w.get("$throws"));
            for (String k : new ArrayList<>(w.keySet())) if (g.containsKey(k)) prune(w.get(k), g.get(k));
        } else if (want instanceof List && got instanceof List) {
            List<Object> w = (List<Object>) want, g = (List<Object>) got;
            for (int i = 0; i < Math.min(w.size(), g.size()); i++) prune(w.get(i), g.get(i));
        }
    }

    static String diff(Map<String, Object> c, Callable<Object> f) {
        Object got = null;
        Throwable err = null;
        try { got = f.call(); } catch (Throwable t) { err = t; }
        Object want = c.get("out");
        if (err != null) got = errOut(err);
        Object norm = IntentJs.normalize(OracleCases.toJson(got));
        prune(want, norm);
        if (IntentJs.jsonEquals(want, norm)) return null;
        String g;
        try { g = Json.canonicalize(norm); } catch (RuntimeException e) { g = String.valueOf(norm); }
        String w;
        try { w = Json.canonicalize(want); } catch (RuntimeException e) { w = String.valueOf(want); }
        return c.get("name") + "\n  want: " + w + "\n  got:  " + g + (err != null && !(err instanceof RuntimeException) ? "\n  err: " + err : "");
    }

    /** Replays every case of {@code fn}: the lambda gets the resolved arguments and the randomness script (null when none). */
    interface Body { Object apply(Object[] a, Script rng) throws Exception; }

    static void each(String module, String fn, Body body) throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : OracleCases.of(module, fn)) {
            Script[] r = new Script[1];
            Object[] a = args(c, r);
            String d = diff(c, () -> body.apply(a, r[0]));
            if (d != null) bad.add(d);
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s) of " + fn + ":\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 30))));
    }

    static byte[] bytes(Object o) { return o instanceof byte[] ? (byte[]) o : null; }

    static BigInteger big(long v) { return BigInteger.valueOf(v); }
}
