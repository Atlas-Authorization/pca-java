package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.nio.charset.StandardCharsets;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.IntentBridge;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.intent.IntentOmega.HarmModel;
import net.atlasauth.pca.intent.IntentOmega.Omega;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * The layered intent lattice (org ceiling, site policy, standing profile, task grant: deny anywhere wins, a ceiling is never a
 * question) and the quorum of principal-signed approvals that a shared layer needs to widen. The learner-bound views
 * (the lattice view of a task learner and its outcome decision) live with the learner.
 */
public final class IntentLayers {
    private IntentLayers() {}

    /** The ceilings in evaluation order. */
    public static final List<String> LAYER_CEILINGS = List.of("org", "site", "std");
    public static final String LAYER_APPROVAL_DOMAIN = "atlas-pca/intent-layer-approval/v1\0";

    /** A well-formed layer: an object with exactly one member, {@code predicates}, a list. */
    public static boolean isLayerPolicy(Object l) {
        return l instanceof Map && ((Map<?, ?>) l).size() == 1 && ((Map<?, ?>) l).get("predicates") instanceof List;
    }

    /** Compiled ceilings; an absent ceiling is null. */
    public record CeilingAdmitters(IntentPolicy.Admitter org, IntentPolicy.Admitter site, IntentPolicy.Admitter std) {
        IntentPolicy.Admitter of(String k) { return k.equals("org") ? org : k.equals("site") ? site : std; }
    }

    /** Absent = no ceiling; a ceiling PRESENT with null (or not an object) is malformed: throws. */
    public static CeilingAdmitters ceilingAdmitters(Map<String, Object> layers) {
        IntentPolicy.Admitter[] out = new IntentPolicy.Admitter[3];
        for (int i = 0; i < 3; i++) {
            String k = LAYER_CEILINGS.get(i);
            if (!layers.containsKey(k)) continue;
            Object l = layers.get(k);
            if (!(l instanceof Map)) throw new IllegalArgumentException("ceilingAdmitters: the " + k + " ceiling is malformed (null or not an object)");
            out[i] = IntentPolicy.admitter(l);
        }
        return new CeilingAdmitters(out[0], out[1], out[2]);
    }

    /** The first ceiling that excludes the outcome, or null when every ceiling admits it. */
    public static String ceilingOf(CeilingAdmitters c, VerbSpace vs, Outcome o) {
        for (String k : LAYER_CEILINGS) {
            IntentPolicy.Admitter a = c.of(k);
            if (a != null && !a.admits(vs, o)) return k;
        }
        return null;
    }

    private static String key(String verb, List<?> cell) {
        StringBuilder sb = new StringBuilder(verb).append('|');
        for (int i = 0; i < cell.size(); i++) sb.append(i == 0 ? "" : ",").append(AttestCommon.jsNumString(IntentOmega.dbl(cell.get(i))));
        return sb.toString();
    }

    /** A question may only be about a cell of the uncertain set (inside every ceiling). Throws otherwise. */
    public static void assertAskable(Map<String, Object> view, Map<String, Object> c) {
        String k = key((String) c.get("verb"), IntentOmega.arr(c.get("cell")));
        for (Object u : IntentOmega.arr(view.get("uncertain"))) {
            Map<String, Object> um = IntentOmega.obj(u);
            if (key((String) um.get("verb"), IntentOmega.arr(um.get("cell"))).equals(k)) return;
        }
        throw new IllegalArgumentException("layers: cell " + k + " is not an uncertain cell inside every ceiling (never a question)");
    }

    /** Layer owner's own risk of a set of cells ({verb, cell}): sum of mass * (1 - a) * E[h | cell]. */
    public static double ownerRisk(Omega omega, List<Map<String, Object>> cells, IntentMetrics.Acceptability acceptability, HarmModel harm) {
        double r = 0;
        for (Map<String, Object> c : cells) {
            VerbSpace vs = IntentOmega.verbSpace(omega, (String) c.get("verb"));
            if (vs == null) continue;
            List<Object> cl = IntentOmega.arr(c.get("cell"));
            int[] idx = new int[cl.size()];
            for (int i = 0; i < idx.length; i++) idx[i] = (int) IntentOmega.dbl(cl.get(i));
            IntentOmega.Stats st = IntentOmega.cellStats(vs, idx, harm);
            r += st.mass() * (1 - acceptability.of(vs, IntentOmega.cellRep(vs, idx))) * st.harm();
        }
        return r;
    }

    private static Map<String, Object> cellKey(String verb, int[] cell) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("verb", verb);
        List<Object> c = new ArrayList<>();
        for (int x : cell) c.add(x);
        m.put("cell", c);
        return m;
    }

    /** Every cell of the space an admitter admits (the layer as a cell set). */
    public static List<Map<String, Object>> layerCells(Omega omega, IntentPolicy.Admitter a) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (VerbSpace vs : omega.verbs) {
            double n = IntentOmega.verbCellCount(vs);
            for (double f = 0; f < n; f++) {
                int[] cell = IntentOmega.decodeCell(vs, f);
                if (a.admits(vs, IntentOmega.cellRep(vs, cell))) out.add(cellKey(vs.verb, cell));
            }
        }
        return out;
    }

    /** Flat key of a cell ({verb, cell}). */
    public static String cellKeyOf(Omega omega, Map<String, Object> c) {
        String verb = (String) c.get("verb");
        VerbSpace vs = IntentOmega.verbSpace(omega, verb);
        List<Object> cl = IntentOmega.arr(c.get("cell"));
        if (vs == null) return key(verb, cl);
        int[] idx = new int[cl.size()];
        for (int i = 0; i < idx.length; i++) idx[i] = (int) IntentOmega.dbl(cl.get(i));
        return verb + "|" + AttestCommon.jsNumString(IntentOmega.encodeCell(vs, idx));
    }

    // ---- quorum-signed layer approvals ----

    private static final List<String> STATEMENT_KEYS = List.of("v", "kind", "layer", "session", "seq", "map_digest", "prev");

    private static Map<String, Object> statementOf(Map<String, Object> a) {
        Map<String, Object> st = new LinkedHashMap<>();
        st.put("v", new Json.Num("1"));
        st.put("kind", "pca-intent-layer-approval");
        for (String k : List.of("layer", "session", "seq", "map_digest", "prev")) if (a.containsKey(k)) st.put(k, a.get(k));
        return st;
    }

    private static byte[] approvalMessage(Map<String, Object> st) {
        return IntentBridge.message(LAYER_APPROVAL_DOMAIN, st);
    }

    /** Sign an approval of a shared-layer widening ({layer, session, seq, map_digest, prev}). */
    public static Map<String, Object> signLayerApproval(Map<String, Object> s, byte[] secretSeed) {
        Keys.EdKey key = Keys.edFromSeed(secretSeed);
        Map<String, Object> st = statementOf(s);
        Map<String, Object> out = new LinkedHashMap<>(st);
        out.put("signer", key.id());
        out.put("sig", Keys.b64u(key.sign(approvalMessage(st))));
        return out;
    }

    private static boolean strictEq(Object a, Object b) {
        if (a == null || b == null) return a == b;
        Double x = IntentBridge.num(a), y = IntentBridge.num(b);
        if (x != null || y != null) return x != null && y != null && x.doubleValue() == y.doubleValue();
        if (a instanceof String || a instanceof Boolean) return a.equals(b);
        return a == b;
    }

    private static Map<String, Object> quorumResult(boolean ok, List<String> signers, List<Map<String, Object>> ignored) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", ok);
        m.put("signers", new ArrayList<Object>(signers));
        m.put("ignored", new ArrayList<Object>(ignored));
        return m;
    }

    private static Map<String, Object> ign(int index, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("index", index);
        m.put("reason", reason);
        return m;
    }

    /**
     * Verify approvals against the layer's members and rule. An approval counts iff its signer is a member, it is the FIRST from
     * that member, its statement equals {@code expected} field by field and its signature verifies; the rule is the multi-principal
     * one over member keys. Returns {ok, signers, ignored[{index, reason}]}.
     */
    public static Map<String, Object> verifyQuorumApprovals(Object approvals, Object members, Map<String, Object> rule, Object expected) {
        List<Map<String, Object>> none = new ArrayList<>();
        if (!(approvals instanceof List) || !(members instanceof List) || !(expected instanceof Map || expected instanceof List)) {
            none.add(ign(-1, "approvals and members must be arrays and expected an object"));
            return quorumResult(false, new ArrayList<>(), none);
        }
        List<?> ms = (List<?>) members;
        Set<Object> distinct = new HashSet<>(ms);
        boolean bad = distinct.size() != ms.size();
        for (Object m : ms) if (!(m instanceof String) || Pca.decodeB64uStrict(m, 32) == null) bad = true;
        if (bad) {
            none.add(ign(-1, "members must be distinct 32-byte keys"));
            return quorumResult(false, new ArrayList<>(), none);
        }
        List<String> mem = new ArrayList<>();
        for (Object m : ms) mem.add((String) m);
        IntentMulti.NormalRule n;
        try {
            n = IntentMulti.normalizeRule(rule, mem);
        } catch (RuntimeException e) {
            none.add(ign(-1, e.getMessage()));
            return quorumResult(false, new ArrayList<>(), none);
        }
        Map<String, Object> want = statementOf(expected instanceof Map ? IntentOmega.obj(expected) : new LinkedHashMap<String, Object>()); // an array is an object with no members
        Set<String> counted = new HashSet<>();
        List<Map<String, Object>> ignored = new ArrayList<>();
        List<?> aps = (List<?>) approvals;
        for (int i = 0; i < aps.size(); i++) {
            Object ao = aps.get(i);
            if (!(ao instanceof Map) && !(ao instanceof List)) {
                ignored.add(ign(i, "not an object"));
                continue;
            }
            if (ao instanceof List) {
                ignored.add(ign(i, "signer is not a member"));
                continue;
            }
            Map<String, Object> a = IntentOmega.obj(ao);
            Object signer = a.get("signer");
            if (!mem.contains(signer)) { ignored.add(ign(i, "signer is not a member")); continue; }
            if (counted.contains(signer)) { ignored.add(ign(i, "second approval from the same member")); continue; }
            Map<String, Object> st = statementOf(a);
            boolean same = true;
            for (String k : STATEMENT_KEYS) {
                Object x = st.containsKey(k) ? st.get(k) : null;
                Object y = want.containsKey(k) ? want.get(k) : null;
                boolean xd = st.containsKey(k), yd = want.containsKey(k);
                if (xd != yd || (xd && !strictEq(x, y))) same = false;
            }
            same = same && strictEq(a.get("v"), new Json.Num("1")) && "pca-intent-layer-approval".equals(a.get("kind"));
            if (!same) { ignored.add(ign(i, "approval is for another (layer, session, seq, map_digest, prev)")); continue; }
            boolean ok;
            try {
                ok = IntentBridge.verifyEd(signer, approvalMessage(st), a.get("sig"));
            } catch (RuntimeException e) {
                ok = false;
            }
            if (!ok) { ignored.add(ign(i, "bad signature")); continue; }
            counted.add((String) signer);
        }
        List<String> signers = new ArrayList<>();
        boolean[] ins = new boolean[mem.size()];
        for (int i = 0; i < mem.size(); i++) {
            ins[i] = counted.contains(mem.get(i));
            if (ins[i]) signers.add(mem.get(i));
        }
        return quorumResult(IntentMulti.ruleAdmits(n, ins), signers, ignored);
    }
}
