package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * Proof of progress against the reference corpus (ref-progress, 723 cases, 23 functions): potentials and the registry, goal commitments, step and
 * trajectory digests and anchors, signed state attestations and the attested source, the tracker, step and trajectory verification, signed steps.
 * The legacy option that accepts an unbound post-quantum key is not offered: the cases the reference accepts only through it are asserted refused.
 */
class ProgressRefDiffTest {
    static final String MODULE = "ref-progress";
    static final int TOTAL = 723;
    /** The corpus cases of verifyStateAttestation that the reference accepts only through allowUnboundPq. */
    static final int UNBOUND_ONLY = 2;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

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

    private static double dbl(Object o) { Double d = IntentJs.num(o); return d == null ? Double.NaN : d; }

    private static Map<String, Object> err(Throwable e) { Map<String, Object> r = new LinkedHashMap<>(); r.put("$err", e.getMessage()); return r; }

    /** A refusal that carries the reference's denial code, compared where the corpus has one. */
    static final class Coded extends RuntimeException implements OracleCases.Coded {
        private static final long serialVersionUID = 1L;
        private final String code;
        Coded(String code, String msg) { super(msg); this.code = code; }
        @Override public String code() { return code; }
    }

    // ---- the host objects of the specs ----

    private static Progress.Potential kind(String k) {
        switch (k) {
            case "l1-feature-v1": return Progress.L1_FEATURE;
            case "dag-remaining-v1": return Progress.DAG_REMAINING;
            case "dag-weighted-v1": return Progress.DAG_WEIGHTED;
            case "v": return (o, s) -> s instanceof Map ? ((Map<?, ?>) s).get("v") : null;
            case "throws": return (o, s) -> { throw new RuntimeException("potential boom"); };
            case "negative": return (o, s) -> -1L;
            case "frac": return (o, s) -> 0.5;
            case "nan": return (o, s) -> Double.NaN;
            case "big": return (o, s) -> 9007199254740992d;
            default:
                if (k.startsWith("const:")) { double c = Double.parseDouble(k.substring(6)); return (o, s) -> c; }
                throw new IllegalArgumentException("bad potential kind " + k);
        }
    }

    private static Object registry(Object sO) {
        Map<String, Object> s = m(sO);
        if (s == null) return null;
        if ("record".equals(s.get("mode"))) {
            Map<String, Object> rec = new LinkedHashMap<>();
            for (Object p : l(s.get("potentials"))) {
                List<Object> e = l(p);
                rec.put((String) e.get(0), e.size() > 2 ? new Progress.PotentialSpec(kind((String) e.get(1)), (String) e.get(2)) : kind((String) e.get(1)));
            }
            return rec;
        }
        Progress.PotentialRegistry r = new Progress.PotentialRegistry();
        for (Object p : l(s.get("potentials"))) {
            List<Object> e = l(p);
            if (e.size() > 2) r.register(e.get(0), kind((String) e.get(1)), e.get(2)); else r.register(e.get(0), kind((String) e.get(1)));
        }
        return r;
    }

    private static Progress.StepGuard guard(Object gO) {
        if (!(gO instanceof String)) return null;
        String g = (String) gO;
        switch (g) {
            case "allow": return t -> true;
            case "deny": return t -> false;
            case "throws": return t -> { throw new RuntimeException("guard boom"); };
            case "truthy": return t -> "yes";
            default:
        }
        if (g.startsWith("action:")) return t -> !g.substring(7).equals(t.get("action_digest"));
        double n = Double.parseDouble(g.substring(g.indexOf(':') + 1));
        if (g.startsWith("seq:")) return t -> dbl(t.get("seq")) != n;
        if (g.startsWith("after-v:")) return t -> !(dbl(t.get("after") instanceof Map ? ((Map<?, ?>) t.get("after")).get("v") : null) == n);
        throw new IllegalArgumentException("bad guard " + g);
    }

    @SuppressWarnings("unchecked")
    private static Progress.StateAttestationVerifier attestation(Object aO) {
        if (aO == null) return null;
        if ("allow".equals(aO)) return s -> true;
        if ("deny".equals(aO)) return s -> false;
        if ("throws".equals(aO)) return s -> { throw new RuntimeException("att boom"); };
        if ("truthy".equals(aO)) return s -> "yes";
        return Progress.attestedStateVerifier((Map<String, Object>) m(aO).get("attested"));
    }

    private static Progress.Options options(Object oO) {
        Progress.Options o = new Progress.Options();
        Map<String, Object> j = m(oO);
        if (j == null) return o;
        if (j.get("expectedSeq") != null) o.expectedSeq = dbl(j.get("expectedSeq"));
        o.expectedPrev = (String) j.get("expectedPrev");
        o.expectedActionDigest = (String) j.get("expectedActionDigest");
        o.expectedBeforeDigest = (String) j.get("expectedBeforeDigest");
        o.expectedAfterDigest = (String) j.get("expectedAfterDigest");
        if (j.containsKey("registry")) o.registry = registry(j.get("registry"));
        if (j.containsKey("guard")) o.guard = guard(j.get("guard"));
        if (j.get("trustedStateSources") != null) o.trustedStateSources = l(j.get("trustedStateSources"));
        if (j.get("requireAttestedState") instanceof Boolean) o.requireAttestedState = (Boolean) j.get("requireAttestedState");
        if (j.containsKey("attestation")) o.attestation = attestation(j.get("attestation"));
        o.hasInitial = j.containsKey("initial");
        o.initial = j.get("initial");
        o.initialDigest = j.get("initialDigest");
        if (j.get("expectedActionDigests") != null) o.expectedActionDigests = l(j.get("expectedActionDigests"));
        o.expectedHolder = (String) j.get("expectedHolder");
        return o;
    }

    /** A source of the specs: the observed world moves with {@link #set}. */
    private static final class Src implements Progress.StateSource {
        final Progress.StateSource inner;
        final Progress.AttestedStateSource attested;
        final Progress.InMemoryStateSource mem;
        final Object[] world;
        final String kind;

        Src(Map<String, Object> s) {
            kind = (String) s.get("kind");
            Object initial = s.get("initial");
            world = new Object[] {Json.parseLenient(Json.canonicalize(initial))};
            if ("attested".equals(kind)) {
                Pq.SignerSuiteOpts suite = null;
                if (Zk.truthy(s.get("alg"))) { suite = new Pq.SignerSuiteOpts(); suite.alg = (String) s.get("alg"); }
                attested = new Progress.AttestedStateSource((String) s.get("id"), Base64.getUrlDecoder().decode((String) s.get("signerSecret")), req -> world[0], suite);
                mem = null;
                inner = attested;
            } else {
                attested = null;
                mem = new Progress.InMemoryStateSource(initial, (String) s.get("id"));
                inner = mem;
            }
        }

        void set(Object next) {
            if (attested != null) world[0] = Json.parseLenient(Json.canonicalize(next)); else mem.apply(next);
        }

        @Override public String id() { return inner.id(); }

        @Override public Map<String, Object> observe(Map<String, Object> req) throws Exception {
            switch (kind) {
                case "throws": throw new RuntimeException("source boom");
                case "null": return null;
                default:
            }
            Map<String, Object> ob = inner.observe(req);
            if (kind.equals("liar-digest")) { ob = new LinkedHashMap<>(ob); ob.put("state_digest", "x".repeat(43)); }
            if (kind.equals("liar-source")) { ob = new LinkedHashMap<>(ob); ob.put("source", "someone-else"); }
            return ob;
        }
    }

    private static Object tracker(List<?> x) {
        Object goal = x.get(0);
        String commitment = x.get(1) != null ? (String) x.get(1) : Progress.goalDigest(goal);
        List<Src> srcs = new ArrayList<>();
        for (Object s : l(x.get(5))) srcs.add(new Src(m(s)));
        Progress.ProgressTracker t;
        try {
            t = new Progress.ProgressTracker(goal, commitment, x.get(2), registry(x.get(3)), guard(x.get(4)));
        } catch (Progress.ProgressError e) {
            throw new Coded(e.code, e.getMessage());
        }
        List<Object> out = new ArrayList<>();
        for (Object o : l(x.get(6))) {
            List<Object> op = l(o);
            try {
                switch ((String) op.get(0)) {
                    case "step": out.add(t.step(op.get(1), op.get(2))); break;
                    case "stepObserved": out.add(t.stepObserved(srcs.get((int) dbl(op.get(1))), op.get(2))); break;
                    case "apply": srcs.get((int) dbl(op.get(1))).set(op.get(2)); out.add(null); break;
                    case "steps": out.add(t.steps()); break;
                    case "state": out.add(t.state()); break;
                    case "currentStateDigest": out.add(t.currentStateDigest()); break;
                    case "spent": out.add((long) t.spent()); break;
                    case "remaining": out.add((long) t.remaining()); break;
                    case "reached": out.add(t.reached()); break;
                    default: throw new IllegalArgumentException("bad op");
                }
            } catch (RuntimeException e) {
                out.add(err(e));
            }
        }
        return out;
    }

    private static List<Object> registryOps(List<Object> ops) {
        Progress.PotentialRegistry r = null;
        List<Object> out = new ArrayList<>();
        for (Object o : ops) {
            List<Object> op = l(o);
            try {
                switch ((String) op.get(0)) {
                    case "new": r = new Progress.PotentialRegistry(); out.add(null); break;
                    case "defaults": r = Progress.PotentialRegistry.defaults(); out.add(null); break;
                    case "default-frozen": r = Progress.DEFAULT_POTENTIALS; out.add(null); break;
                    case "from": {
                        Map<String, Object> rec = new LinkedHashMap<>();
                        for (Map.Entry<String, Object> e : m(op.get(1)).entrySet()) {
                            Object v = e.getValue();
                            rec.put(e.getKey(), v instanceof String ? kind((String) v) : new Progress.PotentialSpec(kind((String) m(v).get("fn")), (String) m(v).get("embedder")));
                        }
                        r = Progress.PotentialRegistry.from(rec);
                        out.add(null);
                        break;
                    }
                    case "register":
                        if (op.size() > 3) r.register(op.get(1), kind((String) op.get(2)), op.get(3)); else r.register(op.get(1), kind((String) op.get(2)));
                        out.add(null);
                        break;
                    case "get": {
                        Progress.PotentialSpec s = r.get(op.get(1));
                        Map<String, Object> g = null;
                        if (s != null) { g = new LinkedHashMap<>(); g.put("embedder", s.embedder); }
                        out.add(g);
                        break;
                    }
                    case "has": out.add(r.has(op.get(1))); break;
                    case "ids": out.add(new ArrayList<Object>(r.ids())); break;
                    case "freeze": r.freeze(); out.add(null); break;
                    default: throw new IllegalArgumentException("bad op");
                }
            } catch (RuntimeException e) {
                out.add(err(e));
            }
        }
        return out;
    }

    private static Object attestedSource(List<?> x) throws Exception {
        Src s = new Src(m(x.get(0)));
        List<Object> observations = new ArrayList<>();
        for (Object r : l(x.get(1))) {
            try {
                observations.add(s.observe(m(r)));
            } catch (RuntimeException e) {
                observations.add(err(e));
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("observations", observations);
        out.put("attestations", s.attested == null ? null : new ArrayList<Object>(s.attested.attestations()));
        return out;
    }

    private static Object anchor(List<?> x) {
        MerkleLog ledger = new MerkleLog();
        for (Object c : l(x.get(2))) ledger.appendCommitment((String) c);
        return Progress.anchorTrajectoryHead(ledger, l(x.get(0)), (String) x.get(1));
    }

    private static Object sign(List<?> x) {
        String sk = (String) m(x.get(1)).get("$bytes");
        return Progress.signProgressStep(x.get(0), Base64.getUrlDecoder().decode(sk), (String) x.get(2));
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("PROGRESS_VERSION", Progress.PROGRESS_VERSION);
            out.put("PROGRESS_SIG_DOMAIN", Progress.PROGRESS_SIG_DOMAIN);
            out.put("TRAJECTORY_ANCHOR_DOMAIN", Progress.TRAJECTORY_ANCHOR_DOMAIN);
            out.put("STATE_ATTESTATION_DOMAIN", Progress.STATE_ATTESTATION_DOMAIN);
            return out;
        });
        f.put("l1FeaturePotential", x -> Progress.L1_FEATURE.apply(x.get(0), x.get(1)));
        f.put("dagRemainingPotential", x -> Progress.DAG_REMAINING.apply(x.get(0), x.get(1)));
        f.put("dagWeightedPotential", x -> Progress.DAG_WEIGHTED.apply(x.get(0), x.get(1)));
        f.put("registryOps", x -> registryOps(l(x.get(0))));
        f.put("goalDigest", x -> Progress.goalDigest(x.get(0)));
        f.put("commitGoal", x -> Progress.commitGoal(x.get(0)));
        f.put("verifyGoalCommitment", x -> Progress.verifyGoalCommitment(x.get(0), x.get(1)));
        f.put("stateDigest", x -> Progress.stateDigest(x.get(0)));
        f.put("trajectoryHead", x -> Progress.trajectoryHead(l(x.get(0))));
        f.put("progressStepDigest", x -> Progress.progressStepDigest(x.get(0)));
        f.put("trajectoryAnchorCommit", x -> Progress.trajectoryAnchorCommit(x.get(0), x.get(1)));
        f.put("verifyTrajectoryAnchor", x -> Progress.verifyTrajectoryAnchor(x.get(0), x.get(1), x.get(2)));
        f.put("anchorTrajectoryHead", ProgressRefDiffTest::anchor);
        f.put("attestedStateVerifier", x -> Boolean.TRUE.equals(Progress.attestedStateVerifier(m(x.get(0))).verify(m(x.get(1)))));
        f.put("attestedSource", ProgressRefDiffTest::attestedSource);
        f.put("tracker", ProgressRefDiffTest::tracker);
        f.put("verifyProgressStep", x -> Progress.verifyProgressStep(x.get(0), x.get(1), x.get(2), options(x.get(3))));
        f.put("verifyTrajectory", x -> Progress.verifyTrajectory(x.get(0), x.get(1), x.get(2), options(x.get(3))));
        f.put("verifySignedProgressStep", x -> Progress.verifySignedProgressStep(x.get(0), x.get(1), x.get(2), options(x.get(3))));
        f.put("verifySignedTrajectory", x -> Progress.verifySignedTrajectory(x.get(0), x.get(1), x.get(2), options(x.get(3))));
        f.put("signProgressStep", ProgressRefDiffTest::sign);

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        Set<String> want = new TreeSet<>(f.keySet());
        want.add("verifyStateAttestation");
        assertEquals(want, fns);
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) OracleCases.each(MODULE, e.getKey(), x -> e.getValue().apply((List<?>) nums(x)));
    }

    /** verifyStateAttestation: the reference's allowUnboundPq cases are refused here (that option is not offered); every other case matches. */
    @Test void stateAttestation() throws Exception {
        int unbound = 0;
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : OracleCases.of(MODULE, "verifyStateAttestation")) {
            List<Object> a = l(c.get("args"));
            Map<String, Object> pin = m(a.get(2));
            // the option only matters to a post-quantum suite: an ed25519 attestation verifies under the trusted key either way
            boolean viaUnbound = pin != null && Boolean.TRUE.equals(pin.get("allowUnboundPq")) && a.get(0) instanceof Map && m(a.get(0)).get("alg") != null && !"ed25519".equals(m(a.get(0)).get("alg"));
            boolean want = Boolean.TRUE.equals(c.get("out"));
            boolean got = Progress.verifyStateAttestation(a.get(0), a.get(1), pin);
            if (viaUnbound && want) { unbound++; want = false; }
            if (got != want) bad.add(c.get("name") + " want " + want + " got " + got);
        }
        assertEquals(List.of(), bad);
        assertEquals(UNBOUND_ONLY, unbound);
    }
}
