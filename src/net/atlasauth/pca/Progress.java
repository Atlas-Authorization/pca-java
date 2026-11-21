package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * Proof of progress toward a committed goal (the reference's progress module). A goal (objective, potential id, embedder, metric, epsilon,
 * exploration budget) is hashed into a commitment; each step is a hash-chained body binding the goal, the action digest, the before and after state
 * digests, the sequence number and the previous step; the verifier recomputes the integer potential and the mode (progress, or exploration charged to
 * the committed budget). Steps can be Ed25519-signed by the holder, post-states can carry a state source's signed attestation, and the trajectory head
 * can be anchored in the transparency log.
 *
 * <p>States, goals, steps and results are JSON trees; digests are the STRICT canonical hashes (the protocol form). Every verifier is total: a
 * fault is a denial code, never an exception.
 */
public final class Progress {
    private Progress() {}

    public static final long PROGRESS_VERSION = 2;
    public static final String PROGRESS_SIG_DOMAIN = "atlas-pca/progress-step/v2";
    public static final String TRAJECTORY_ANCHOR_DOMAIN = "atlas-pca/trajectory-anchor/v1";
    public static final String STATE_ATTESTATION_DOMAIN = "atlas-pca/progress-state-attestation/v1\u0000";
    private static final String GENESIS = "genesis";
    private static final double MAX_SAFE = 9007199254740991d;

    // ---- helpers ------------------------------------------------------------------------------------------------------------

    private static Map<String, Object> obj(Object... kv) { return Issue.obj(kv); }

    private static Object get(Object m, String k) { return m instanceof Map ? ((Map<?, ?>) m).get(k) : null; }

    private static boolean has(Object m, String k) { return m instanceof Map && ((Map<?, ?>) m).containsKey(k); }

    private static boolean isObj(Object o) { return o instanceof Map; }

    private static boolean isStr(Object o) { return o instanceof String; }

    private static boolean isSafe(Object o) { return IntentJs.isSafeInteger(o); }

    private static double num(Object o) { Double d = IntentJs.num(o); return d == null ? Double.NaN : d; }

    private static void assertInt(Object n, String what) {
        if (!isSafe(n)) throw new IllegalArgumentException(what + ": safe integer required");
    }

    private static String hash(Object v) { return Pca.hashCanonical(v); }

    /** A deep copy through the lenient canonical form (a value without a stable encoding throws). */
    private static Object snapshot(Object v) { return Json.parseLenient(Json.canonicalize(v)); }

    /** A JavaScript Set key: equal for the values SameValueZero treats as equal (objects by identity). */
    private static Object sv(Object o) {
        Double d = IntentJs.num(o);
        if (d != null) return "n:" + (d == 0 ? 0.0 : d);
        if (o instanceof String) return "s:" + o;
        if (o == null || o instanceof Boolean) return o;
        return o;
    }

    /** A progress fault carrying its denial code. */
    public static final class ProgressError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public final String code;
        public ProgressError(String code, String msg) { super(msg); this.code = code; }
    }

    // ---- potentials ---------------------------------------------------------------------------------------------------------

    /** A potential: a non-negative safe integer measuring what remains of the objective in a state. May throw. */
    @FunctionalInterface public interface Potential {
        Object apply(Object objective, Object state);
    }

    public static final class PotentialSpec {
        public final Potential fn;
        public final String embedder;
        public PotentialSpec(Potential fn, String embedder) { this.fn = fn; this.embedder = embedder; }
    }

    /** {@code sum |target - x|} over safe-integer features. */
    public static final Potential L1_FEATURE = (objective, state) -> {
        Object t = get(objective, "target"), x = get(state, "x");
        if (!(t instanceof List) || !(x instanceof List) || ((List<?>) t).size() != ((List<?>) x).size()) throw new IllegalArgumentException("l1-feature-v1: bad shape");
        double d = 0;
        for (int i = 0; i < ((List<?>) t).size(); i++) {
            Object a = ((List<?>) t).get(i), b = ((List<?>) x).get(i);
            assertInt(a, "target");
            assertInt(b, "x");
            d += Math.abs(num(a) - num(b));
            assertInt(d, "distance");
        }
        return (long) d;
    };

    /** The summed cost of the tasks not yet done. */
    public static final Potential DAG_REMAINING = (objective, state) -> {
        Object tasks = get(objective, "tasks"), done = get(state, "done");
        if (!(tasks instanceof List) || !(done instanceof List)) throw new IllegalArgumentException("dag-remaining-v1: bad shape");
        Set<Object> ids = new HashSet<>();
        for (Object t : (List<?>) tasks) {
            if (t == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'id')");
            ids.add(sv(get(t, "id")));
        }
        if (ids.size() != ((List<?>) tasks).size()) throw new IllegalArgumentException("dag-remaining-v1: duplicate task id");
        Set<Object> doneSet = new HashSet<>();
        for (Object d : (List<?>) done) doneSet.add(sv(d));
        for (Object d : (List<?>) done) if (!ids.contains(sv(d))) throw new IllegalArgumentException("dag-remaining-v1: unknown task " + IntentRevocation.jsText(d, true));
        double rem = 0;
        for (Object t : (List<?>) tasks) {
            assertInt(get(t, "cost"), "cost");
            if (num(get(t, "cost")) < 0) throw new IllegalArgumentException("negative cost");
            if (!doneSet.contains(sv(get(t, "id")))) rem += num(get(t, "cost"));
            assertInt(rem, "remaining");
        }
        return (long) rem;
    };

    /** The summed cost of the tasks not yet done in a dependency DAG; a task done before its dependencies, a cycle or an unknown dependency throws. */
    public static final Potential DAG_WEIGHTED = (objective, state) -> {
        Object tasks = get(objective, "tasks"), done = get(state, "done");
        if (!(tasks instanceof List) || !(done instanceof List)) throw new IllegalArgumentException("dag-weighted-v1: bad shape");
        Map<String, double[]> cost = new LinkedHashMap<>();
        Map<String, List<String>> deps = new LinkedHashMap<>();
        for (Object t : (List<?>) tasks) {
            if (!isObj(t) || !isStr(get(t, "id")) || ((String) get(t, "id")).isEmpty()) throw new IllegalArgumentException("dag-weighted-v1: bad task");
            String id = (String) get(t, "id");
            if (cost.containsKey(id)) throw new IllegalArgumentException("dag-weighted-v1: duplicate task id");
            assertInt(get(t, "cost"), "cost");
            if (num(get(t, "cost")) < 0) throw new IllegalArgumentException("negative cost");
            Object dd = get(t, "deps") == null ? new ArrayList<Object>() : get(t, "deps");
            if (!(dd instanceof List)) throw new IllegalArgumentException("dag-weighted-v1: bad deps");
            List<String> dl = new ArrayList<>();
            for (Object x : (List<?>) dd) {
                if (!isStr(x)) throw new IllegalArgumentException("dag-weighted-v1: bad deps");
                dl.add((String) x);
            }
            cost.put(id, new double[] {num(get(t, "cost"))});
            deps.put(id, dl);
        }
        Map<String, Integer> indeg = new LinkedHashMap<>();
        Map<String, List<String>> rev = new HashMap<>();
        for (Map.Entry<String, List<String>> e : deps.entrySet()) {
            Set<String> uniq = new java.util.LinkedHashSet<>(e.getValue());
            indeg.put(e.getKey(), uniq.size());
            for (String d : uniq) {
                if (d.equals(e.getKey()) || !cost.containsKey(d)) throw new IllegalArgumentException("dag-weighted-v1: bad dependency " + d);
                rev.computeIfAbsent(d, k -> new ArrayList<>()).add(e.getKey());
            }
        }
        List<String> q = new ArrayList<>();
        for (Map.Entry<String, Integer> e : indeg.entrySet()) if (e.getValue() == 0) q.add(e.getKey());
        int seen = 0;
        while (!q.isEmpty()) {
            String id = q.remove(q.size() - 1);
            seen++;
            for (String n : rev.getOrDefault(id, List.of())) {
                int k = indeg.get(n) - 1;
                indeg.put(n, k);
                if (k == 0) q.add(n);
            }
        }
        if (seen != cost.size()) throw new IllegalArgumentException("dag-weighted-v1: cycle");
        Set<String> doneSet = new HashSet<>();
        for (Object d : (List<?>) done) {
            if (!isStr(d) || !cost.containsKey(d)) throw new IllegalArgumentException("dag-weighted-v1: unknown task " + IntentRevocation.jsText(d, true));
            if (!doneSet.add((String) d)) throw new IllegalArgumentException("dag-weighted-v1: duplicate done");
        }
        for (String d : doneSet) for (String dep : deps.get(d)) if (!doneSet.contains(dep)) throw new IllegalArgumentException("dag-weighted-v1: " + d + " done before dependency " + dep);
        double rem = 0;
        for (Map.Entry<String, double[]> e : cost.entrySet()) {
            if (!doneSet.contains(e.getKey())) rem += e.getValue()[0];
            assertInt(rem, "remaining");
        }
        return (long) rem;
    };

    /** The potential registry a goal names its potential in; frozen once committed. */
    public static final class PotentialRegistry {
        private final Map<String, PotentialSpec> m = new HashMap<>();
        private boolean frozen = false;

        /** Registers {@code fn} under {@code id} (1..128 characters, not yet registered) with the embedder it was calibrated for ('' when none). */
        public PotentialRegistry register(Object id, Potential fn, Object embedder) {
            if (frozen) throw new IllegalStateException("registry is frozen");
            if (!isStr(id) || ((String) id).isEmpty() || ((String) id).length() > 128) throw new IllegalArgumentException("potential id: 1..128 chars");
            if (fn == null) throw new IllegalArgumentException("potential must be a function");
            if (!isStr(embedder)) throw new IllegalArgumentException("embedder must be a string");
            if (m.containsKey(id)) throw new IllegalStateException("potential " + id + " already registered");
            m.put((String) id, new PotentialSpec(fn, (String) embedder));
            return this;
        }

        public PotentialRegistry register(Object id, Potential fn) { return register(id, fn, ""); }

        public PotentialSpec get(Object id) { return id instanceof String ? m.get(id) : null; }

        public boolean has(Object id) { return id instanceof String && m.containsKey(id); }

        /** The ids in UTF-16 code unit order. */
        public List<String> ids() {
            List<String> l = new ArrayList<>(m.keySet());
            l.sort(String::compareTo);
            return l;
        }

        public PotentialRegistry freeze() { frozen = true; return this; }

        /** From a record of id to a {@link Potential} or a {@link PotentialSpec}. */
        public static PotentialRegistry from(Map<String, Object> rec) {
            PotentialRegistry r = new PotentialRegistry();
            for (Map.Entry<String, Object> e : rec.entrySet()) {
                Object v = e.getValue();
                if (v instanceof Potential) r.register(e.getKey(), (Potential) v);
                else r.register(e.getKey(), ((PotentialSpec) v).fn, ((PotentialSpec) v).embedder == null ? "" : ((PotentialSpec) v).embedder);
            }
            return r;
        }

        /** A mutable registry holding the three built-in potentials. */
        public static PotentialRegistry defaults() {
            return new PotentialRegistry().register("l1-feature-v1", L1_FEATURE).register("dag-remaining-v1", DAG_REMAINING).register("dag-weighted-v1", DAG_WEIGHTED);
        }
    }

    public static final PotentialRegistry DEFAULT_POTENTIALS = PotentialRegistry.defaults().freeze();

    @SuppressWarnings("unchecked")
    private static PotentialRegistry toRegistry(Object r) {
        if (r == null) return DEFAULT_POTENTIALS;
        return r instanceof PotentialRegistry ? (PotentialRegistry) r : PotentialRegistry.from((Map<String, Object>) r);
    }

    // ---- goal commitment ----------------------------------------------------------------------------------------------------------

    private static void validateGoal(Object goal) {
        if (!isObj(goal)) throw new IllegalArgumentException("goal must be an object");
        assertInt(get(goal, "epsilon"), "epsilon");
        assertInt(get(goal, "explorationBudget"), "explorationBudget");
        if (num(get(goal, "epsilon")) < 1) throw new IllegalArgumentException("epsilon must be >= 1");
        if (num(get(goal, "explorationBudget")) < 0) throw new IllegalArgumentException("explorationBudget must be >= 0");
        if (!isStr(get(goal, "potential")) || ((String) get(goal, "potential")).isEmpty()) throw new IllegalArgumentException("potential id required");
        if (!isStr(get(goal, "metric"))) throw new IllegalArgumentException("metric must be a string");
        if (has(goal, "embedder") && !isStr(get(goal, "embedder"))) throw new IllegalArgumentException("embedder must be a string");
    }

    private static Object embedderOf(Object goal) { return get(goal, "embedder") == null ? "" : get(goal, "embedder"); }

    /** The commitment of a goal: a strict canonical hash over every committed member. */
    public static String goalDigest(Object goal) {
        validateGoal(goal);
        if (!has(goal, "objective")) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
        return hash(obj("t", "pca-goal", "v", PROGRESS_VERSION, "objective", get(goal, "objective"), "potential", get(goal, "potential"), "embedder", embedderOf(goal),
            "metric", get(goal, "metric"), "epsilon", get(goal, "epsilon"), "explorationBudget", get(goal, "explorationBudget")));
    }

    /** {@code {goal (a snapshot), commitment}}. */
    public static Map<String, Object> commitGoal(Object goal) {
        String c = goalDigest(goal);
        return obj("goal", snapshot(goal), "commitment", c);
    }

    public static boolean verifyGoalCommitment(Object goal, Object commitment) {
        try {
            return commitment instanceof String && goalDigest(goal).equals(commitment);
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ---- step digests, anchors ------------------------------------------------------------------------------------------------------

    private static String stepBodyDigest(Map<String, Object> body) {
        Map<String, Object> m = obj("t", "pca-progress-step", "v", PROGRESS_VERSION);
        m.putAll(body);
        return hash(m);
    }

    public static String stateDigest(Object state) { return hash(obj("t", "pca-state", "state", state)); }

    public static String trajectoryHead(List<?> steps) { return steps.isEmpty() ? GENESIS : (String) get(steps.get(steps.size() - 1), "digest"); }

    public static String progressStepDigest(Object step) {
        if (step == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'digest')");
        return (String) get(step, "digest");
    }

    public static String trajectoryAnchorCommit(Object salt, Object head) {
        if (!isStr(salt) || ((String) salt).isEmpty() || !isStr(head) || ((String) head).isEmpty()) throw new IllegalArgumentException("trajectoryAnchorCommit: salt and head must be non-empty strings");
        return hash(obj("t", TRAJECTORY_ANCHOR_DOMAIN, "salt", salt, "head", head));
    }

    public static boolean verifyTrajectoryAnchor(Object commit, Object salt, Object head) {
        try {
            return commit instanceof String && trajectoryAnchorCommit(salt, head).equals(commit);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Appends a salted commitment to the head to the log: {@code {head, salt, commit, index, ledgerHead}}; a null salt draws a random one. */
    public static Map<String, Object> anchorTrajectoryHead(MerkleLog ledger, List<?> steps, String salt) {
        String head = trajectoryHead(steps);
        String s = salt != null ? salt : Issue.randomB64u(16);
        String commit = trajectoryAnchorCommit(s, head);
        int index = ledger.appendCommitment(commit);
        return obj("head", head, "salt", s, "commit", commit, "index", (long) index, "ledgerHead", ledger.head());
    }

    // ---- verification options and hooks ---------------------------------------------------------------------------------------------

    /** A guard over a transition {@code {seq, before, after, action_digest}}: only the boolean true allows. */
    @FunctionalInterface public interface StepGuard {
        Object allows(Map<String, Object> transition);
    }

    /** The attestation hook: only the boolean true accepts the step's post-state. */
    @FunctionalInterface public interface StateAttestationVerifier {
        Object verify(Map<String, Object> step);
    }

    private static boolean runGuard(StepGuard g, Map<String, Object> t) {
        try {
            return Boolean.TRUE.equals(g.allows(t));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** The options of {@link #verifyProgressStep}, {@link #verifyTrajectory} and the signed verifiers (null fields are absent). */
    public static final class Options {
        public Double expectedSeq;
        public String expectedPrev, expectedActionDigest, expectedBeforeDigest, expectedAfterDigest;
        /** A {@link PotentialRegistry} or a record of id to {@link Potential} / {@link PotentialSpec}; null = the default frozen registry. */
        public Object registry;
        public StepGuard guard;
        public List<?> trustedStateSources;
        /** Only the boolean false lifts the requirement of an attested state source. */
        public Boolean requireAttestedState;
        public StateAttestationVerifier attestation;
        /** Trajectory: the initial state (when {@link #hasInitial}) or its digest. */
        public boolean hasInitial;
        public Object initial;
        public Object initialDigest;
        public List<?> expectedActionDigests;
        /** Signed steps: the holder the signatures must name. */
        public String expectedHolder;

        Options copy() {
            Options o = new Options();
            o.expectedSeq = expectedSeq; o.expectedPrev = expectedPrev; o.expectedActionDigest = expectedActionDigest;
            o.expectedBeforeDigest = expectedBeforeDigest; o.expectedAfterDigest = expectedAfterDigest; o.registry = registry; o.guard = guard;
            o.trustedStateSources = trustedStateSources; o.requireAttestedState = requireAttestedState; o.attestation = attestation;
            o.hasInitial = hasInitial; o.initial = initial; o.initialDigest = initialDigest; o.expectedActionDigests = expectedActionDigests; o.expectedHolder = expectedHolder;
            return o;
        }
    }

    private static Map<String, Object> fail(String reason) { return obj("ok", false, "reason", reason); }

    private static boolean isStep(Object s) {
        if (!isObj(s)) return false;
        return isStr(get(s, "goal_commitment")) && isSafe(get(s, "seq")) && num(get(s, "seq")) >= 0 && isStr(get(s, "before_digest")) && isStr(get(s, "after_digest"))
            && isStr(get(s, "action_digest")) && ("progress".equals(get(s, "mode")) || "exploration".equals(get(s, "mode")))
            && isSafe(get(s, "potential_before")) && isSafe(get(s, "potential_after")) && isSafe(get(s, "charge")) && isStr(get(s, "state_source"))
            && isStr(get(s, "evidence_digest")) && isStr(get(s, "prev")) && isStr(get(s, "digest")) && has(s, "before") && has(s, "after");
    }

    // ---- the potential and its classification -----------------------------------------------------------------------------------------

    private static PotentialSpec resolve(Object goal, PotentialRegistry reg) {
        PotentialSpec spec = reg.get(get(goal, "potential"));
        if (spec == null) throw new ProgressError("unknown-potential", "unknown potential " + IntentRevocation.jsText(get(goal, "potential"), true));
        if (!(spec.embedder == null ? "" : spec.embedder).equals(embedderOf(goal))) throw new ProgressError("embedder-mismatch", "embedder mismatch");
        return spec;
    }

    private static double potentialOf(Object goal, PotentialRegistry reg, Object state) {
        PotentialSpec spec = resolve(goal, reg);
        Object p;
        try {
            p = spec.fn.apply(get(goal, "objective"), state);
            assertInt(p, "potential");
        } catch (RuntimeException e) {
            throw new ProgressError("bad-potential", e.getMessage());
        }
        if (num(p) < 0) throw new ProgressError("bad-potential", "potential must be >= 0");
        return num(p);
    }

    private static String denialOf(RuntimeException e) { return e instanceof ProgressError ? ((ProgressError) e).code : "bad-potential"; }

    private static final class Cls {
        final String mode;
        final double charge;
        Cls(String mode, double charge) { this.mode = mode; this.charge = charge; }
    }

    private static Cls classify(double pb, double pa, double epsilon) {
        double required = pb - epsilon;
        if (pa <= required || (pa == 0 && pb > 0)) return new Cls("progress", 0);
        double charge = pa - required;
        try {
            assertInt(charge, "charge");
        } catch (RuntimeException e) {
            throw new ProgressError("bad-potential", e.getMessage());
        }
        return new Cls("exploration", charge);
    }

    // ---- state sources and attestations --------------------------------------------------------------------------------------------------

    /** What a state source reports: {@code {state, state_digest, source, evidence?}}. */
    public interface StateSource {
        String id();
        Map<String, Object> observe(Map<String, Object> request) throws Exception;
    }

    /** A source holding the world in memory (the reference implementation; self-reported unless wrapped in an attestation). */
    public static final class InMemoryStateSource implements StateSource {
        private Object cur;
        private long n = 0;
        private final String id;
        public final List<Map<String, Object>> requests = new ArrayList<>();

        public InMemoryStateSource(Object initial, String id) { this.cur = snapshot(initial); this.id = id == null ? "in-memory" : id; }

        public void apply(Object next) { cur = snapshot(next); }

        @Override public String id() { return id; }

        @Override public Map<String, Object> observe(Map<String, Object> req) {
            requests.add(req);
            Object state = snapshot(cur);
            return obj("state", state, "state_digest", stateDigest(state), "source", id,
                "evidence", obj("kind", "in-memory", "n", n++, "prior", req.get("prior_digest"), "action", req.get("action_digest")));
        }
    }

    private static byte[] attestationMessage(Map<String, Object> a, Object alg, boolean algPresent, Object pqPk, boolean pqPresent) {
        Map<String, Object> base = obj("source", a.get("source"), "goal_commitment", a.get("goal_commitment"), "action_digest", a.get("action_digest"),
            "prior_digest", a.get("prior_digest"), "state_digest", a.get("state_digest"));
        byte[] body = IntentJs.canonBytes(IntentJs.bindSuiteFields(base, alg, algPresent, pqPk, pqPresent));
        return Pca.concat(STATE_ATTESTATION_DOMAIN.getBytes(StandardCharsets.UTF_8), body);
    }

    /**
     * Verifies a state attestation under the source's trusted key. A post-quantum suite needs a pinned PQ key ({@code pin.pqPins}); the legacy
     * opt-out that accepts an unbound PQ key is not offered, so an attestation that only that option accepts is refused.
     */
    @SuppressWarnings("unchecked")
    public static boolean verifyStateAttestation(Object att, Object trustedPublicKey, Map<String, Object> pin) {
        try {
            if (!isStr(get(att, "sig")) || !isStr(get(att, "source"))) return false;
            if (!isStr(trustedPublicKey) || ((String) trustedPublicKey).isEmpty()) return false;
            Map<String, Object> a = (Map<String, Object>) att;
            boolean algPresent = a.containsKey("alg");
            if (!Pq.sigAlgKnown(a.get("alg"), algPresent)) return false;
            byte[] msg = attestationMessage(a, a.get("alg"), algPresent, a.get("pq_pk"), a.containsKey("pq_pk"));
            return IntentJs.verifyPinnedSuite(a.get("alg"), algPresent, (String) trustedPublicKey, a.get("pq_pk"), msg, a.get("sig"), a.get("pq_sig"),
                pin != null && get(pin, "pqPins") instanceof Map ? (Map<String, Object>) get(pin, "pqPins") : null);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** A source that signs what it observes: every observation carries a state attestation under the source's key. */
    public static final class AttestedStateSource implements StateSource {
        private final String id;
        public final String publicKey;
        private final byte[] secret;
        private final Function<Map<String, Object>, Object> observeState;
        private final Pq.SignerSuiteOpts suite;
        private final String pqPk;
        private final List<Map<String, Object>> attestations = new ArrayList<>();

        public AttestedStateSource(String id, byte[] signerSecret, Function<Map<String, Object>, Object> observeState, Pq.SignerSuiteOpts suite) {
            if (id == null || id.isEmpty()) throw new IllegalArgumentException("AttestedStateSource: id is required");
            if (signerSecret == null) throw new IllegalArgumentException("AttestedStateSource: signerSecret must be a Uint8Array");
            if (observeState == null) throw new IllegalArgumentException("AttestedStateSource: observeState must be a function");
            Object alg = suite == null ? null : suite.alg;
            if (!Pq.sigAlgKnown(alg, alg != null)) throw new IllegalArgumentException("AttestedStateSource: unknown signature alg '" + alg + "'");
            this.id = id;
            this.secret = signerSecret.clone();
            this.publicKey = Keys.edFromSeed(secret).id();
            this.observeState = observeState;
            this.suite = suite;
            this.pqPk = Pq.suitePqPublicKey(alg, suite);
        }

        public List<Map<String, Object>> attestations() { return new ArrayList<>(attestations); }

        @Override public String id() { return id; }

        @Override public Map<String, Object> observe(Map<String, Object> req) {
            Object state = snapshot(observeState.apply(req));
            String digest = stateDigest(state);
            Map<String, Object> stmt = obj("source", id, "goal_commitment", req.get("goal_commitment"), "action_digest", req.get("action_digest"),
                "prior_digest", req.get("prior_digest"), "state_digest", digest);
            Object alg = suite == null ? null : suite.alg;
            Pq.SuiteArtifactFields f = Pq.signSuiteArtifact(alg, Pq.suiteKeysOf(secret, suite), attestationMessage(stmt, alg, alg != null, pqPk, pqPk != null));
            Map<String, Object> att = new LinkedHashMap<>(stmt);
            att.put("sig", f.sig);
            if (f.alg != null) att.put("alg", f.alg);
            if (f.pqPk != null) att.put("pq_pk", f.pqPk);
            if (f.pqSig != null) att.put("pq_sig", f.pqSig);
            attestations.add(att);
            return obj("state", state, "state_digest", digest, "source", id, "evidence", att);
        }
    }

    private static String attestationKey(Object action, Object prior, Object state) { return action + "\u0000" + prior + "\u0000" + state; }

    /**
     * The attestation hook over a set of attestations ({@code {trustedKeys, pqPins?, attestations}}): a step passes only when its source is trusted, an
     * attestation for exactly this transition exists, the step's evidence digest is that attestation's and its signature verifies.
     */
    @SuppressWarnings("unchecked")
    public static StateAttestationVerifier attestedStateVerifier(Map<String, Object> opts) {
        Map<String, Map<String, Object>> byKey = new HashMap<>();
        Object atts = opts.get("attestations");
        if (atts instanceof List)
            for (Object a : (List<?>) atts)
                if (isStr(get(a, "action_digest")) && isStr(get(a, "prior_digest")) && isStr(get(a, "state_digest")))
                    byKey.put(attestationKey(get(a, "action_digest"), get(a, "prior_digest"), get(a, "state_digest")), (Map<String, Object>) a);
        return step -> {
            try {
                Object pub = get(opts.get("trustedKeys"), (String) step.get("state_source"));
                if (!isStr(pub) || ((String) pub).isEmpty()) return false;
                Map<String, Object> att = byKey.get(attestationKey(step.get("action_digest"), step.get("before_digest"), step.get("after_digest")));
                if (att == null || !java.util.Objects.equals(att.get("source"), step.get("state_source"))) return false;
                if (!hash(obj("t", "pca-evidence", "e", att)).equals(step.get("evidence_digest"))) return false;
                return verifyStateAttestation(att, pub, opts);
            } catch (RuntimeException e) {
                return false;
            }
        };
    }

    // ---- the tracker --------------------------------------------------------------------------------------------------------------------

    /** Builds and proves a trajectory one step at a time. */
    public static final class ProgressTracker {
        private long seq = 0;
        private String head = GENESIS;
        private double spentTotal = 0;
        private Object cur;
        private String curDigest;
        private final List<Object> log = new ArrayList<>();
        private final PotentialRegistry reg;
        private final StepGuard guard;
        public final Object goal;
        public final String commitment;

        public ProgressTracker(Object goal, String commitment, Object initial, Object registry, StepGuard guard) {
            if (!verifyGoalCommitment(goal, commitment)) throw new IllegalStateException("goal does not match commitment");
            this.commitment = commitment;
            this.goal = snapshot(goal);
            this.reg = toRegistry(registry);
            this.guard = guard;
            this.cur = snapshot(initial);
            this.curDigest = stateDigest(cur);
            potentialOf(this.goal, reg, cur); // fail fast: unknown id, embedder mismatch, bad initial state
        }

        public double spent() { return spentTotal; }

        public double remaining() { return num(get(goal, "explorationBudget")) - spentTotal; }

        public Object state() { return cur; }

        public String currentStateDigest() { return curDigest; }

        public boolean reached() { return potentialOf(goal, reg, cur) == 0; }

        public List<Object> steps() { return new ArrayList<>(log); }

        /** A self-reported step to {@code after}. */
        public Map<String, Object> step(Object after, Object actionDigest) { return advance(after, actionDigest, "", ""); }

        /** A step to the state a source observed (its identity and evidence enter the step). */
        public Map<String, Object> stepObserved(StateSource source, Object actionDigest) {
            try {
                Map<String, Object> obs = source.observe(obj("action_digest", actionDigest, "goal_commitment", commitment, "prior_digest", curDigest));
                if (obs == null || !source.id().equals(obs.get("source")) || !stateDigest(obs.get("state")).equals(obs.get("state_digest")))
                    return obj("ok", false, "reason", "state-source-mismatch", "stepUp", false);
                return advance(obs.get("state"), actionDigest, source.id(), hash(obj("t", "pca-evidence", "e", obs.get("evidence"))));
            } catch (Exception e) {
                return obj("ok", false, "reason", "state-source-mismatch", "stepUp", false);
            }
        }

        private Map<String, Object> advance(Object afterIn, Object actionDigest, String stateSource, String evidenceDigest) {
            if (!isStr(actionDigest) || ((String) actionDigest).isEmpty()) return obj("ok", false, "reason", "malformed", "stepUp", false);
            Object after;
            String afterDigest;
            double pb, pa;
            Cls cls;
            try {
                after = snapshot(afterIn);
                afterDigest = stateDigest(after);
                pb = potentialOf(goal, reg, cur);
                pa = potentialOf(goal, reg, after);
                cls = classify(pb, pa, num(get(goal, "epsilon")));
            } catch (RuntimeException e) {
                return obj("ok", false, "reason", denialOf(e), "stepUp", false);
            }
            if (guard != null && !runGuard(guard, obj("seq", seq, "before", cur, "after", after, "action_digest", actionDigest)))
                return obj("ok", false, "reason", "prohibited", "stepUp", false);
            double nextSpent = spentTotal + cls.charge;
            if (nextSpent > MAX_SAFE || nextSpent > num(get(goal, "explorationBudget"))) return obj("ok", false, "reason", "exploration-exhausted", "stepUp", true);
            Map<String, Object> body = obj("goal_commitment", commitment, "seq", seq, "before", cur, "after", after, "before_digest", curDigest, "after_digest", afterDigest,
                "action_digest", actionDigest, "mode", cls.mode, "potential_before", (long) pb, "potential_after", (long) pa, "charge", (long) cls.charge,
                "state_source", stateSource, "evidence_digest", evidenceDigest, "prev", head);
            Map<String, Object> step = new LinkedHashMap<>(body);
            step.put("digest", stepBodyDigest(body));
            log.add(step);
            seq++;
            head = (String) step.get("digest");
            spentTotal = nextSpent;
            cur = after;
            curDigest = afterDigest;
            return obj("ok", true, "step", step, "spent", (long) spentTotal, "remaining", (long) remaining());
        }
    }

    // ---- verification -----------------------------------------------------------------------------------------------------------------------

    /** {@code {ok: true, charge}} or {@code {ok: false, reason}} for one step; total. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyProgressStep(Object goal, Object commitment, Object stepO, Options opts) {
        try {
            if (!verifyGoalCommitment(goal, commitment)) return fail("goal-mismatch");
            if (!isStep(stepO)) return fail("malformed");
            Map<String, Object> step = (Map<String, Object>) stepO;
            if (!step.get("goal_commitment").equals(commitment)) return fail("goal-mismatch");
            if (opts.expectedSeq != null && num(step.get("seq")) != opts.expectedSeq) return fail("seq-mismatch");
            if (opts.expectedPrev != null && !step.get("prev").equals(opts.expectedPrev)) return fail("chain-break");
            if (opts.expectedActionDigest != null && !step.get("action_digest").equals(opts.expectedActionDigest)) return fail("action-mismatch");
            if (opts.expectedBeforeDigest != null && !step.get("before_digest").equals(opts.expectedBeforeDigest)) return fail("state-mismatch");
            if (opts.expectedAfterDigest != null && !step.get("after_digest").equals(opts.expectedAfterDigest)) return fail("state-mismatch");
            Map<String, Object> body = new LinkedHashMap<>(step);
            Object digest = body.remove("digest");
            if (!stepBodyDigest(body).equals(digest)) return fail("digest-mismatch");
            if (!stateDigest(step.get("before")).equals(step.get("before_digest")) || !stateDigest(step.get("after")).equals(step.get("after_digest"))) return fail("state-digest-mismatch");
            PotentialRegistry reg = toRegistry(opts.registry);
            double pb, pa;
            Cls cls;
            try {
                pb = potentialOf(goal, reg, step.get("before"));
                pa = potentialOf(goal, reg, step.get("after"));
                cls = classify(pb, pa, num(get(goal, "epsilon")));
            } catch (RuntimeException e) {
                return fail(denialOf(e));
            }
            if (pb != num(step.get("potential_before")) || pa != num(step.get("potential_after"))) return fail("potential-mismatch");
            if (!step.get("mode").equals(cls.mode)) return fail("mode-mismatch");
            if (num(step.get("charge")) != cls.charge) return fail("charge-mismatch");
            if (opts.trustedStateSources != null && !opts.trustedStateSources.contains(step.get("state_source"))) return fail("untrusted-state-source");
            if (!Boolean.FALSE.equals(opts.requireAttestedState) && "".equals(step.get("state_source"))) return fail("untrusted-state-source");
            if (opts.guard != null && !runGuard(opts.guard, obj("seq", step.get("seq"), "before", step.get("before"), "after", step.get("after"), "action_digest", step.get("action_digest"))))
                return fail("prohibited");
            if (opts.attestation != null) {
                boolean ok;
                try {
                    ok = Boolean.TRUE.equals(opts.attestation.verify(step));
                } catch (RuntimeException e) {
                    ok = false;
                }
                if (!ok) return fail("attestation-failed");
            }
            return obj("ok", true, "charge", (long) cls.charge);
        } catch (RuntimeException e) {
            return fail("malformed");
        }
    }

    private static Map<String, Object> trajFail(String reason, long at) { return obj("ok", false, "reason", reason, "at", at); }

    /** Verifies a whole trajectory: each step, the chain, the continuity of states and the committed exploration budget. */
    public static Map<String, Object> verifyTrajectory(Object goal, Object commitment, Object stepsO, Options opts) {
        if (!verifyGoalCommitment(goal, commitment)) return trajFail("goal-mismatch", -1);
        if (!(stepsO instanceof List)) return trajFail("malformed", -1);
        List<?> steps = (List<?>) stepsO;
        if (opts.expectedActionDigests != null && opts.expectedActionDigests.size() != steps.size())
            return trajFail("action-mismatch", Math.min(opts.expectedActionDigests.size(), steps.size()));
        Object anchor;
        try {
            anchor = opts.initialDigest != null ? opts.initialDigest : !opts.hasInitial ? null : stateDigest(opts.initial);
        } catch (RuntimeException e) {
            return trajFail("malformed", -1);
        }
        String prev = GENESIS;
        double spent = 0, finalPotential = -1;
        if (steps.isEmpty() && opts.hasInitial) {
            try {
                finalPotential = potentialOf(goal, toRegistry(opts.registry), opts.initial);
            } catch (RuntimeException e) {
                return trajFail(denialOf(e), -1);
            }
        }
        double budget = num(get(goal, "explorationBudget"));
        for (int i = 0; i < steps.size(); i++) {
            Object s = steps.get(i);
            Options so = opts.copy();
            so.expectedSeq = (double) i;
            so.expectedPrev = prev;
            so.expectedActionDigest = opts.expectedActionDigests == null ? null : (String) opts.expectedActionDigests.get(i);
            Map<String, Object> r = verifyProgressStep(goal, commitment, s, so);
            if (!Boolean.TRUE.equals(r.get("ok"))) return trajFail((String) r.get("reason"), i);
            if (anchor != null && !get(s, "before_digest").equals(anchor)) return trajFail("discontinuous-state", i);
            spent += num(r.get("charge"));
            if (!(Double.isFinite(spent) && spent <= MAX_SAFE && spent <= budget)) return trajFail("budget-exceeded", i);
            anchor = get(s, "after_digest");
            prev = (String) get(s, "digest");
            finalPotential = num(get(s, "potential_after"));
        }
        return obj("ok", true, "spent", (long) spent, "remaining", (long) (budget - spent), "reached", finalPotential == 0, "finalPotential", (long) finalPotential,
            "steps", (long) steps.size(), "head", prev);
    }

    // ---- signed steps -------------------------------------------------------------------------------------------------------------------

    private static byte[] sigMessage(Object step, Object holder) {
        return Pca.canonBytes(obj("d", PROGRESS_SIG_DOMAIN, "b", obj("holder", holder, "goal_commitment", get(step, "goal_commitment"), "action_digest", get(step, "action_digest"),
            "before_digest", get(step, "before_digest"), "after_digest", get(step, "after_digest"), "seq", get(step, "seq"), "prev", get(step, "prev"), "step_digest", get(step, "digest"))));
    }

    /** {@code {step, holder, sig}}: Ed25519 over the domain-separated binding of the step to the holder (deterministic). */
    public static Map<String, Object> signProgressStep(Object step, byte[] secretKey, String holderPublicKey) {
        return obj("step", step, "holder", holderPublicKey, "sig", Pca.b64(Keys.edFromSeed(secretKey).sign(sigMessage(step, holderPublicKey))));
    }

    private static boolean signedShape(Object s) { return isObj(s) && isStr(get(s, "holder")) && isStr(get(s, "sig")) && isStep(get(s, "step")); }

    /** One signed step: holder, action, goal and signature checks, then {@link #verifyProgressStep}. */
    public static Map<String, Object> verifySignedProgressStep(Object goal, Object commitment, Object signed, Options opts) {
        try {
            if (!signedShape(signed)) return fail("malformed");
            Object step = get(signed, "step");
            if (!get(signed, "holder").equals(opts.expectedHolder)) return fail("holder-mismatch");
            if (!get(step, "action_digest").equals(opts.expectedActionDigest)) return fail("action-mismatch");
            if (!get(step, "goal_commitment").equals(commitment)) return fail("goal-mismatch");
            if (!Pca.verifyB64u((String) get(signed, "holder"), sigMessage(step, get(signed, "holder")), (String) get(signed, "sig"))) return fail("bad-signature");
            Options o = opts.copy();
            o.expectedActionDigest = opts.expectedActionDigest;
            return verifyProgressStep(goal, commitment, step, o);
        } catch (RuntimeException e) {
            return fail("malformed");
        }
    }

    /** A signed trajectory: per step the holder, action and signature, then {@link #verifyTrajectory} over the steps. */
    public static Map<String, Object> verifySignedTrajectory(Object goal, Object commitment, Object signedO, Options opts) {
        if (!(signedO instanceof List)) return trajFail("malformed", -1);
        List<?> signed = (List<?>) signedO;
        if (opts.expectedActionDigests.size() != signed.size()) return trajFail("action-mismatch", Math.min(opts.expectedActionDigests.size(), signed.size()));
        for (int i = 0; i < signed.size(); i++) {
            Object sp = signed.get(i);
            try {
                if (!signedShape(sp)) return trajFail("malformed", i);
                if (!get(sp, "holder").equals(opts.expectedHolder)) return trajFail("holder-mismatch", i);
                if (!get(get(sp, "step"), "action_digest").equals(opts.expectedActionDigests.get(i))) return trajFail("action-mismatch", i);
                if (!Pca.verifyB64u((String) get(sp, "holder"), sigMessage(get(sp, "step"), get(sp, "holder")), (String) get(sp, "sig"))) return trajFail("bad-signature", i);
            } catch (RuntimeException e) {
                return trajFail("malformed", i);
            }
        }
        List<Object> steps = new ArrayList<>();
        for (Object s : signed) steps.add(get(s, "step"));
        return verifyTrajectory(goal, commitment, steps, opts);
    }
}
