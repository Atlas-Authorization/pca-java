package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * The leftovers of five intent modules of the reference, over the JSON tree: the signing and digest helpers of the strict artifacts (intent-artifacts.ts),
 * classifier verdict signing and the attestation gate (intent-classifier.ts), the signing and digest half of accumulator receipts and sequencer key sets
 * (intent-acc.ts), the exported constants of those modules, and admission and settlement of an action through a session store (intent-history.ts). The shape
 * checks, the verdicts and the pure history functions are the rest of the intent layer ({@link IntentArtifacts}, {@link IntentClassifier}, {@link IntentAcc},
 * {@link IntentHistory}); {@link IntentRequired} is the signed question.
 */
public final class IntentMisc2 {
    private IntentMisc2() {}

    public static final String ACC_RECEIPT_CORE_DOMAIN = "atlas-pca/acc-receipt-core/v1";
    public static final List<String> ACC_SCOPES = NullSafe.list(List.of("session", "principal", "org", "fleet"));

    private static Map<String, Object> re(String source) { return Issue.obj("$regex", source); }

    private static List<Object> strs(String... xs) { return new ArrayList<Object>(List.of(xs)); }

    private static Object num(long n) { return IntentJs.ofLong(n); }

    /** Every exported constant of the five modules (a regular expression as {"$regex": source}). */
    public static Map<String, Object> constants() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("DATA_CLASS_RE", re("^[a-z][a-z0-9_]*(\\.[a-z0-9_]+)*$"));
        m.put("INTENT_NAME_RE", re("^[a-z][a-z0-9_]{0,63}$"));
        m.put("PARAM_SEGMENT_RE", re("^[A-Za-z0-9_-]{1,64}$"));
        m.put("SUITE_MEMBERS", new ArrayList<Object>(IntentArtifacts.SUITE_MEMBERS));
        m.put("FRICTIONS", new ArrayList<Object>(IntentRequired.FRICTIONS));
        m.put("INTENT_ACTION_DOMAIN", IntentRequired.INTENT_ACTION_DOMAIN);
        m.put("INTENT_PROBLEM_KINDS", new ArrayList<Object>(IntentRequired.INTENT_PROBLEM_KINDS));
        m.put("INTENT_REQUIRED_DOMAIN", IntentRequired.INTENT_REQUIRED_DOMAIN);
        m.put("PROBLEM_BASE", IntentRequired.PROBLEM_BASE);
        m.put("INTENT_CLASSIFIER_DOMAIN", IntentClassifier.INTENT_CLASSIFIER_DOMAIN);
        m.put("INTENT_CLASSIFIER_REF_DOMAIN", IntentClassifier.INTENT_CLASSIFIER_REF_DOMAIN);
        m.put("MAX_CLASSIFIER_LABELS", num(IntentClassifier.MAX_CLASSIFIER_LABELS));
        m.put("MAX_COMMITTED_CLASSES", num(IntentClassifier.MAX_COMMITTED_CLASSES));
        m.put("ACC_AGGS", strs("sum", "count", "distinct", "max"));
        m.put("ACC_ID_RE", re("^[A-Za-z0-9_]{1,64}$"));
        m.put("ACC_RECEIPT_CORE_DOMAIN", ACC_RECEIPT_CORE_DOMAIN);
        m.put("ACC_RECEIPT_DOMAIN", IntentAcc.ACC_RECEIPT_DOMAIN);
        m.put("ACC_RECEIPT_REF_DOMAIN", IntentAcc.ACC_RECEIPT_REF_DOMAIN);
        m.put("ACC_RESERVE_DOMAIN", IntentAcc.ACC_RESERVE_DOMAIN);
        m.put("ACC_SCOPES", new ArrayList<Object>(ACC_SCOPES));
        m.put("DEFAULT_MAX_KEYSET_AGE_MS", num(IntentAcc.DEFAULT_MAX_KEYSET_AGE_MS));
        m.put("DEFAULT_MAX_RECEIPT_AGE_MS", num(IntentAcc.DEFAULT_MAX_RECEIPT_AGE_MS));
        m.put("KID_RE", re("^[A-Za-z0-9_.:-]{1,64}$"));
        m.put("MAX_MONITOR_WITHIN", num(IntentAcc.MAX_MONITOR_WITHIN));
        m.put("MAX_RECEIPT_LIFETIME_MS", num(IntentAcc.MAX_RECEIPT_LIFETIME_MS));
        m.put("MAX_SESSION_ACCUMULATORS", num(IntentAcc.MAX_SESSION_ACCUMULATORS));
        m.put("MAX_SESSION_MONITORS", num(IntentAcc.MAX_SESSION_MONITORS));
        m.put("MONITOR_KINDS", strs("requires_prior", "precedes", "never", "always", "responds_within"));
        m.put("RECEIPT_SKEW_MS", num(IntentAcc.RECEIPT_SKEW_MS));
        m.put("SEQUENCER_KEYS_DOMAIN", IntentAcc.SEQUENCER_KEYS_DOMAIN);
        m.put("SEQUENCER_KEYS_REF_DOMAIN", IntentAcc.SEQUENCER_KEYS_REF_DOMAIN);
        m.put("COUNTED_STATUSES", strs("reserved", "committed"));
        m.put("EVENT_STATUSES", strs("reserved", "committed", "released", "reverted"));
        return m;
    }

    private static Object need(Map<String, Object> d, String k) {
        if (!d.containsKey(k)) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
        return d.get(k);
    }

    // ---- strict artifacts ----

    /**
     * Sign an artifact body under {@code domain}: {...body, sig, pq_sig?}; a non-ed25519 suite signs {@code alg} and {@code pq_pk} into the body.
     * Throws on an unknown alg or missing key material.
     */
    public static Map<String, Object> signArtifact(String domain, Map<String, Object> body, byte[] secret, Pq.SignerSuiteOpts suite) {
        Object alg = suite == null ? null : suite.alg;
        Pq.Suite resolved = Pq.resolveSigAlg(alg, alg != null);
        if (resolved == null) throw new IllegalArgumentException("signArtifact: unknown signature alg '" + IntentRevocation.jsText(alg, true) + "'");
        Map<String, Object> full = new LinkedHashMap<>(body);
        if (!resolved.alg.equals("ed25519")) {
            full.put("alg", resolved.alg);
            String pq = Pq.suitePqPublicKey(alg, suite);
            if (pq == null) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
            full.put("pq_pk", pq);
        }
        Pq.SuiteArtifactFields f = Pq.signSuiteArtifact(alg, Pq.suiteKeysOf(secret, suite), IntentArtifacts.artifactMessage(domain, full));
        Map<String, Object> out = new LinkedHashMap<>(full);
        out.put("sig", f.sig);
        if (f.pqSig != null) out.put("pq_sig", f.pqSig);
        return out;
    }

    /** The artifact's signature under a pinned signer: {@code pin} a b64u key, or {pk, pq_pk?}. Never throws. */
    public static boolean verifyArtifactSig(String domain, Object artifact, Object pin) {
        try {
            if (!(artifact instanceof Map)) return false;
            Object pk = pin instanceof String ? pin : IntentJs.get(pin, "pk");
            Object pq = pin instanceof Map ? IntentJs.get(pin, "pq_pk") : null;
            return IntentArtifacts.verifyArtifactSig(domain, IntentJs.obj(artifact), pk, pq instanceof String ? pq : null);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** The b64u public key of an Ed25519 secret key (seed). */
    public static String publicKeyB64u(byte[] secret) { return Keys.edFromSeed(secret).id(); }

    // ---- the classifier ----

    /** A classifier verdict signed by {@code secret}: {v: 1, kind, ...body, judge, sig, ...} (the judge is the signer's key). */
    public static Map<String, Object> signClassifierVerdict(Map<String, Object> body, byte[] secret, Pq.SignerSuiteOpts suite) {
        Map<String, Object> o = Issue.obj("v", IntentJs.ofLong(1), "kind", "pca-intent-classification");
        o.putAll(body);
        o.put("judge", publicKeyB64u(secret));
        return signArtifact(IntentClassifier.INTENT_CLASSIFIER_DOMAIN, o, secret, suite);
    }

    /** The attestation gate of a classifier verdict: its {@code measurement} must equal the attested enclave measurement. A non-object verdict is refused. */
    public static Map<String, Object> verifyClassifierAttestation(Object v, Object attestation, Object approved) {
        if (!(v instanceof Map)) return Issue.obj("ok", false, "reason", "verdict must be an object");
        try {
            return SemanticThreshold.verifyJudgeAttestation(IntentJs.get(v, "measurement"), attestation, approved);
        } catch (RuntimeException e) {
            return Issue.obj("ok", false, "reason", "attestation check error (fail closed): " + (e.getMessage() == null || e.getMessage().isEmpty() ? "unknown" : e.getMessage()));
        }
    }

    // ---- accumulator receipts and sequencer key sets ----

    private static Map<String, Object> receiptBodyOf(Map<String, Object> r, String signer) {
        Map<String, Object> b = new LinkedHashMap<>();
        for (String k : new String[] {"v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at", "kid"}) b.put(k, need(r, k));
        Object l = need(r, "ledger");
        if (!(l instanceof Map)) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'index')");
        b.put("ledger", Issue.obj("index", need(IntentJs.obj(l), "index"), "head", need(IntentJs.obj(l), "head")));
        b.put("signer", signer);
        return b;
    }

    private static Map<String, Object> withSuiteFields(Map<String, Object> base, Pq.SuiteArtifactFields f) {
        Map<String, Object> o = new LinkedHashMap<>(base);
        o.put("sig", f.sig);
        if (f.alg != null) o.put("alg", f.alg);
        if (f.pqPk != null) o.put("pq_pk", f.pqPk);
        if (f.pqSig != null) o.put("pq_sig", f.pqSig);
        return o;
    }

    /** Sign an accumulator receipt as the sequencer: {...body, signer, sig, ...}. Throws on a body that is not a well-formed receipt. */
    public static Map<String, Object> signAccReceipt(Map<String, Object> body, byte[] sequencerSecret, Pq.SignerSuiteOpts suite) {
        String signer = publicKeyB64u(sequencerSecret);
        Map<String, Object> base = receiptBodyOf(body, signer);
        Object alg = suite == null ? null : suite.alg;
        String pqPk = Pq.suitePqPublicKey(alg, suite);
        Pq.SuiteArtifactFields f = Pq.signSuiteArtifact(alg, Pq.suiteKeysOf(sequencerSecret, suite),
            IntentJs.message(IntentAcc.ACC_RECEIPT_DOMAIN, IntentJs.bindSuiteFields(base, alg, alg != null, pqPk, pqPk != null)));
        Map<String, Object> out = withSuiteFields(base, f);
        String bad = IntentAcc.receiptShapeError(out);
        if (bad != null) throw new IllegalArgumentException("signAccReceipt: " + bad);
        return out;
    }

    /** The receipt's log-leaf content: the strict hash of its core (without the ledger position, the key id and the signature fields). */
    public static String accReceiptCoreDigest(Map<String, Object> r) {
        Map<String, Object> core = new LinkedHashMap<>();
        for (String k : new String[] {"v", "kind", "session", "acc", "seq", "pre", "delta", "post", "pcactn_digest", "aud", "issued_at", "expires_at"}) core.put(k, need(r, k));
        return IntentJs.hashCanonical(Issue.obj("d", ACC_RECEIPT_CORE_DOMAIN, "r", core));
    }

    /** Sign a sequencer key set as the root: {v, kind, sequencer, version, issued_at, keys, sig, ...}. Throws on a body that is not a well-formed key set. */
    public static Map<String, Object> signSequencerKeySet(Map<String, Object> body, byte[] rootSecret, Pq.SignerSuiteOpts suite) {
        Map<String, Object> base = new LinkedHashMap<>();
        for (String k : new String[] {"v", "kind"}) base.put(k, need(body, k));
        base.put("sequencer", publicKeyB64u(rootSecret));
        for (String k : new String[] {"version", "issued_at", "keys"}) base.put(k, need(body, k));
        Object alg = suite == null ? null : suite.alg;
        String pqPk = Pq.suitePqPublicKey(alg, suite);
        Pq.SuiteArtifactFields f = Pq.signSuiteArtifact(alg, Pq.suiteKeysOf(rootSecret, suite),
            IntentJs.message(IntentAcc.SEQUENCER_KEYS_DOMAIN, IntentJs.bindSuiteFields(base, alg, alg != null, pqPk, pqPk != null)));
        Map<String, Object> out = withSuiteFields(base, f);
        String bad = IntentAcc.keySetShapeError(out);
        if (bad != null) throw new IllegalArgumentException("signSequencerKeySet: " + bad);
        return out;
    }

    /** The distinct strings in UTF-8 byte order. */
    public static List<Object> sortedDistinct(List<String> keys) { return new ArrayList<Object>(IntentJs.sortedUtf8(new LinkedHashSet<>(keys))); }

    // ---- admission and settlement through a session store ----

    /** A transaction on ONE session's history, holding its exclusive lock. */
    public interface SessionTx {
        /** A copy of the session's events in admission order. */
        List<Object> events();

        void append(Map<String, Object> event);

        /** Set the status of an event; false when the session has no such event. */
        boolean setStatus(String id, String status);
    }

    /**
     * The accumulator state holder. Admission is linearizable iff {@link #withSession} serialises every admission of one session: the pre-state read, the
     * verification and the reservation happen under one lock (a row lock in a database, the in-process lock of {@link MemorySessionStore}).
     * {@link #durable} must be exactly {@code true} for a store whose history survives a restart; admission refuses any other store unless told otherwise.
     */
    public interface SessionStore {
        Object durable();

        <T> T withSession(String session, Function<SessionTx, T> fn);
    }

    /** The in-process session store (tests and single-process sites): its histories die with the process. */
    public static final class MemorySessionStore implements SessionStore {
        private final Object durable;
        private final Map<String, List<Map<String, Object>>> events = new HashMap<>();
        private final Object lock = new Object();

        public MemorySessionStore(Object durable) { this.durable = durable; }

        @Override public Object durable() { return durable; }

        @Override public <T> T withSession(String session, Function<SessionTx, T> fn) {
            synchronized (lock) {
                List<Map<String, Object>> list = events.computeIfAbsent(session, k -> new ArrayList<>());
                return fn.apply(new SessionTx() {
                    @Override public List<Object> events() {
                        List<Object> out = new ArrayList<>();
                        for (Map<String, Object> e : list) out.add(new LinkedHashMap<>(e));
                        return out;
                    }

                    @Override public void append(Map<String, Object> event) { list.add(new LinkedHashMap<>(event)); }

                    @Override public boolean setStatus(String id, String status) {
                        for (Map<String, Object> e : list) {
                            if (java.util.Objects.equals(e.get("id"), id)) {
                                e.put("status", status);
                                return true;
                            }
                        }
                        return false;
                    }
                });
            }
        }
    }

    /**
     * Admit one action atomically against the session's accumulators (site-local holder): under the session lock, compute the pre-states and monitor states from
     * the history, run {@code verify} with them and, on {@code allow}, append the event as {@code reserved}. The store must report {@code durable() === true}
     * unless {@code requireDurable} is false (a restart would reset every cap). {@code args} = {session, root, schema?, event}.
     */
    public static Map<String, Object> admitIntentAction(SessionStore store, Map<String, Object> args, Function<Map<String, Object>, Map<String, Object>> verify, boolean requireDurable) {
        if (requireDurable && !Boolean.TRUE.equals(store == null ? null : store.durable())) {
            throw new IllegalStateException("admitIntentAction: the session store is not durable (a restart would reset every cap); use a durable IntentSessionStore");
        }
        Map<String, Object> ev = IntentJs.obj(args.get("event"));
        return store.withSession((String) args.get("session"), tx -> {
            List<Object> history = tx.events();
            Map<String, Object> acc = IntentHistory.accContextFor(IntentJs.obj(args.get("root")), history, IntentJs.obj(ev.get("params")), ev.get("t"), args.get("schema"));
            Map<String, Object> v = verify.apply(acc);
            if (IntentRevocation.truthy(v.get("allow"))) {
                Map<String, Object> reserved = new LinkedHashMap<>(ev);
                reserved.put("status", "reserved");
                tx.append(reserved);
            }
            return v;
        });
    }

    /** Settle an event after its effect: committed, released or reverted. False when the session has no such event. */
    public static boolean settleIntentEvent(SessionStore store, String session, String id, String status) { return store.withSession(session, tx -> tx.setStatus(id, status)); }
}
