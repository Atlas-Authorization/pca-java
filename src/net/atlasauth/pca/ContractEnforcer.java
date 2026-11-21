package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.DoubleSupplier;

/**
 * Durable enforcement of a signed behavioural contract (the reference's {@code contract-enforcer.ts}). The monitor state is ONE document in an
 * {@link AtomicKv}; the whole read-check-advance runs inside {@code update}, so racing callers serialise and a counter-style state never forks. Only a
 * contract signed by the PINNED principal is loaded, the state document is bound to the contract id, every corrupt or unreadable state and every store
 * error DENIES, and a real violation LATCHES the enforcer until the principal signs a reset.
 */
public final class ContractEnforcer {
    public static final String RESET_DOMAIN = "atlas-pca/contract-reset/v1\u0000";
    private static final int DOC_VERSION = 1;
    private static final String CORRUPT = "<state>: stored state is corrupt or belongs to another contract";

    /** The outcome of one check: {@code reason} is ok, latched, violated, permission, state-error or store-error. */
    public static final class Result {
        public final boolean allow;
        public final String reason;
        public final List<Object> violated, reasons;
        public final long seq;

        Result(boolean allow, String reason, List<Object> violated, List<Object> reasons, long seq) {
            this.allow = allow; this.reason = reason; this.violated = violated; this.reasons = reasons; this.seq = seq;
        }
    }

    private final AtomicKv kv;
    private final Map<String, Object> contract;
    private final String key;
    private final DoubleSupplier now;
    private final boolean latch;

    private ContractEnforcer(AtomicKv kv, Map<String, Object> contract, String key, DoubleSupplier now, boolean latch) {
        this.kv = kv; this.contract = contract; this.key = key; this.now = now; this.latch = latch;
    }

    /** Opens an enforcer; throws {@link IllegalArgumentException} unless the contract verifies under the pinned principal. {@code key} and {@code now} are nullable. */
    public static ContractEnforcer open(AtomicKv kv, Object contract, String principal, String key, DoubleSupplier now, boolean latchOnViolation) {
        if (kv == null) throw new IllegalArgumentException("ContractEnforcer: a durable key-value store is required");
        if (principal == null || principal.isEmpty()) throw new IllegalArgumentException("ContractEnforcer: a pinned principal is required");
        String v = Contracts.verifyContract(contract, principal);
        if (v != null) throw new IllegalArgumentException("ContractEnforcer: contract refused: " + v);
        Map<String, Object> c = Prohibitions.obj(contract);
        return new ContractEnforcer(kv, c, key != null ? key : "contract/" + Contracts.contractId(c), now != null ? now : () -> (double) System.currentTimeMillis(), latchOnViolation);
    }

    private static byte[] resetMessage(String id, long seq) {
        return Pca.concat(RESET_DOMAIN.getBytes(StandardCharsets.UTF_8), AttestCommon.sha256Sum((id + ":" + seq).getBytes(StandardCharsets.UTF_8)));
    }

    /** The principal's authorisation to un-latch a contract at sequence {@code seq} (binds both, so it cannot be replayed later). */
    public static String signReset(byte[] principalSeed, String contractId, long seq) {
        return Pca.b64(Keys.edFromSeed(principalSeed).sign(resetMessage(contractId, seq)));
    }

    private static boolean isDoc(Object dO, String id) {
        if (!Prohibitions.isObj(dO)) return false;
        Map<String, Object> d = Prohibitions.obj(dO);
        if (!Prohibitions.isInteger(d.get("v")) || Prohibitions.dv(d.get("v")) != DOC_VERSION || !id.equals(d.get("contract_id")) || Prohibitions.stateProblem(d.get("state")) != null) return false;
        if (!d.containsKey("latched")) return true;
        Object l = d.get("latched");
        if (!Prohibitions.isObj(l)) return false;
        Map<String, Object> lm = Prohibitions.obj(l);
        if (!Prohibitions.isInteger(lm.get("seq")) || Prohibitions.negZero(lm.get("seq")) || !(lm.get("violated") instanceof List)) return false;
        for (Object v : Prohibitions.arr(lm.get("violated"))) if (!(v instanceof String)) return false;
        return true;
    }

    private static long seqOf(Map<String, Object> doc) { return (long) Prohibitions.dv(Prohibitions.obj(doc.get("state")).get("seq")); }

    private static Result res(boolean allow, String reason, List<Object> violated, List<Object> reasons, long seq) { return new Result(allow, reason, violated, reasons, seq); }

    private static List<Object> list(Object... xs) { return new ArrayList<>(java.util.Arrays.asList(xs)); }

    private Result latchedResult(Map<String, Object> doc) {
        Map<String, Object> l = Prohibitions.obj(doc.get("latched"));
        return res(false, "latched", new ArrayList<>(Prohibitions.arr(l.get("violated"))),
            list("<latched>: contract violated at seq " + AttestCommon.jsNumString(Prohibitions.dv(l.get("seq")))), seqOf(doc));
    }

    /** Checks one action against the permission verdict AND the contract, advancing the durable state iff both allow. Never throws. */
    public Result check(Object action, boolean permitted) {
        String id = (String) contract.get("id");
        Result[] out = {res(false, "store-error", new ArrayList<>(), list("store unavailable"), 0)};
        try {
            double wall = now.getAsDouble();
            kv.update(key, prev -> {
                if (prev != null && !isDoc(prev, id)) {
                    out[0] = res(false, "state-error", new ArrayList<>(), list(CORRUPT), 0);
                    return null;
                }
                Map<String, Object> pd = prev == null ? null : Prohibitions.obj(prev);
                if (pd != null && (Double.isNaN(wall) || Double.isInfinite(wall))) {
                    out[0] = res(false, "state-error", new ArrayList<>(), list("<state>: clock is not finite"), seqOf(pd));
                    return null;
                }
                Map<String, Object> doc = pd != null ? pd : Prohibitions.map("v", Prohibitions.jn(DOC_VERSION), "contract_id", id,
                    "state", Prohibitions.emptyState(Prohibitions.jn(Double.isNaN(wall) || Double.isInfinite(wall) ? 0 : wall)));
                if (doc.containsKey("latched")) {
                    out[0] = latchedResult(doc);
                    return null;
                }
                Map<String, Object> state = Prohibitions.obj(doc.get("state"));
                double stateNow = Prohibitions.dv(state.get("now"));
                Map<String, Object> r = Contracts.checkAndAdvanceContract(permitted, state, action, contract, Prohibitions.jn(Math.max(wall, stateNow)), state.get("seq"), null);
                if (Boolean.TRUE.equals(r.get("allow"))) {
                    out[0] = res(true, "ok", new ArrayList<>(), new ArrayList<>(), (long) Prohibitions.dv(Prohibitions.obj(r.get("next")).get("seq")));
                    Map<String, Object> next = new LinkedHashMap<>(doc);
                    next.put("state", r.get("next"));
                    return next;
                }
                boolean structural = "state".equals(r.get("decidedBy"));
                List<Object> violated = Prohibitions.arr(r.get("violated"));
                boolean real = !structural && !violated.isEmpty();
                out[0] = res(false, structural ? "state-error" : (real ? "violated" : "permission"), real ? new ArrayList<>(violated) : new ArrayList<>(),
                    new ArrayList<>(Prohibitions.arr(r.get("reasons"))), seqOf(doc));
                if (real && latch) {
                    Map<String, Object> next = new LinkedHashMap<>(doc);
                    next.put("latched", Prohibitions.map("seq", state.get("seq"), "violated", new ArrayList<>(violated)));
                    return next;
                }
                return null;
            });
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            out[0] = res(false, "store-error", new ArrayList<>(), list("store error (fail closed)"), 0);
        }
        return out[0];
    }

    /** Read-only evaluation against the stored state: nothing is advanced or latched. Never throws. */
    public Result peek(Object action) {
        try {
            Object prev = kv.get(key);
            if (prev != null && !isDoc(prev, (String) contract.get("id"))) return res(false, "state-error", new ArrayList<>(), list(CORRUPT), 0);
            if (prev != null && Prohibitions.obj(prev).containsKey("latched")) return latchedResult(Prohibitions.obj(prev));
            double wall = now.getAsDouble();
            Object state = prev != null ? Prohibitions.obj(prev).get("state") : Prohibitions.emptyState(Prohibitions.jn(Double.isNaN(wall) || Double.isInfinite(wall) ? 0 : wall));
            Map<String, Object> r = Contracts.checkContract(action, contract, state);
            long seq = prev != null ? seqOf(Prohibitions.obj(prev)) : 0;
            if (Boolean.TRUE.equals(r.get("ok"))) return res(true, "ok", new ArrayList<>(), new ArrayList<>(), seq);
            return res(false, "violated", new ArrayList<>(Prohibitions.arr(r.get("violated"))), new ArrayList<>(Prohibitions.arr(r.get("reasons"))), seq);
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return res(false, "store-error", new ArrayList<>(), list("store error (fail closed)"), 0);
        }
    }

    /** The stored state (and whether it is latched), or null when nothing was admitted yet. Throws {@link IllegalStateException} on a corrupt document. */
    public Map<String, Object> state() {
        Object d = kv.get(key);
        if (d == null) return null;
        if (!isDoc(d, (String) contract.get("id"))) throw new IllegalStateException("ContractEnforcer: stored state is corrupt or belongs to another contract");
        return Prohibitions.map("state", Prohibitions.obj(d).get("state"), "latched", Prohibitions.obj(d).containsKey("latched"));
    }

    /** Un-latches with the principal's signature at the latched sequence (see {@link #signReset}); returns whether it cleared. */
    public boolean reset(String sig) {
        boolean[] cleared = {false};
        String id = (String) contract.get("id");
        try {
            kv.update(key, prev -> {
                if (!isDoc(prev, id) || !Prohibitions.obj(prev).containsKey("latched")) return null;
                long seq = (long) Prohibitions.dv(Prohibitions.obj(Prohibitions.obj(prev).get("latched")).get("seq"));
                if (sig == null || !IntentJs.verifyEd(contract.get("principal"), resetMessage(id, seq), sig)) return null;
                cleared[0] = true;
                Map<String, Object> next = new LinkedHashMap<>(Prohibitions.obj(prev));
                next.remove("latched");
                return next;
            });
        } catch (RuntimeException | LinkageError | AssertionError | StackOverflowError e) {
            return false;
        }
        return cleared[0];
    }
}
