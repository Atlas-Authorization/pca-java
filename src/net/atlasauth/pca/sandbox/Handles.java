package net.atlasauth.pca.sandbox;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.DoubleSupplier;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.revoke.JsVal;

/**
 * A per-sandbox capability table (a CSpace): indices are small integers meaningful only inside one table, like file descriptors.
 * A slot exists only because a verified authorization allowed exactly that operation, so the authority a tool holds is the set of
 * operations someone with the right to approve them approved. Derivation is monotone; revoking a slot revokes everything derived
 * from it. Handle indices are 1-based.
 */
public final class Handles {
    private Handles() {}

    /** Negative return codes of a handle use (the WASM ABI returns them as i32). */
    public static final Map<String, Long> USE_ERR;

    static {
        Map<String, Long> m = new LinkedHashMap<>();
        m.put("unknown_handle", -1L);
        m.put("spent", -2L);
        m.put("out_too_small", -3L);
        m.put("bad_memory", -4L);
        m.put("executor_error", -5L);
        m.put("no_executor", -6L);
        USE_ERR = Collections.unmodifiableMap(m);
    }

    /** What a tool may do with a handle: run the one authorized operation. A null result or a throw is an executor error. */
    @FunctionalInterface
    public interface Executor {
        byte[] run(String verb, String resource, Map<String, Object> params) throws Exception;
    }

    /** Outcome of a handle use. */
    public static final class UseResult {
        public final boolean ok;
        public final byte[] result;
        public final String reason;

        UseResult(boolean ok, byte[] result, String reason) { this.ok = ok; this.result = result; this.reason = reason; }

        static UseResult fail(String reason) { return new UseResult(false, null, reason); }

        /** {@code {ok:true, result}} or {@code {ok:false, reason}}. */
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", ok);
            if (ok) m.put("result", result);
            else m.put("reason", reason);
            return m;
        }
    }

    /** Options of {@link HandleTable#mint}: JSON numbers (or null for the default) and an optional minimum runtime class. */
    public static final class MintOptions {
        /** How many times the handle may be used. Default 1. */
        public Object uses;
        /** Epoch ms after which the handle is spent. Default never. */
        public Object expiresAt;
        /** Refuse to mint into a table below this class. */
        public String requires;
    }

    private static final class Slot {
        String verb, resource, paramsDigest, opId;
        Map<String, Object> params;
        long uses;
        double expiresAt;
        boolean revoked;
        final List<Integer> children = new ArrayList<>();
    }

    @SuppressWarnings("unchecked")
    private static Object deepCopy(Object v) {
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) out.put(e.getKey(), deepCopy(e.getValue()));
            return out;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(deepCopy(x));
            return out;
        }
        return v;
    }

    /** The capability table of one sandbox. */
    public static final class HandleTable {
        private final List<Slot> slots = new ArrayList<>();
        private final String runtimeClass;
        private final Receipts.ReceiptLog log;
        private final Map<String, Executor> executors;
        private final DoubleSupplier now;

        public HandleTable(String runtimeClass, Receipts.ReceiptLog log, Map<String, Executor> executors, DoubleSupplier now) {
            this.runtimeClass = runtimeClass;
            this.log = log;
            this.executors = executors;
            this.now = now != null ? now : () -> (double) System.currentTimeMillis();
        }

        public String runtimeClass() { return runtimeClass; }

        public int size() { return slots.size(); }

        private Slot slot(long index) { return index >= 1 && index <= slots.size() ? slots.get((int) (index - 1)) : null; }

        private int push(Slot s) {
            slots.add(s);
            return slots.size();
        }

        /** Mint a handle for the operation {@code result} allowed. Throws (fail closed) if {@code result} does not allow exactly {@code operation}. */
        @SuppressWarnings("unchecked")
        public int mint(Authorize.AuthorizeResult result, Authorize.Operation operation, MintOptions opts) {
            if (opts.requires != null && !Receipts.satisfiesRuntimeClass(runtimeClass, opts.requires))
                throw new IllegalArgumentException("runtime_class_too_weak: table is " + runtimeClass + ", grant requires " + opts.requires);
            if (!Authorize.isAuthorizedFor(result, operation)) throw new IllegalArgumentException("not_authorized: result does not allow exactly this operation");
            Double u = JsVal.num(opts.uses == null ? Long.valueOf(1) : opts.uses);
            if (u == null || u.isNaN() || u.isInfinite() || u != Math.rint(u) || u < 1 || u > 1_000_000) throw new IllegalArgumentException("bad_uses");
            Slot s = new Slot();
            s.verb = operation.verb;
            s.resource = operation.resource;
            s.params = (Map<String, Object>) deepCopy(operation.params);
            s.paramsDigest = Pca.hashCanonical(s.params);
            s.opId = result.operation != null ? result.operation.id : "";
            s.uses = (long) (double) u;
            Double ex = opts.expiresAt == null ? null : JsVal.num(opts.expiresAt);
            s.expiresAt = ex == null ? Double.POSITIVE_INFINITY : ex;
            return push(s);
        }

        /** Derive a narrower handle: takes {@code uses} from the parent (never more than it has) and an expiry no later than the parent's. */
        @SuppressWarnings("unchecked")
        public int attenuate(long index, Object uses, Object expiresAt) {
            Slot p = live(index);
            if (p == null) throw new IllegalArgumentException("unknown_handle");
            Double u = JsVal.num(uses == null ? Long.valueOf(p.uses) : uses);
            if (u == null || u.isNaN() || u.isInfinite() || u != Math.rint(u) || u < 1 || u > p.uses) throw new IllegalArgumentException("attenuate_widens");
            Double ex = expiresAt == null ? Double.valueOf(p.expiresAt) : JsVal.num(expiresAt);
            if (ex == null || !(ex <= p.expiresAt)) throw new IllegalArgumentException("attenuate_widens");
            p.uses -= (long) (double) u;
            Slot c = new Slot();
            c.verb = p.verb;
            c.resource = p.resource;
            c.params = (Map<String, Object>) deepCopy(p.params);
            c.paramsDigest = p.paramsDigest;
            c.opId = p.opId;
            c.uses = (long) (double) u;
            c.expiresAt = ex;
            int child = push(c);
            p.children.add(child);
            return child;
        }

        /** Revoke a handle and, transitively, every handle derived from it. */
        public void revoke(long index) {
            Slot s = slot(index);
            if (s == null || s.revoked) return;
            s.revoked = true;
            for (int c : s.children) revoke(c);
        }

        /** The verb a handle carries, or null. */
        public String verbOf(long index) {
            Slot s = slot(index);
            return s == null ? null : s.verb;
        }

        /**
         * Use a handle: run the executor on the authorized operation and record a receipt. A use is consumed before the executor runs
         * and stays consumed if it throws (a failed side effect needs a new authorization, not a retry on the old one).
         */
        public UseResult use(long index) {
            Slot s = slot(index);
            if (s == null) {
                log.append(runtimeClass, body("", "", "", "", "refused", "unknown_handle"));
                return UseResult.fail("unknown_handle");
            }
            Slot live = live(index);
            if (live == null) return finish(s, UseResult.fail("spent"));
            Executor exec = executors.get(s.verb);
            if (exec == null) return finish(s, UseResult.fail("no_executor"));
            live.uses -= 1;
            try {
                byte[] result = exec.run(s.verb, s.resource, (Map<String, Object>) deepCopy(s.params));
                if (result == null) return finish(s, UseResult.fail("executor_error"));
                return finish(s, new UseResult(true, result, null));
            } catch (Exception e) {
                return finish(s, UseResult.fail("executor_error"));
            }
        }

        private UseResult finish(Slot s, UseResult r) {
            String outcome = r.ok ? "ok" : r.reason.equals("executor_error") ? "error" : "refused";
            log.append(runtimeClass, body(s.opId, s.verb, s.resource, s.paramsDigest, outcome, r.ok ? "used" : r.reason));
            return r;
        }

        private Slot live(long index) {
            Slot s = slot(index);
            if (s == null || s.revoked || s.uses <= 0) return null;
            double t = now.getAsDouble();
            return Double.isFinite(t) && t < s.expiresAt ? s : null; // a -Infinity clock is "before" every expiry
        }
    }

    private static Map<String, Object> body(String opId, String verb, String resource, String paramsDigest, String outcome, String reason) {
        Map<String, Object> subject = new LinkedHashMap<>();
        subject.put("op_id", opId);
        subject.put("verb", verb);
        subject.put("resource", resource);
        subject.put("params_digest", paramsDigest);
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("kind", "handle_use");
        b.put("subject", subject);
        b.put("outcome", outcome);
        b.put("reason", reason);
        return b;
    }
}
