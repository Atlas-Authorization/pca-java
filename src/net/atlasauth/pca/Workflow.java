package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * Workflow (DAG) admission (K5, C-300..C-309): the verifier side of a signed workflow commitment and its step receipts. Total and
 * pure: everything unknown, malformed, unsigned, out of order or unplanned DENIES; only a pipelined step with an unconstrained
 * promise and a label marked "ask a human" ESCALATE. Integers only. Ports packages/pca/src/workflow.ts check for check and
 * replays packages/pca/conformance/workflow-vectors.json.
 */
public final class Workflow {
    private Workflow() {}

    public static final String WORKFLOW_DOMAIN = "atlas-pca/workflow/v1\u0000";
    public static final String WF_RECEIPT_DOMAIN = "atlas-pca/wf-receipt/v1\u0000";
    private static final String WF_REF = "atlas-pca/workflow-ref/v1";
    private static final String WR_REF = "atlas-pca/wf-receipt-ref/v1";
    private static final String VAL = "atlas-pca/wf-value/v1";

    // matches() is a full match; \z (not $) so no trailing-newline slack
    static final Pattern ID_RE = Pattern.compile("(?!__proto__\\z)[A-Za-z0-9_.:-]{1,64}");
    static final Pattern LABEL_RE = Pattern.compile("(?!__proto__\\z)[a-z0-9_.:-]{1,64}");
    static final Pattern NAME_RE = Pattern.compile("(?!__proto__\\z)[A-Za-z0-9_.-]{1,64}");
    static final Pattern UNIT_RE = Pattern.compile("[A-Za-z0-9_.:-]{1,16}");

    private static final List<String> STEP_KEYS = List.of("id", "verb", "resource", "params_digest", "deps", "sink", "deny_labels", "escalate_labels", "fresh_ms", "cost");
    private static final List<String> EDGE_KEYS = List.of("from", "to", "op", "unit", "deny_labels", "promise");
    private static final List<String> BODY_KEYS = List.of("v", "id", "principal", "goal_digest", "plan_root", "issued_at", "expires_at", "steps", "edges", "budget");
    private static final List<String> RECEIPT_KEYS = List.of("v", "wf", "step", "seq", "prev", "outcome", "params_digest", "outputs", "issued_at", "signer", "sig");
    private static final List<String> OPS = List.of("eq", "le", "ge", "lt", "gt");

    // ---- shared strict helpers (also used by ReadSide) ----

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }
    static boolean isObj(Object x) { return x instanceof Map; }
    static boolean isUint(Object n) { return Json.isSafeInt(n) && Json.asLong(n) >= 0; }
    static boolean isStr(Object x, int max) { return x instanceof String && ((String) x).length() >= 1 && ((String) x).length() <= max; }
    static boolean isB32(Object x) { return Pca.decodeB64uStrict(x, 32) != null; }
    static boolean re(Pattern p, Object x) { return x instanceof String && p.matcher((String) x).matches(); }
    static boolean isId(Object x) { return re(ID_RE, x); }
    static boolean isName(Object x) { return re(NAME_RE, x); }
    static boolean isUnit(Object x) { return re(UNIT_RE, x); }
    static boolean nullOr(Object x, Predicate<Object> ok) { return x == null || ok.test(x); }
    static boolean onlyKeys(Object o, List<String> keys) {
        if (!(o instanceof Map)) return false;
        Map<String, Object> mm = m(o);
        if (mm.size() != keys.size()) return false;
        for (String k : keys) if (!mm.containsKey(k)) return false;
        return true;
    }
    /** Strictly ascending (bytewise; all members are ASCII) with every member matching {@code p}. */
    static boolean sortedUnique(Object x, Pattern p, int max) {
        if (!(x instanceof List) || l(x).size() > max) return false;
        List<Object> xs = l(x);
        for (int i = 0; i < xs.size(); i++) {
            if (!re(p, xs.get(i))) return false;
            if (i > 0 && !(((String) xs.get(i - 1)).compareTo((String) xs.get(i)) < 0)) return false;
        }
        return true;
    }
    static boolean isScalar(Object v) { return v instanceof String || v instanceof Boolean || Json.isSafeInt(v); }
    static boolean isScalarMap(Object x) {
        if (!isObj(x) || m(x).size() > 32) return false;
        for (Map.Entry<String, Object> e : m(x).entrySet()) if (!isName(e.getKey()) || !isScalar(e.getValue())) return false;
        return true;
    }
    private static boolean uintMap(Object x, int max) {
        if (!isObj(x) || m(x).size() > max) return false;
        for (Map.Entry<String, Object> e : m(x).entrySet()) if (!isName(e.getKey()) || !isUint(e.getValue())) return false;
        return true;
    }
    /** True iff {@code sig} is a canonical 64-byte base64url Ed25519 signature by {@code signer} over {@code domain || canonical(body)}. */
    static boolean verifyBody(String domain, Object body, Object signer, Object sig) {
        return signer instanceof String && K3.verifyBody(domain, body, (String) signer, sig);
    }
    static List<String> strs(Object o) { List<String> out = new ArrayList<>(); for (Object x : l(o)) out.add((String) x); return out; }

    /** The digest of a scalar value as it appears in step receipts. */
    public static String valueDigest(Object v) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("d", VAL);
        d.put("v", v);
        return Pca.hashCanonical(d);
    }

    // ---- validation ----

    private static boolean validStep(Object o) {
        if (!isObj(o) || !onlyKeys(o, STEP_KEYS)) return false;
        Map<String, Object> s = m(o);
        return isId(s.get("id")) && isStr(s.get("verb"), 128) && isStr(s.get("resource"), 512) && nullOr(s.get("params_digest"), Workflow::isB32) && sortedUnique(s.get("deps"), ID_RE, 16)
            && nullOr(s.get("sink"), Workflow::isId) && sortedUnique(s.get("deny_labels"), LABEL_RE, 16) && sortedUnique(s.get("escalate_labels"), LABEL_RE, 16)
            && nullOr(s.get("fresh_ms"), Workflow::isUint) && uintMap(s.get("cost"), 8);
    }

    private static boolean validEdge(Object o) {
        if (!isObj(o) || !onlyKeys(o, EDGE_KEYS)) return false;
        Map<String, Object> e = m(o);
        Object f = e.get("from"), t = e.get("to");
        return isObj(f) && onlyKeys(f, List.of("step", "field")) && isId(m(f).get("step")) && isName(m(f).get("field"))
            && isObj(t) && onlyKeys(t, List.of("step", "param")) && isId(m(t).get("step")) && isName(m(t).get("param"))
            && e.get("op") instanceof String && OPS.contains(e.get("op")) && nullOr(e.get("unit"), Workflow::isUnit) && sortedUnique(e.get("deny_labels"), LABEL_RE, 16) && nullOr(e.get("promise"), Workflow::isId);
    }

    /** Shape of the body only (no signature, no DAG semantics). */
    public static boolean validWorkflowBody(Object o) {
        if (!isObj(o) || !onlyKeys(o, BODY_KEYS)) return false;
        Map<String, Object> b = m(o);
        if (!Json.isSafeInt(b.get("v")) || Json.asLong(b.get("v")) != 1) return false;
        if (!isId(b.get("id")) || !isB32(b.get("principal")) || !nullOr(b.get("goal_digest"), Workflow::isB32) || !nullOr(b.get("plan_root"), Workflow::isB32) || !isUint(b.get("issued_at")) || !isUint(b.get("expires_at"))) return false;
        if (!(b.get("steps") instanceof List) || l(b.get("steps")).isEmpty() || l(b.get("steps")).size() > 64) return false;
        for (Object s : l(b.get("steps"))) if (!validStep(s)) return false;
        if (!(b.get("edges") instanceof List) || l(b.get("edges")).size() > 256) return false;
        for (Object e : l(b.get("edges"))) if (!validEdge(e)) return false;
        Object bg = b.get("budget");
        if (!isObj(bg) || !onlyKeys(bg, List.of("max_steps", "caps")) || !isUint(m(bg).get("max_steps")) || !uintMap(m(bg).get("caps"), 8)) return false;
        // every cost name must be capped: an uncapped cost is a budget that silently does not exist
        for (Object s : l(b.get("steps"))) for (String k : m(m(s).get("cost")).keySet()) if (!m(m(bg).get("caps")).containsKey(k)) return false;
        return true;
    }

    /** DAG semantics: unique ids, deps exist, acyclic, every edge runs from a (transitive) dependency. Null when fine. */
    public static String dagError(Map<String, Object> b) {
        Set<String> ids = new HashSet<>();
        for (Object s : l(b.get("steps"))) if (!ids.add((String) m(s).get("id"))) return "duplicate step id";
        for (Object s : l(b.get("steps"))) for (Object d : l(m(s).get("deps"))) if (d.equals(m(s).get("id")) || !ids.contains(d)) return "bad dependency";
        Map<String, Set<String>> anc = ancestors(b);
        if (anc == null) return "cycle";
        for (Object eo : l(b.get("edges"))) {
            Map<String, Object> e = m(eo);
            String from = (String) m(e.get("from")).get("step"), to = (String) m(e.get("to")).get("step");
            if (!ids.contains(from) || !ids.contains(to) || !anc.get(to).contains(from)) return "edge does not follow a dependency";
        }
        return null;
    }

    /** step id -> the set of its transitive dependencies; null on a cycle. */
    public static Map<String, Set<String>> ancestors(Map<String, Object> b) {
        Map<String, Map<String, Object>> byId = new HashMap<>();
        for (Object s : l(b.get("steps"))) byId.put((String) m(s).get("id"), m(s));
        Map<String, Set<String>> out = new HashMap<>();
        Map<String, Integer> state = new HashMap<>();
        for (Object s : l(b.get("steps"))) if (!visit((String) m(s).get("id"), byId, out, state)) return null;
        return out;
    }

    private static boolean visit(String id, Map<String, Map<String, Object>> byId, Map<String, Set<String>> out, Map<String, Integer> state) {
        Integer st = state.get(id);
        if (st != null && st == 2) return true;
        if (st != null && st == 1) return false;
        state.put(id, 1);
        Set<String> set = new HashSet<>();
        for (Object d : l(byId.get(id).get("deps"))) {
            if (!visit((String) d, byId, out, state)) return false;
            set.add((String) d);
            set.addAll(out.get(d));
        }
        out.put(id, set);
        state.put(id, 2);
        return true;
    }

    // ---- commitment and receipts ----

    public static String workflowDigest(Object body) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("d", WF_REF);
        d.put("w", body);
        return Pca.hashCanonical(d);
    }

    public static String receiptRef(Object r) {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("d", WR_REF);
        d.put("r", r);
        return Pca.hashCanonical(d);
    }

    private static Map<String, Object> recBody(Map<String, Object> r) {
        Map<String, Object> b = new LinkedHashMap<>();
        for (String k : new String[] {"v", "wf", "step", "seq", "prev", "outcome", "params_digest", "outputs", "issued_at", "signer"}) b.put(k, r.get(k));
        return b;
    }

    private static boolean validReceiptShape(Object o) {
        if (!isObj(o) || !onlyKeys(o, RECEIPT_KEYS)) return false;
        Map<String, Object> r = m(o);
        if (!Json.isSafeInt(r.get("v")) || Json.asLong(r.get("v")) != 1) return false;
        if (!isB32(r.get("wf")) || !isId(r.get("step")) || !isUint(r.get("seq")) || !nullOr(r.get("prev"), Workflow::isB32) || (isUint(r.get("seq")) && (Json.asLong(r.get("seq")) == 0) != (r.get("prev") == null))) return false;
        Object oc = r.get("outcome");
        if (!"ok".equals(oc) && !"failed".equals(oc)) return false;
        if (!isB32(r.get("params_digest")) || !isUint(r.get("issued_at")) || !isB32(r.get("signer")) || !(r.get("sig") instanceof String)) return false;
        Object outs = r.get("outputs");
        if (!isObj(outs) || m(outs).size() > 32) return false;
        for (Map.Entry<String, Object> e : m(outs).entrySet()) {
            Object v = e.getValue();
            if (!isName(e.getKey()) || !isObj(v) || !onlyKeys(v, List.of("digest", "num", "unit", "labels"))) return false;
            Map<String, Object> vm = m(v);
            if (!isB32(vm.get("digest")) || !nullOr(vm.get("num"), Workflow::isUint) || !nullOr(vm.get("unit"), Workflow::isUnit) || !sortedUnique(vm.get("labels"), LABEL_RE, 16)) return false;
        }
        return true;
    }

    // ---- admission ----

    /** Result of an admission. {@code at} and {@code pending} as in the reference (at is the offending receipt / edge index). */
    public static final class Result {
        public final String decision, code, step;
        public final Integer at;
        public final List<Integer> pending;
        Result(String decision, String code, String step, Integer at, List<Integer> pending) { this.decision = decision; this.code = code; this.step = step; this.at = at; this.pending = pending; }
        public Map<String, Object> toMap() {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("decision", decision);
            o.put("code", code);
            o.put("step", step);
            o.put("at", at == null ? null : (Object) at.longValue());
            List<Object> p = new ArrayList<>();
            for (Integer i : pending) p.add(i.longValue());
            o.put("pending", p);
            return o;
        }
    }

    private static Result res(String decision, String code, String step, Integer at, List<Integer> pending) { return new Result(decision, code, step, at, pending); }
    private static Result deny(String code, String step) { return res("deny", code, step, null, List.of()); }
    private static Result deny(String code, String step, int at) { return res("deny", code, step, at, List.of()); }

    /** Is {@code root} the Merkle plan root this signed, unexpired, pinned-principal workflow authorizes? */
    public static boolean planRootAuthorized(Object workflow, Object principal, Object now, Object root) {
        try {
            if (!isObj(workflow)) return false;
            Object body = m(workflow).get("body");
            if (!validWorkflowBody(body) || !isUint(now) || !(principal instanceof String)) return false;
            Map<String, Object> b = m(body);
            long n = Json.asLong(now);
            return dagError(b) == null && principal.equals(b.get("principal")) && verifyBody(WORKFLOW_DOMAIN, b, principal, m(workflow).get("sig"))
                && n >= Json.asLong(b.get("issued_at")) && n < Json.asLong(b.get("expires_at")) && Objects.equals(b.get("plan_root"), root);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean validRequest(Object o) {
        if (!isObj(o) || !onlyKeys(o, List.of("step", "verb", "resource", "params", "units", "goal_digest", "plan_root"))) return false;
        Map<String, Object> r = m(o);
        if (!isId(r.get("step")) || !isStr(r.get("verb"), 128) || !isStr(r.get("resource"), 512) || !isScalarMap(r.get("params")) || !isObj(r.get("units"))) return false;
        for (Map.Entry<String, Object> e : m(r.get("units")).entrySet()) if (!isName(e.getKey()) || !isUnit(e.getValue())) return false;
        return nullOr(r.get("goal_digest"), Workflow::isB32) && nullOr(r.get("plan_root"), Workflow::isB32);
    }

    /** Check the receipt chain against the workflow. Returns the offending index, or -1. */
    private static int receiptError(Map<String, Object> w, String rsSigner, List<Object> receipts, long now) {
        String wd = workflowDigest(w);
        Map<String, Map<String, Object>> byId = new HashMap<>();
        for (Object s : l(w.get("steps"))) byId.put((String) m(s).get("id"), m(s));
        Set<String> index = new HashSet<>();
        Map<String, Object> prev = null;
        for (int i = 0; i < receipts.size(); i++) {
            Object ro = receipts.get(i);
            if (!validReceiptShape(ro)) return i;
            Map<String, Object> r = m(ro);
            if (!rsSigner.equals(r.get("signer")) || !wd.equals(r.get("wf")) || Json.asLong(r.get("seq")) != i || Json.asLong(r.get("issued_at")) > now) return i;
            String step = (String) r.get("step");
            if (!byId.containsKey(step) || index.contains(step)) return i;
            if ((prev == null ? r.get("prev") != null : !receiptRef(prev).equals(r.get("prev"))) || !verifyBody(WF_RECEIPT_DOMAIN, recBody(r), rsSigner, r.get("sig"))) return i;
            // a receipt may precede one of its dependencies' receipts only when every edge from that dependency is a declared promise
            for (Object d : l(byId.get(step).get("deps"))) {
                if (index.contains(d)) continue;
                boolean any = false, unpromised = false;
                for (Object eo : l(w.get("edges"))) {
                    Map<String, Object> e = m(eo);
                    if (d.equals(m(e.get("from")).get("step")) && step.equals(m(e.get("to")).get("step"))) { any = true; if (e.get("promise") == null) unpromised = true; }
                }
                if (!any || unpromised) return i;
            }
            index.add(step);
            prev = r;
        }
        return -1;
    }

    private static Result evaluate(Object workflow, Object principal, Object rsSignerO, Object receiptsO, Object nowO, Object request, boolean bind) {
        if (!isObj(workflow) || !onlyKeys(workflow, List.of("body", "sig")) || !validWorkflowBody(m(workflow).get("body")) || !validRequest(request) || !(receiptsO instanceof List)
            || !isB32(principal) || !isB32(rsSignerO) || !isUint(nowO)) return deny("bad_workflow", null);
        Map<String, Object> w = m(m(workflow).get("body"));
        Map<String, Object> q = m(request);
        String qstep = (String) q.get("step");
        long now = Json.asLong(nowO);
        List<Object> receipts = l(receiptsO);
        if (dagError(w) != null) return deny("bad_dag", qstep);
        if (!principal.equals(w.get("principal")) || !verifyBody(WORKFLOW_DOMAIN, w, principal, m(workflow).get("sig"))) return deny("bad_signature", qstep);
        if (now < Json.asLong(w.get("issued_at"))) return deny("not_yet", qstep);
        if (now >= Json.asLong(w.get("expires_at"))) return deny("expired", qstep);
        if (!Objects.equals(q.get("goal_digest"), w.get("goal_digest"))) return deny("goal_mismatch", qstep);
        if (!Objects.equals(q.get("plan_root"), w.get("plan_root"))) return deny("plan_root_mismatch", qstep);
        int bad = receiptError(w, (String) rsSignerO, receipts, now);
        if (bad >= 0) return deny("bad_receipt", qstep, bad);
        Map<String, Map<String, Object>> rec = new HashMap<>();
        for (Object r : receipts) rec.put((String) m(r).get("step"), m(r));
        Map<String, Object> step = null;
        Map<String, Map<String, Object>> stepById = new HashMap<>();
        for (Object s : l(w.get("steps"))) { stepById.put((String) m(s).get("id"), m(s)); if (step == null && qstep.equals(m(s).get("id"))) step = m(s); }
        if (step == null) return deny("unplanned_step", qstep);
        if (!step.get("verb").equals(q.get("verb")) || !step.get("resource").equals(q.get("resource"))) return deny("step_mismatch", qstep);
        Map<String, Object> params = m(q.get("params")), units = m(q.get("units"));
        String pd = Pca.hashCanonical(params);
        if (step.get("params_digest") != null && !step.get("params_digest").equals(pd)) return deny("params_mismatch", qstep);
        String sid = (String) step.get("id");
        Map<String, Object> mine = rec.get(sid);
        if (bind) {
            if (mine == null || !pd.equals(mine.get("params_digest"))) return deny("params_mismatch", qstep);
        } else {
            if (mine != null) return deny("already_done", qstep);
            Map<String, Object> bg = m(w.get("budget"));
            if (receipts.size() + 1 > Json.asLong(bg.get("max_steps"))) return deny("budget_exceeded", qstep);
            for (Map.Entry<String, Object> cap : m(bg.get("caps")).entrySet()) {
                long spent = 0;
                for (Object r : receipts) { Object c = m(stepById.get((String) m(r).get("step")).get("cost")).get(cap.getKey()); if (c != null) spent += Json.asLong(c); }
                Object mc = m(step.get("cost")).get(cap.getKey());
                if (mc != null) spent += Json.asLong(mc);
                if (spent > Json.asLong(cap.getValue())) return deny("budget_exceeded", qstep);
            }
        }
        // dependencies
        List<Integer> pending = new ArrayList<>();
        boolean unconstrained = false;
        List<Object> edges = l(w.get("edges"));
        for (Object d : l(step.get("deps"))) {
            Map<String, Object> dr = rec.get(d);
            if (dr == null) {
                boolean any = false, unpromised = false;
                for (Object eo : edges) {
                    Map<String, Object> e = m(eo);
                    if (d.equals(m(e.get("from")).get("step")) && sid.equals(m(e.get("to")).get("step"))) { any = true; if (e.get("promise") == null) unpromised = true; }
                }
                if (bind || !any) return deny("deps_unmet", qstep);
                if (unpromised) unconstrained = true;
                continue;
            }
            if (!"ok".equals(dr.get("outcome"))) return deny("dep_failed", qstep);
            if (step.get("fresh_ms") != null && now - Json.asLong(dr.get("issued_at")) > Json.asLong(step.get("fresh_ms"))) return deny("stale_dep", qstep);
        }
        // edge constraints
        for (int i = 0; i < edges.size(); i++) {
            Map<String, Object> e = m(edges.get(i));
            if (!sid.equals(m(e.get("to")).get("step"))) continue;
            Map<String, Object> src = rec.get((String) m(e.get("from")).get("step"));
            if (src == null) { pending.add(i); continue; }
            Object out = m(src.get("outputs")).get(m(e.get("from")).get("field"));
            String param = (String) m(e.get("to")).get("param");
            Object val = params.get(param);
            if (out == null || val == null) return deny("edge_missing", qstep, i);
            Map<String, Object> om = m(out);
            if (!Objects.equals(om.get("unit"), units.get(param)) || !Objects.equals(om.get("unit"), e.get("unit"))) return deny("edge_unit", qstep, i);
            String op = (String) e.get("op");
            if (op.equals("eq")) {
                if (!valueDigest(val).equals(om.get("digest"))) return deny("edge_digest", qstep, i);
            } else {
                if (!Json.isSafeInt(val) || om.get("num") == null) return deny("edge_value", qstep, i);
                long v = Json.asLong(val), n = Json.asLong(om.get("num"));
                boolean ok = op.equals("le") ? v <= n : op.equals("ge") ? v >= n : op.equals("lt") ? v < n : v > n;
                if (!ok) return deny("edge_relation", qstep, i);
            }
            for (Object lab : l(om.get("labels"))) if (l(e.get("deny_labels")).contains(lab)) return deny("taint_flow", qstep, i);
        }
        if (bind && !pending.isEmpty()) return deny("deps_unmet", qstep);
        // taint across the DAG: every label any executed ancestor produced
        Set<String> inherited = new HashSet<>();
        for (String a : ancestors(w).get(sid)) {
            Map<String, Object> r = rec.get(a);
            if (r == null) continue;
            for (Object o : m(r.get("outputs")).values()) inherited.addAll(strs(m(o).get("labels")));
        }
        if (anyIn(step.get("deny_labels"), inherited)) return deny("taint_flow", qstep);
        if (unconstrained) return res("escalate", "pipeline_unconstrained", qstep, null, List.of());
        if (anyIn(step.get("escalate_labels"), inherited)) return res("escalate", "taint_escalate", qstep, null, List.of());
        return res("allow", null, qstep, null, pending);
    }

    private static boolean anyIn(Object labels, Collection<String> set) {
        for (Object x : l(labels)) if (set.contains(x)) return true;
        return false;
    }

    /** Admit ONE step of the committed workflow, or deny / escalate. Never throws. {@code rsSigner} is the verifier-pinned receipt signer. */
    public static Result admitStep(Object workflow, Object principal, Object rsSigner, Object receipts, Object now, Object request) {
        try {
            return evaluate(workflow, principal, rsSigner, receipts, now, request, false);
        } catch (Exception e) {
            return deny("bad_workflow", null);
        }
    }

    /** Promise binding (post hoc): the step already has its receipt; its params are re-checked against every edge. Never throws. */
    public static Result bindPromises(Object workflow, Object principal, Object rsSigner, Object receipts, Object now, Object request) {
        try {
            return evaluate(workflow, principal, rsSigner, receipts, now, request, true);
        } catch (Exception e) {
            return deny("bad_workflow", null);
        }
    }
}
