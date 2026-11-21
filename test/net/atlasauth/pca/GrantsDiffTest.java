package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import net.atlasauth.pca.grants.Blueprints;
import net.atlasauth.pca.grants.Bundle;
import net.atlasauth.pca.grants.FreshAt;
import net.atlasauth.pca.grants.GrantHttp;
import net.atlasauth.pca.grants.GrantResource;
import net.atlasauth.pca.grants.LeaseHttp;
import net.atlasauth.pca.grants.Leases;
import net.atlasauth.pca.grants.ListAuthorized;
import net.atlasauth.pca.grants.Shadow;
import net.atlasauth.pca.grants.Sig;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle for the grants operational plane (see the oracle header for the case shapes and the porting table). */
class GrantsDiffTest {
    private static final String MODULE = "ref-grants";
    private static final long T0 = 1_800_000_000_000L;

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }
    private static long n(Object o) { return Long.parseLong(o.toString()); }
    private static Map<String, Object> obj(Object... kv) { Map<String, Object> r = new LinkedHashMap<>(); for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]); return r; }
    private static Object err(Throwable e) { return obj("$err", e instanceof GrantResource.GrantError ? ((GrantResource.GrantError) e).code : e instanceof ListAuthorized.ListError ? ((ListAuthorized.ListError) e).code : "x"); }
    private static Map<String, Object> copy(Map<String, Object> o) { return new LinkedHashMap<>(o); }

    private static final Map<String, Keys.EdKey> KEYS = new HashMap<>();

    /** The key of a label: seed = sha256("atlas-pca-conformance/" + label). */
    private static synchronized Keys.EdKey key(String label) throws Exception {
        Keys.EdKey k = KEYS.get(label);
        if (k == null) {
            k = Keys.edFromSeed(MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8)));
            KEYS.put(label, k);
        }
        return k;
    }

    private static String pub(String label) throws Exception { return key(label).id(); }

    /** Replace "$key:LABEL" strings and {"$sign": ...} objects, recursively. */
    @SuppressWarnings("unchecked")
    private static Object resolve(Object v) throws Exception {
        if (v instanceof String) return ((String) v).startsWith("$key:") ? pub(((String) v).substring(5)) : v;
        if (v instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<Object>) v) out.add(resolve(x)); return out; }
        if (v instanceof Map) {
            Map<String, Object> mm = (Map<String, Object>) v;
            if (mm.containsKey("$sign")) {
                Map<String, Object> s = m(mm.get("$sign"));
                Keys.EdKey k = key((String) s.get("label"));
                Map<String, Object> f = m(resolve(s.get("fields")));
                switch ((String) s.get("kind")) {
                    case "lease": return GrantSigning.signLease(k, f);
                    case "leaseOver": return GrantSigning.signLeaseUnsafeOverCap(k, f);
                    case "revocation": return GrantSigning.signLeaseRevocation(k, f);
                    case "blueprint": return GrantSigning.signBlueprint(k, f);
                    case "breakglass": return GrantSigning.signBreakGlass(k, f);
                    case "review": return GrantSigning.signBreakGlassReview(k, f);
                    default: throw new IllegalArgumentException("bad kind");
                }
            }
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : mm.entrySet()) out.put(e.getKey(), resolve(e.getValue()));
            return out;
        }
        return v;
    }

    // ---- pure signing ----

    @Test void signerOf() throws Exception { OracleCases.each(MODULE, "signerOf", a -> pub((String) a.get(0))); }
    @Test void signBody() throws Exception { OracleCases.each(MODULE, "signBody", a -> Sig.signBody((String) a.get(0), a.get(1), key((String) a.get(2)))); }
    @Test void verifyBody() throws Exception { OracleCases.each(MODULE, "verifyBody", a -> Sig.verifyBody((String) a.get(0), a.get(1), (String) a.get(2), a.get(3))); }
    @Test void signLease() throws Exception { OracleCases.each(MODULE, "signLease", a -> GrantSigning.signLease(key((String) a.get(0)), m(a.get(1)))); }
    @Test void signLeaseUnsafeOverCap() throws Exception { OracleCases.each(MODULE, "signLeaseUnsafeOverCap", a -> GrantSigning.signLeaseUnsafeOverCap(key((String) a.get(0)), m(a.get(1)))); }
    @Test void signLeaseRevocation() throws Exception { OracleCases.each(MODULE, "signLeaseRevocation", a -> GrantSigning.signLeaseRevocation(key((String) a.get(0)), m(a.get(1)))); }
    @Test void signBlueprint() throws Exception { OracleCases.each(MODULE, "signBlueprint", a -> GrantSigning.signBlueprint(key((String) a.get(0)), m(a.get(1)))); }
    @Test void signBreakGlass() throws Exception { OracleCases.each(MODULE, "signBreakGlass", a -> GrantSigning.signBreakGlass(key((String) a.get(0)), m(a.get(1)))); }
    @Test void signBreakGlassReview() throws Exception { OracleCases.each(MODULE, "signBreakGlassReview", a -> GrantSigning.signBreakGlassReview(key((String) a.get(0)), m(a.get(1)))); }

    // ---- bundles ----

    @Test void signBundle() throws Exception { OracleCases.each(MODULE, "signBundle", a -> Bundle.signBundle(m(a.get(0)), key((String) a.get(1)))); }
    @Test void assembleBundle() throws Exception { OracleCases.each(MODULE, "assembleBundle", a -> Bundle.assembleBundle(m(a.get(0)), l(a.get(1)))); }

    @Test void maskRecord() throws Exception {
        OracleCases.each(MODULE, "maskRecord", a -> {
            List<String> cl = new ArrayList<>();
            for (Object c : l(a.get(1))) cl.add((String) c);
            return Bundle.maskRecord(m(a.get(0)), cl);
        });
    }

    private static Object batchVerdict(K3.BatchVerdict v) { return v.ok ? obj("ok", true, "next", v.next, "lastCommit", v.lastCommit) : obj("ok", false, "reason", v.reason); }

    @Test void logScenario() throws Exception {
        OracleCases.each(MODULE, "logScenario", a -> {
            Map<String, Object> spec = m(a.get(0));
            Keys.EdKey k = key((String) spec.get("label"));
            List<String> mask = new ArrayList<>();
            if (spec.get("mask") != null) for (Object c : l(spec.get("mask"))) mask.add((String) c);
            Bundle.DecisionLog log = new Bundle.DecisionLog(k, mask);
            List<Object> recs = new ArrayList<>();
            for (Object r : l(spec.get("records"))) recs.add(log.append(m(r)));
            String signer = k.id();
            long now = n(spec.get("now"));
            Map<String, Object> head = log.head(now);
            Map<String, Object> out = obj("recs", recs, "head", head, "size", (long) log.size());
            List<Object> proofs = new ArrayList<>(), incl = new ArrayList<>(), batches = new ArrayList<>();
            List<Object> pi = spec.get("proofs") == null ? new ArrayList<>() : l(spec.get("proofs"));
            for (Object i : pi) {
                try { proofs.add(log.proof((int) n(i))); } catch (RuntimeException e) { proofs.add(obj("$err", true)); }
            }
            for (int j = 0; j < pi.size(); j++) {
                Object p = proofs.get(j);
                incl.add(m(p).containsKey("$err") ? obj("$err", true) : Bundle.verifyRecordInclusion(recs.get((int) n(pi.get(j))), p, head, signer));
            }
            List<Object> bs = spec.get("batches") == null ? new ArrayList<>() : l(spec.get("batches"));
            for (Object bo : bs) {
                Map<String, Object> b = m(bo);
                try {
                    Map<String, Object> bt = Bundle.nextBatch(log, b.get("from"), b.get("max"), spec.get("now"));
                    long from = n(b.get("from"));
                    String last = from == 0 ? "" : Bundle.recordCommit(recs.get((int) from - 1));
                    Map<String, Object> tampered = bt;
                    List<Object> brecs = l(bt.get("records"));
                    if (!brecs.isEmpty()) {
                        Map<String, Object> first = copy(m(brecs.get(0)));
                        first.put("at", 1L);
                        List<Object> tr = new ArrayList<>(brecs);
                        tr.set(0, first);
                        tampered = copy(bt);
                        tampered.put("records", tr);
                    }
                    batches.add(obj("bt", bt, "verdict", batchVerdict(Bundle.verifyBatch(bt, from, last, signer)), "tampered", batchVerdict(Bundle.verifyBatch(tampered, from, last, signer)),
                        "wrong", batchVerdict(Bundle.verifyBatch(bt, from, last, pub("zz")))));
                } catch (RuntimeException e) {
                    batches.add(obj("$err", true));
                }
            }
            out.put("proofs", proofs);
            out.put("incl", incl);
            out.put("batches", batches);
            return out;
        });
    }

    private static Function<Object, String> table(Object t) { return i -> (String) m(t).get(i); }

    @Test void replayScenario() throws Exception {
        OracleCases.each(MODULE, "replayScenario", a -> {
            Map<String, Object> spec = m(a.get(0));
            return obj("diff", Bundle.semanticDiff(l(spec.get("cases")), table(spec.get("oldT")), table(spec.get("newT"))),
                "audit", Bundle.auditReplay(l(spec.get("records")), l(spec.get("cases")), (i, rev) -> (String) m(spec.get("revT")).get(i + "@" + rev)));
        });
    }

    // ---- fresh_at ----

    @Test void mergeFreshAt() throws Exception { OracleCases.each(MODULE, "mergeFreshAt", a -> FreshAt.mergeFreshAt(m(a.get(0)), m(a.get(1)))); }

    private static Map<String, Object> verdict(K3.FreshVerdict v) {
        Map<String, Object> r = obj("decision", v.decision);
        if (v.code != null) r.put("code", v.code);
        if ("escalate".equals(v.decision)) r.put("behind", new ArrayList<Object>(v.behind));
        return r;
    }

    @Test void gateDecision() throws Exception {
        OracleCases.each(MODULE, "gateDecision", a -> {
            Map<String, Object> v = m(a.get(1));
            return FreshAt.gateDecision((String) a.get(0), new K3.FreshVerdict((String) v.get("decision"), (String) v.get("code"), new ArrayList<String>()));
        });
    }

    @Test void freshScenario() throws Exception {
        OracleCases.each(MODULE, "freshScenario", a -> {
            Map<String, Object> spec = m(a.get(0));
            FreshAt.Issuer iss = new FreshAt.Issuer(key((String) spec.get("label")), (String) spec.get("scope"), m(spec.get("init")));
            List<Object> out = new ArrayList<>();
            Map<String, Object> last = null;
            for (Object so : l(spec.get("steps"))) {
                Map<String, Object> s = m(so);
                try {
                    String op = (String) s.get("op");
                    if (op.equals("advance")) { last = iss.advance(m(s.get("patch")), n(s.get("now"))); out.add(last); }
                    else if (op.equals("check")) {
                        Object tok = "last".equals(s.get("token")) ? last : s.get("token");
                        Double max = s.get("maxAge") == null ? null : Double.valueOf(s.get("maxAge").toString());
                        out.add(verdict(iss.check(tok, n(s.get("now")), max)));
                    } else if (op.equals("current")) out.add(iss.current());
                    else if (op.equals("tamper")) {
                        Map<String, Object> t = copy(last);
                        t.put("policy_revision", n(last.get("policy_revision")) + 1);
                        out.add(verdict(iss.check(t, n(s.get("now")), null)));
                    }
                } catch (RuntimeException e) {
                    out.add(obj("$err", true));
                }
            }
            return out;
        });
    }

    // ---- shadow ----

    private static Function<Object, String> shadowFn(Object t) {
        return i -> {
            Object d = m(t).get(i);
            if ("throw".equals(d)) throw new IllegalStateException("boom");
            if ("junk".equals(d)) return "weird";
            return (String) d;
        };
    }

    @Test void shadowScenario() throws Exception {
        OracleCases.each(MODULE, "shadowScenario", a -> {
            Map<String, Object> spec = m(a.get(0));
            Shadow.ShadowLog log = new Shadow.ShadowLog(key((String) spec.get("label")));
            Map<String, Object> out = obj("runs", new ArrayList<Object>(), "diffs", new LinkedHashMap<String, Object>());
            for (Object oo : l(spec.get("obs"))) {
                Map<String, Object> ob = m(oo);
                List<Shadow.Candidate> cands = new ArrayList<>();
                for (Object co : l(spec.get("cands"))) cands.add(new Shadow.Candidate((String) m(co).get("digest"), shadowFn(m(co).get("T"))));
                Shadow.Run run = Shadow.runShadow(ob.get("input"), shadowFn(spec.get("enforcedT")), cands);
                List<Object> sh = new ArrayList<>();
                for (Shadow.Outcome oc : run.shadow) sh.add(oc.toMap());
                l(out.get("runs")).add(obj("decision", run.decision, "shadow", sh));
                for (Shadow.Outcome oc : run.shadow) log.observe((String) spec.get("enforcedDigest"), (String) ob.get("action_digest"), run.decision, oc, n(ob.get("at")));
            }
            Map<String, Object> stats = new LinkedHashMap<>();
            List<Object> flat = new ArrayList<>();
            for (Object co : l(spec.get("cands"))) {
                String d = (String) m(co).get("digest");
                stats.put(d, log.stats(d).toMap());
                List<Object> ds = new ArrayList<Object>(log.diffs(d));
                m(out.get("diffs")).put(d, ds);
                flat.addAll(ds);
            }
            out.put("stats", stats);
            List<Object> verify = new ArrayList<>();
            for (Object d : flat) {
                Map<String, Object> dm = m(d);
                Map<String, Object> badSig = copy(dm);
                badSig.put("sig", ((String) dm.get("sig")).substring(1) + "A");
                Map<String, Object> badAt = copy(dm);
                badAt.put("at", n(dm.get("at")) + 1);
                verify.add(new ArrayList<Object>(Arrays.asList(Shadow.verifyShadowDiff(d, log.signer()), Shadow.verifyShadowDiff(d, null), Shadow.verifyShadowDiff(d, pub("zz")),
                    Shadow.verifyShadowDiff(badSig, log.signer()), Shadow.verifyShadowDiff(badAt, null))));
            }
            out.put("verify", verify);
            out.put("signer", log.signer());
            Map<String, Object> g = spec.get("gate") == null ? null : m(spec.get("gate"));
            if (g != null) {
                List<Object> principals = new ArrayList<>();
                if (g.get("principals") != null) for (Object p : l(g.get("principals"))) principals.add(pub((String) p));
                List<Object> explanations = new ArrayList<>();
                if (g.get("explain") != null) for (Object eo : l(g.get("explain"))) {
                    Map<String, Object> e = m(eo);
                    explanations.add(Shadow.signWideningExplanation(key((String) e.get("label")), obj("shadow_digest", e.get("shadow_digest"), "action_digest", e.get("action_digest"), "reason_digest", e.get("reason_digest"))));
                }
                Map<String, Object> approval = null;
                if (g.get("approval") != null) {
                    Map<String, Object> ap = m(g.get("approval"));
                    approval = Shadow.signPromotionApproval(key((String) ap.get("label")), obj("shadow_digest", ap.get("shadow_digest"), "enforced_digest", ap.get("enforced_digest"), "at", ap.get("at")));
                }
                out.put("explanations", explanations);
                out.put("approval", approval);
                Map<String, Object> opts = g.get("options") == null ? new LinkedHashMap<String, Object>() : copy(m(g.get("options")));
                if (opts.get("principals") == null) opts.put("principals", principals);
                if (opts.get("explanations") == null) opts.put("explanations", explanations);
                if (approval != null) opts.put("approval", approval);
                Map<String, Object> gate = Shadow.promotionGate(log, opts);
                out.put("gate", gate);
                if (spec.get("promote") != null) {
                    Map<String, Object> pr = m(spec.get("promote"));
                    try {
                        Map<String, Object> usedGate = Boolean.FALSE.equals(pr.get("useGate")) ? obj("ok", false, "code", "bad_input", "reason", "x") : gate;
                        out.put("promoted", Shadow.promoteShadow(m(pr.get("enforced")), m(pr.get("candidate")), usedGate, pr.get("now")));
                    } catch (RuntimeException e) {
                        out.put("promoted", obj("$err", true));
                    }
                }
            }
            return out;
        });
    }

    // ---- list-authorized ----

    @Test void windowAcc() throws Exception {
        OracleCases.each(MODULE, "windowAcc", a -> {
            ListAuthorized.WindowReadAccumulator acc = new ListAuthorized.WindowReadAccumulator(n(a.get(0)), n(a.get(1)));
            List<Object> out = new ArrayList<>();
            for (Object o : l(a.get(2))) out.add(acc.charge((String) m(o).get("key"), n(m(o).get("units")), n(m(o).get("now"))));
            return out;
        });
    }

    private static ListAuthorized.CandidatePage pageOf(List<String> list, String cursor, int limit, Map<String, Object> spec) {
        int idx = cursor == null ? 0 : Integer.parseInt(cursor);
        int end = Math.min(idx + limit + (Boolean.TRUE.equals(spec.get("overfetch")) ? 3 : 0), list.size());
        List<String> objects = idx >= list.size() ? new ArrayList<String>() : new ArrayList<>(list.subList(idx, end));
        String next = idx + limit < list.size() ? String.valueOf(idx + limit) : Boolean.TRUE.equals(spec.get("emptyNext")) ? "" : null;
        return new ListAuthorized.CandidatePage(objects, next);
    }

    private static List<String> strs(Object o) { List<String> r = new ArrayList<>(); for (Object x : l(o)) r.add((String) x); return r; }

    @Test void listScenario() throws Exception {
        OracleCases.each(MODULE, "listScenario", a -> {
            Map<String, Object> spec = m(a.get(0));
            ListAuthorized.WindowReadAccumulator acc = new ListAuthorized.WindowReadAccumulator(n(spec.get("cap")), n(spec.get("windowMs")));
            List<String> universe = strs(spec.get("universe"));
            Map<String, Object> relSpec = spec.get("relation") == null ? null : m(spec.get("relation"));
            Set<String> allowed = new HashSet<>();
            if (relSpec != null) allowed.addAll(strs(relSpec.get("allowed")));
            boolean useList = relSpec != null && Boolean.TRUE.equals(relSpec.get("useList"));
            ListAuthorized.RelationSource rel = new ListAuthorized.RelationSource() {
                @Override public boolean check(String subject, String relation, String object) { return allowed.contains(object); }
                @Override public boolean supportsListObjects() { return useList; }
                @Override public ListAuthorized.CandidatePage listObjects(String subject, String relation, String type, String cursor, int limit) {
                    return pageOf(relSpec.get("listed") != null ? strs(relSpec.get("listed")) : universe, cursor, limit, spec);
                }
            };
            Set<String> permitted = spec.get("permitted") == null ? null : new HashSet<>(strs(spec.get("permitted")));
            Map<String, Object> tamper = spec.get("tamper") == null ? null : m(spec.get("tamper"));
            List<Object> out = new ArrayList<>();
            String cursor = null;
            for (long p = 0; p < n(spec.get("pages")); p++) {
                Map<String, Object> t = tamper != null && p == n(tamper.get("page")) ? tamper : null;
                try {
                    ListAuthorized.Args args = new ListAuthorized.Args();
                    args.candidates = relSpec != null && Boolean.TRUE.equals(relSpec.get("asCandidates"))
                        ? ListAuthorized.candidatesFromRelation(rel, (String) spec.get("subject"), (String) relSpec.get("name"))
                        : (type, cur, limit) -> pageOf(universe, cur, limit, spec);
                    args.subject = t != null && t.get("subject") != null ? (String) t.get("subject") : (String) spec.get("subject");
                    args.resourceType = (String) spec.get("type");
                    args.permits = x -> permitted == null || permitted.contains(x);
                    if (relSpec != null) {
                        args.relationSource = rel;
                        args.relation = t != null && t.get("relation") != null ? (String) t.get("relation") : (String) relSpec.get("name");
                    }
                    args.filterId = t != null && t.get("filterId") != null ? (String) t.get("filterId") : (String) spec.get("filterId");
                    args.policyDigest = (String) spec.get("policyDigest");
                    args.freshAtDigest = (String) spec.get("freshAt");
                    if (!(t != null && Boolean.TRUE.equals(t.get("dropCursor"))) && cursor != null) args.cursor = t != null && t.containsKey("cursor") ? (String) t.get("cursor") : cursor;
                    args.limit = t != null && t.get("limit") != null ? n(t.get("limit")) : n(spec.get("limit"));
                    args.reads = acc;
                    args.now = T0 + p * (spec.get("nowStep") == null ? 1 : n(spec.get("nowStep")));
                    args.signingSecret = key(t != null && t.get("label") != null ? (String) t.get("label") : (String) spec.get("label"));
                    if (spec.get("maxScan") != null) args.maxScan = n(spec.get("maxScan"));
                    ListAuthorized.Result r = ListAuthorized.listAuthorized(args);
                    out.add(r.toMap());
                    cursor = r.nextCursor;
                } catch (Exception e) {
                    out.add(err(e));
                    if (t == null) break;
                }
            }
            return out;
        });
    }

    // ---- grant management ----

    private static String sec(String by) { return by.equals("principal") ? "$P" : by.equals("holder") ? "$A" : "$X"; }

    private static final class Who { GrantHttp.Caller caller; }

    @Test void grantScenario() throws Exception {
        OracleCases.each(MODULE, "grantScenario", a -> {
            Map<String, Object> spec = m(a.get(0));
            GrantResource.MemoryGrantStore store = new GrantResource.MemoryGrantStore();
            List<Object> events = new ArrayList<>();
            long[] gc = {0}, nc = {0};
            GrantResource.Options o = new GrantResource.Options();
            o.store = store;
            o.now = () -> T0;
            o.newId = k -> k.equals("grant") ? "g_" + (++gc[0]) : "n_" + (++nc[0]);
            if (Boolean.TRUE.equals(spec.get("providers"))) {
                o.usage = g -> obj("rev", g.get("rev"));
                o.remainingBudget = g -> obj("left", 5L);
                o.residual = g -> obj("id", g.get("id"));
            }
            if (Boolean.TRUE.equals(spec.get("stepUp"))) o.verifyStepUp = (ref, g) -> ref.equals("ok-step");
            o.onRevoke = (ids, scope, root) -> events.add(obj("revoked", new ArrayList<Object>(ids), "scope", scope, "root", root.get("id")));
            o.onChange = (kind, g) -> events.add(obj("change", kind, "id", g.get("id"), "rev", g.get("rev")));
            if (Boolean.TRUE.equals(spec.get("validateNeed"))) o.validateNeed = nd -> "forbidden".equals(nd.get("verb")) ? "verb not allowed" : null;
            GrantResource.GrantService svc = new GrantResource.GrantService(o);
            Who who = new Who();
            GrantHttp.Handler handler = GrantHttp.grantResourceHandler(svc, req -> who.caller);
            List<Object> out = new ArrayList<>();
            for (Object raw : l(spec.get("steps"))) {
                Map<String, Object> s = m(resolve(raw));
                try {
                    Object r;
                    switch ((String) s.get("op")) {
                        case "register": r = svc.register(m(s.get("grant"))); break;
                        case "list": {
                            GrantResource.ListFilter f = new GrantResource.ListFilter();
                            Map<String, Object> fm = s.get("filter") == null ? new LinkedHashMap<String, Object>() : m(s.get("filter"));
                            f.principal = (String) fm.get("principal");
                            f.agent = (String) fm.get("agent");
                            f.status = (String) fm.get("status");
                            f.limit = fm.get("limit") == null ? null : n(fm.get("limit"));
                            f.cursor = (String) fm.get("cursor");
                            r = svc.list(f);
                            break;
                        }
                        case "inspect": r = svc.inspect((String) s.get("id")); break;
                        case "amend": {
                            Map<String, Object> g = svc.inspect((String) s.get("id"));
                            Map<String, Object> req = obj("action", s.get("action"), "authority", s.get("authority"));
                            if (!"none".equals(s.get("by"))) {
                                String by = (String) s.get("by");
                                req.put("signed_by", s.get("signed_by") != null ? s.get("signed_by") : by.equals("holder") ? "holder" : "principal");
                                if (GrantResource.authorityDigest(s.get("authority")) == null) throw new IllegalArgumentException("the reference's digest throws on this authority");
                                req.put("sig", Sig.signBody(GrantResource.GRANT_AMEND_DOMAIN, GrantResource.amendMessage(g, (String) s.get("action"), s.get("authority")), key(sec(by))));
                            }
                            if (s.get("stepUp") != null) req.put("step_up_ref", s.get("stepUp"));
                            r = svc.amend((String) s.get("id"), req);
                            break;
                        }
                        case "revoke": {
                            Map<String, Object> g = svc.inspect((String) s.get("id"));
                            String by = (String) s.get("by");
                            String scope = (String) s.get("scope");
                            if (by.equals("admin")) r = svc.revoke((String) s.get("id"), scope, null, true);
                            else if (by.equals("noauth")) r = svc.revoke((String) s.get("id"), scope, null, false);
                            else r = svc.revoke((String) s.get("id"), scope, Sig.signBody(GrantResource.GRANT_REVOKE_DOMAIN, GrantResource.grantRevokeMessage((String) g.get("id"), scope), key(sec(by))), false);
                            break;
                        }
                        case "needs": r = svc.requestNeeds((String) s.get("id"), s.get("needs")); break;
                        case "approve": {
                            String needId = (String) s.get("needId");
                            String nid = svc.needGrantId(needId);
                            Map<String, Object> g = svc.inspect(nid);
                            String sig = Sig.signBody(GrantResource.NEED_APPROVE_DOMAIN, GrantResource.needApproveMessage(obj("id", needId, "grant_id", nid), g.get("rev"), s.get("approved")), key(sec((String) s.get("by"))));
                            r = svc.approveNeeds(needId, s.get("approved"), sig, (String) s.get("stepUp"));
                            break;
                        }
                        case "deny": svc.denyNeeds((String) s.get("needId")); r = null; break;
                        case "http": {
                            Map<String, Object> w = s.get("who") == null ? null : m(s.get("who"));
                            who.caller = w == null ? null : new GrantHttp.Caller((String) w.get("principal"), Boolean.TRUE.equals(w.get("admin")));
                            Map<String, String> q = new LinkedHashMap<>();
                            if (s.get("query") != null) for (Map.Entry<String, Object> e : m(s.get("query")).entrySet()) q.put(e.getKey(), (String) e.getValue());
                            GrantHttp.Response res = handler.handle(new GrantHttp.Request((String) s.get("method"), (String) s.get("path"), q, s.get("body")));
                            Object body = res.body;
                            r = obj("status", (long) res.status, "body", body);
                            break;
                        }
                        default: throw new IllegalStateException("bad op");
                    }
                    out.add(r);
                } catch (RuntimeException e) {
                    out.add(err(e));
                }
            }
            List<Object> grants = new ArrayList<Object>(store.list());
            grants.sort((x, y) -> ((String) m(x).get("id")).compareTo((String) m(y).get("id")));
            return obj("steps", out, "events", events, "grants", grants);
        });
    }

    // ---- leases ----

    private static Map<String, Object> acceptMap(Lease.Accept r) {
        Map<String, Object> m = obj("ok", r.code == null);
        if (r.code == null) { m.put("replaced", r.replaced); m.put("seq", r.seq); } else { m.put("code", r.code); if (r.reason != null) m.put("reason", r.reason); }
        return m;
    }

    private static Map<String, Object> decisionMap(Lease.Decision d) {
        Map<String, Object> m = obj("decision", d.decision);
        if (d.code != null) m.put("code", d.code);
        if (d.leaseId != null) m.put("lease_id", d.leaseId);
        if (d.expiresAt != null) m.put("expires_at", d.expiresAt);
        return m;
    }

    @SuppressWarnings("unchecked")
    @Test void leaseScenario() throws Exception {
        OracleCases.each(MODULE, "leaseScenario", a -> {
            Map<String, Object> spec = m(a.get(0));
            Lease.Policy policy = new Lease.Policy(Arrays.asList(pub("auth")));
            if (spec.get("policy") != null) {
                Map<String, Object> pm = m(spec.get("policy"));
                if (pm.get("minApprovals") != null) policy.minApprovals = n(pm.get("minApprovals"));
                if (pm.get("eligibleApprovers") != null) policy.eligibleApprovers = strs(pm.get("eligibleApprovers"));
                if (pm.get("maxTtlCeiling") != null) policy.maxTtlCeiling = n(pm.get("maxTtlCeiling"));
            }
            Lease.Registry reg = new Lease.Registry(policy, new MemoryAtomicKv(), spec.get("shards") == null ? 4 : (int) n(spec.get("shards")), () -> T0);
            Who who = new Who();
            Map<String, Object>[] holder = new Map[1];
            GrantHttp.Handler[] handler = new GrantHttp.Handler[1];
            LeaseHttp.Caller[] lw = new LeaseHttp.Caller[1];
            handler[0] = LeaseHttp.leaseResourceHandler(reg, req -> lw[0], () -> T0);
            List<Object> out = new ArrayList<>();
            for (Object raw : l(spec.get("steps"))) {
                Map<String, Object> s = m(resolve(raw));
                try {
                    Object r;
                    switch ((String) s.get("op")) {
                        case "accept": r = acceptMap(reg.accept(s.get("lease"), s.get("chain") == null ? new ArrayList<String>() : (List<String>) (List<?>) l(s.get("chain")))); break;
                        case "revoke": {
                            Lease.Revoke rv = reg.revoke(s.get("rev"));
                            r = obj("ok", rv.code == null);
                            if (rv.code == null) m(r).put("revoked", (long) rv.revoked); else m(r).put("code", rv.code);
                            break;
                        }
                        case "get": r = reg.get((String) s.get("id")); break;
                        case "history": r = reg.history((String) s.get("id")); break;
                        case "shardRevs": r = reg.shardRevocations((int) n(s.get("i"))); break;
                        case "renew": {
                            Leases.RenewOptions ro = new Leases.RenewOptions();
                            ro.now = s.get("now");
                            ro.increment = s.get("increment");
                            ro.justificationDigest = (String) s.get("just");
                            if (s.get("approvers") != null) ro.approvers = l(s.get("approvers"));
                            if (s.get("vetoSeq") != null) { long vs = n(s.get("vetoSeq")); ro.veto = c -> n(c.get("seq")) >= vs; }
                            if (s.get("chain") != null) ro.chain = (List<String>) (List<?>) l(s.get("chain"));
                            Map<String, Object> rr = Leases.renewLease(key(s.get("label") == null ? "auth" : (String) s.get("label")), reg, (String) s.get("id"), ro);
                            r = Boolean.TRUE.equals(rr.get("ok")) ? rr : obj("ok", false, "code", rr.get("code"));
                            break;
                        }
                        case "check": r = decisionMap(reg.check(s.get("lease"), s.get("now"))); break;
                        case "http": {
                            Map<String, Object> w = s.get("who") == null ? null : m(s.get("who"));
                            lw[0] = w == null ? null : new LeaseHttp.Caller(Boolean.TRUE.equals(w.get("admin")), (String) w.get("principal"));
                            GrantHttp.Response res = handler[0].handle(new GrantHttp.Request((String) s.get("method"), (String) s.get("path"), null, s.get("body")));
                            Object rb = res.body;
                            r = obj("status", (long) res.status, "body", rb);
                            break;
                        }
                        default: throw new IllegalStateException("bad op");
                    }
                    out.add(r);
                } catch (RuntimeException e) {
                    out.add(err(e));
                }
            }
            return out;
        });
    }

    // ---- blueprints ----

    @Test void blueprintScenario() throws Exception {
        OracleCases.each(MODULE, "blueprintScenario", a -> {
            Map<String, Object> spec = m(a.get(0));
            Blueprint.Registry reg = new Blueprint.Registry(Arrays.asList(pub("op")), new MemoryAtomicKv());
            Blueprints.AdmissionRegistry adm = new Blueprints.AdmissionRegistry();
            List<Object> revoked = new ArrayList<>();
            Map<String, Object> init = obj("revocation_epoch", 0L, "ledger_tree_size", 0L, "budget_version", 0L, "policy_revision", 0L, "policy_digest", "pd");
            FreshAt.Issuer fresh = new FreshAt.Issuer(key("iss"), "scope", init);
            List<Object> out = new ArrayList<>();
            for (Object raw : l(spec.get("steps"))) {
                Map<String, Object> s = m(resolve(raw));
                try {
                    Object r;
                    switch ((String) s.get("op")) {
                        case "accept": { Blueprint.Accept ac = reg.accept(s.get("bp")); r = obj("ok", ac.code == null); if (ac.code == null) m(r).put("replaced", ac.replaced); else m(r).put("code", ac.code); break; }
                        case "epoch": r = reg.epoch(); break;
                        case "kill": {
                            Blueprints.IssuerRevoker rv = Boolean.TRUE.equals(s.get("revoker")) ? (value, reason, at) -> revoked.add(obj("kind", "issuer", "value", value, "reason", reason, "revokedAt", at)) : null;
                            r = Blueprints.groupKill(key(s.get("label") == null ? "op" : (String) s.get("label")), reg, (String) s.get("key"), n(s.get("now")), (String) s.get("reason"), rv, Boolean.TRUE.equals(s.get("fresh")) ? fresh : null);
                            break;
                        }
                        case "revoked": r = revoked; break;
                        case "admit": adm.admit((String) s.get("instance"), GrantSigning.blueprintGet(reg, (String) s.get("key")), n(s.get("until"))); r = true; break;
                        case "admitRevoke": r = adm.revoke((String) s.get("instance"), (String) s.get("key")); break;
                        case "admitCheck": r = adm.checker(n(s.get("now"))).admitted((String) s.get("instance"), GrantSigning.blueprintGet(reg, (String) s.get("key"))); break;
                        default: throw new IllegalStateException("bad op");
                    }
                    out.add(r);
                } catch (Exception e) {
                    out.add(err(e));
                }
            }
            return out;
        });
    }

    /** The reference adapter throws a TypeError. */
    static final class TypeError extends RuntimeException { TypeError(String m) { super(m); } }

    @Test void admitWithEvidence() throws Exception {
        OracleCases.each(MODULE, "admitWithEvidence", a -> {
            Object e = a.get(1);
            return Blueprints.admitWithEvidence(m(a.get(0)), () -> {
                if (e instanceof Map && m(e).containsKey("$throw")) throw new TypeError("boom");
                return e;
            });
        });
    }
}
