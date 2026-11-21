package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.connect.ReplayGuard;
import net.atlasauth.pca.dataflow.Detectors;
import org.junit.jupiter.api.Test;

/** Small public helpers of the core package against the reference corpus (cheap claims, goal commitment, discharge requests, detector fold, replay-guard options, ...). */
public class SmallSurfaceDiffTest {
    private static final String MOD = "ref-core-small-surface";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return o instanceof List ? (List<Object>) o : null; }

    private static String s(Object o) { return o instanceof String ? (String) o : null; }

    @Test void pcactnCheapClaims() throws Exception {
        OracleCases.each(MOD, "pcactnCheapClaims", a -> Pca.pcactnCheapClaims(m(a.get(0)), s(a.get(1)), OracleCases.num(a.get(2))));
    }

    @Test void goalCommit() throws Exception {
        OracleCases.each(MOD, "goalCommitOf", a -> Issue.goalCommit(s(a.get(0)), s(a.get(1))));
        OracleCases.each(MOD, "verifyGoalCommit", a -> Issue.verifyGoalCommit(s(a.get(0)), s(a.get(1)), s(a.get(2))));
    }

    @Test void dischargeRequests() throws Exception {
        OracleCases.each(MOD, "dischargeRequests", a -> CaveatLang.dischargeRequests(a.get(0), a.get(1), s(a.get(2))));
    }

    @Test void namedUnmetLimitReason() throws Exception {
        OracleCases.each(MOD, "namedUnmetLimitReason", a -> Predicates.namedUnmetLimitReason(a.get(0), m(a.get(1))));
    }

    @Test void reversibilityAndContext() throws Exception {
        OracleCases.each(MOD, "resolveReversibilityClass", a -> Authorize.resolveReversibilityClass(m(a.get(0)), l(a.get(1)), s(a.get(2))));
        OracleCases.each(MOD, "agentCaveatContext", a -> {
            return Authorize.agentCaveatContext(m(a.get(0)), m(a.get(1)));
        });
    }

    @Test void thresholdAndPredicates() throws Exception {
        OracleCases.each(MOD, "assembleThreshold", a -> Threshold.assembleThreshold(a.get(0)));
        OracleCases.each(MOD, "isBudgetAllocCaveat", a -> Pca.isBudgetAllocCaveat(a.get(0)));
        OracleCases.each(MOD, "meetAll", a -> {
            List<String> ds = new ArrayList<>();
            for (Object d : l(a.get(0))) ds.add((String) d);
            return Decision.meetAll(ds);
        });
        OracleCases.each(MOD, "escalateThreshold", a -> {
            Map<String, Object> rt = m(a.get(0));
            Risk.Required r = Risk.escalateThreshold(new Risk.Required((int) Json.asLong(rt.get("t")), (String) rt.get("proof"), Boolean.TRUE.equals(rt.get("optimisticAllowed"))), (int) Json.asLong(a.get(1)));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("t", (long) r.t);
            out.put("proof", r.proof);
            out.put("optimisticAllowed", r.optimisticAllowed);
            return out;
        });
    }

    @Test void detectorReceipts() throws Exception {
        OracleCases.each(MOD, "detectorReceiptShapeError", a -> Detectors.detectorReceiptShapeError(a.get(0)));
        OracleCases.each(MOD, "detectorReceiptRef", a -> Detectors.detectorReceiptRef(a.get(0)));
        OracleCases.each(MOD, "detectorPolicyError", a -> Detectors.detectorPolicyError(a.get(0)));
        OracleCases.each(MOD, "detectorSignal", a -> Detectors.detectorSignal(m(a.get(0))));
    }

    @Test void replayGuardOptions() throws Exception {
        OracleCases.each(MOD, "guardSeq", a -> {
            Map<String, Object> o = m(a.get(0));
            ReplayGuard.Options opts = new ReplayGuard.Options();
            if (o.get("clockSkewMs") != null) opts.clockSkewMs = OracleCases.num(o.get("clockSkewMs"));
            if (o.get("requireNonce") != null) opts.requireNonce = Boolean.TRUE.equals(o.get("requireNonce"));
            opts.counters = Boolean.TRUE.equals(o.get("counters"));
            MemoryStateStore store = new MemoryStateStore();
            List<Object> out = new ArrayList<>();
            for (Object st : l(a.get(1))) {
                ReplayGuard.Verdict v = ReplayGuard.guard(store, m(st).get("p"), s(o.get("aud")), Json.asLong(m(st).get("now")), opts);
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("ok", v.ok);
                if (!v.ok) { r.put("code", v.code); r.put("reason", v.reason); }
                out.add(r);
            }
            return out;
        });
    }

    @Test void workflowAndObligations() throws Exception {
        OracleCases.each(MOD, "workflowCommitmentError", a -> Workflow.workflowCommitmentError(a.get(0), a.get(1), a.get(2)));
        OracleCases.each(MOD, "workflowReceiptError", a -> {
            Integer at = Workflow.workflowReceiptError(m(a.get(0)), s(a.get(1)), l(a.get(2)), Json.asLong(a.get(3)));
            return at == null ? null : (Object) at.longValue();
        });
        OracleCases.each(MOD, "collectObligations", a -> {
            Obligations.Merge r = Obligations.collectObligations(a.get(0), m(a.get(1)));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", r.ok);
            if (r.ok) out.put("obligations", r.obligations); else out.put("reason", r.reason);
            return out;
        });
    }

    @Test void cheapChainAndHolderKey() throws Exception {
        OracleCases.each(MOD, "verifyChainCheap", a -> {
            List<String> allowed = null;
            if (a.get(2) instanceof List) { allowed = new ArrayList<>(); for (Object x : l(a.get(2))) allowed.add((String) x); }
            Pca.CheapChain r = Pca.verifyChainCheap(l(a.get(0)), s(a.get(1)), a.get(1) != null, allowed);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ok", r.ok);
            if (r.ok) out.put("pqHops", (long) r.pqHops); else out.put("reason", r.reason);
            return out;
        });
        OracleCases.each(MOD, "holderPqKey", a -> {
            Pq.PinnedPq k = Pca.holderPqKey(a.get(0), s(a.get(1)), a.get(2), s(a.get(3)));
            return k == null ? null : k.b64u();
        });
    }

    @Test void discovery() throws Exception {
        OracleCases.each(MOD, "parseDiscoveryDocument", a -> Discovery.parseDiscoveryDocument(a.get(0)));
        OracleCases.each(MOD, "parseDiscoveryIntent", a -> Discovery.parseDiscoveryIntent(a.get(0)));
        OracleCases.each(MOD, "acceptsSuite", a -> Discovery.acceptsSuite(m(a.get(0)), s(a.get(1))));
        OracleCases.each(MOD, "buildDiscoveryDocument", a -> Discovery.buildDiscoveryDocument(m(a.get(0))));
        OracleCases.each(MOD, "fetchDiscovery", a -> {
            String mode = s(a.get(1));
            List<Object> urls = new ArrayList<>();
            Discovery.Fetch f = (url, headers) -> {
                urls.add(url + "|" + headers.get("accept"));
                if (mode.equals("throw")) throw new IllegalStateException("boom");
                Object body = mode.equals("bad") ? Json.parse("{\"nope\":1}")
                    : Json.parse("{\"audience\":\"https://rs.example\",\"pca_versions\":[2],\"signature_suites\":[\"ed25519\",\"ml-dsa-65\"],\"action_header\":\"PCA-Action\"}");
                return new Discovery.Reply(!mode.equals("500"), mode.equals("500") ? 500 : 200, body);
            };
            Map<String, Object> out = new LinkedHashMap<>();
            try {
                out.put("doc", Discovery.fetchDiscovery(s(a.get(0)), f));
            } catch (Exception e) {
                out.put("error", true);
            }
            out.put("urls", urls);
            return out;
        });
    }

    @Test void revocation() throws Exception {
        OracleCases.each(MOD, "verifyMembership", a -> RevocationStaleness.verifyMembership(s(a.get(0)), m(a.get(1)), s(a.get(2))));
        OracleCases.each(MOD, "validateRevocationStaleness", a -> {
            Map<String, Object> r = new LinkedHashMap<>();
            try { RevocationStaleness.validateRevocationStaleness(a.get(0)); r.put("ok", true); } catch (IllegalArgumentException e) { r.put("ok", false); }
            return r;
        });
    }

    private static boolean canonical(Object token, int parts, int max, boolean json) {
        try {
            net.atlasauth.pca.oauth.Jws.assertCanonicalCompactJws(token, parts, max, json);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    @Test void canonicalJws() throws Exception {
        OracleCases.each(MOD, "isCanonicalCompactJws", a -> net.atlasauth.pca.oauth.Jws.isCanonicalCompactJws(a.get(0)));
        OracleCases.each(MOD, "isCanonicalCompactJwsOpaque", a -> canonical(a.get(0), 3, net.atlasauth.pca.oauth.Jws.DEFAULT_MAX_JWS_BYTES, false));
        OracleCases.each(MOD, "isCanonicalCompactJwsMax", a -> canonical(a.get(0), 3, 40, true));
        OracleCases.each(MOD, "isCanonicalCompactJwsFive", a -> canonical(a.get(0), 5, net.atlasauth.pca.oauth.Jws.DEFAULT_MAX_JWS_BYTES, true));
        OracleCases.each(MOD, "assertCanonicalJwsSegments", a -> {
            Map<String, Object> r = new LinkedHashMap<>();
            try {
                r.put("header", net.atlasauth.pca.oauth.Jws.assertCanonicalJwsSegments(a.get(0), a.get(1)));
                r.put("ok", true);
            } catch (RuntimeException e) {
                r.clear();
                r.put("ok", false);
            }
            return r;
        });
        // the strict parser's refusals are typed and carry the offset
        Json.StrictJsonError e = org.junit.jupiter.api.Assertions.assertThrows(Json.StrictJsonError.class, () -> Json.parse("{\"a\":1,\"a\":2}"));
        org.junit.jupiter.api.Assertions.assertTrue(e.offset > 0 && e.getMessage().startsWith("duplicate key"));
    }

    private static Keys.SuiteKey seedKey(String label) throws Exception {
        byte[] seed = java.security.MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/small/tpl/" + label).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return Keys.ed25519(Keys.edFromSeed(seed));
    }

    @SuppressWarnings("unchecked")
    @Test void policyTemplatesAndLinks() throws Exception {
        OracleCases.each(MOD, "listTemplates", a -> {
            List<Object> out = new ArrayList<>();
            for (PolicyTemplates.PolicyTemplate t : PolicyTemplates.listTemplates()) {
                Map<String, Object> o = new LinkedHashMap<>();
                o.put("name", t.name);
                o.put("description", t.description);
                o.put("permissions", t.permissions);
                if (t.limits != null) o.put("limits", t.limits);
                if (t.riskPolicy != null) o.put("riskPolicy", t.riskPolicy);
                out.add(o);
            }
            return out;
        });
        OracleCases.each(MOD, "fromTemplate", a -> {
            Map<String, Object> r = new LinkedHashMap<>();
            try {
                PolicyTemplates.FromTemplateOptions o = new PolicyTemplates.FromTemplateOptions(seedKey("p"), "g");
                o.holder = seedKey("h");
                o.now = 1_700_000_000_000L;
                Map<String, Object> ov = m(a.get(1));
                if (ov != null) {
                    o.permissions = m(ov.get("permissions")); o.limits = m(ov.get("limits")); o.riskPolicy = m(ov.get("riskPolicy"));
                    if (ov.get("budgetModel") != null) o.budgetModel = s(ov.get("budgetModel"));
                }
                Facade.Handle h = PolicyTemplates.fromTemplate(s(a.get(0)), o);
                r.put("ok", true);
                r.put("predicates", h.policy.predicates);
                r.put("caveats", h.policy.caveats);
                r.put("riskPolicy", h.policy.riskPolicy);
                r.put("budgetModel", h.policy.budgetModel);
            } catch (IllegalArgumentException e) {
                r.clear();
                r.put("ok", false);
            }
            return r;
        });
        OracleCases.each(MOD, "policyBuilder", a -> {
            Map<String, Object> r = new LinkedHashMap<>();
            try {
                PolicyTemplates.PolicyBuilder b = PolicyTemplates.policy();
                for (Object op0 : l(a.get(0))) {
                    List<Object> op = l(op0);
                    String name = (String) op.get(0);
                    if (name.equals("from")) b = PolicyTemplates.PolicyBuilder.from(s(op.get(1)));
                    else if (name.equals("allow")) { List<String> acts = new ArrayList<>(); for (Object x : l(op.get(2))) acts.add((String) x); b.allow(s(op.get(1)), acts); }
                    else if (name.equals("limit")) b.limit(s(op.get(1)), s(op.get(2)));
                    else b.risk(m(op.get(1)));
                }
                PolicyTemplates.BuiltPolicy p = b.build();
                Map<String, Object> built = new LinkedHashMap<>();
                built.put("permissions", p.permissions);
                built.put("limits", p.limits);
                if (p.riskPolicy != null) built.put("riskPolicy", p.riskPolicy);
                r.put("ok", true);
                r.put("built", built);
            } catch (IllegalArgumentException | IllegalStateException e) {
                r.clear();
                r.put("ok", false);
            }
            return r;
        });
        OracleCases.each(MOD, "createLink", a -> {
            Map<String, Object> r = new LinkedHashMap<>();
            try {
                r.put("ref", PolicyAuthoring.createLink(a.get(0), a.get(1), Boolean.TRUE.equals(a.get(2))));
                r.put("ok", true);
            } catch (IllegalArgumentException e) {
                r.clear();
                r.put("ok", false);
            }
            return r;
        });
        OracleCases.each(MOD, "slotsDigest", a -> PolicyAuthoring.slotsDigest(a.get(0)));
        OracleCases.each(MOD, "linkDigest", a -> PolicyAuthoring.linkDigest(a.get(0)));
        OracleCases.each(MOD, "limits", a -> {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("MAX_SLOTS", (long) PolicyAuthoring.MAX_SLOTS);
            r.put("MAX_SLOT_STRING", (long) PolicyAuthoring.MAX_SLOT_STRING);
            r.put("MAX_SLOT_SET", (long) PolicyAuthoring.MAX_SLOT_SET);
            r.put("TEMPLATE_KIND", PolicyAuthoring.TEMPLATE_KIND);
            r.put("TIGHTEN_KIND", PolicyAuthoring.TIGHTEN_KIND);
            return r;
        });
    }

    @Test void undoLedger() throws Exception {
        Keys.EdKey key = Keys.edFromSeed(java.security.MessageDigest.getInstance("SHA-256").digest("atlas-pca-conformance/small/undo/service".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        OracleCases.each(MOD, "undoLifecycle", a -> {
            Map<String, Object> rec = m(a.get(0));
            Map<String, Object> cur = Undo.withReceipt(rec, "opened", "", IntentJs.lng(rec.get("opened_at")), key);
            List<Object> out = new ArrayList<>();
            out.add(cur);
            for (Object st : l(a.get(1))) {
                Object ev = l(st).get(0), now = l(st).get(1);
                Undo.Transition t = Undo.transition(cur, ev, now);
                Map<String, Object> step = new LinkedHashMap<>();
                if (t.outcome.equals("applied")) {
                    cur = Undo.withReceipt(t.record, t.event, t.note, IntentJs.lng(now), key);
                    step.put("applied", m(ev).get("kind"));
                    step.put("record", cur);
                } else step.put(t.outcome, t.code);
                out.add(step);
            }
            Map<String, Object> chain = new LinkedHashMap<>();
            chain.put("chain", Undo.receiptChainError(cur, key.id()));
            out.add(chain);
            return out;
        });
        OracleCases.each(MOD, "undoStore", a -> {
            UndoStore st = s(a.get(0)).equals("memory") ? new MemoryUndoStore() : new KvUndoStore(new MemoryAtomicKv(), true);
            List<Object> out = new ArrayList<>();
            for (Object op0 : l(a.get(1))) {
                List<Object> op = l(op0);
                String name = (String) op.get(0);
                try {
                    if (name.equals("create")) {
                        UndoStore.CreateResult c = st.create(m(op.get(1)));
                        Map<String, Object> r = new LinkedHashMap<>();
                        r.put("created", c.created);
                        if (!c.created) r.put("record", c.record);
                        out.add(r);
                    } else if (name.equals("get")) out.add(st.get(s(op.get(1))));
                    else if (name.equals("replace")) out.add(st.replace(s(op.get(1)), Json.asLong(op.get(2)), m(op.get(3))));
                    else {
                        Map<String, Object> q = m(op.get(1));
                        UndoStore.Query qq = new UndoStore.Query(s(q.get("state")));
                        if (q.get("windowEndedBy") != null) qq.windowEndedBy = Json.asLong(q.get("windowEndedBy"));
                        qq.grantRef = s(q.get("grantRef"));
                        qq.bondRef = s(q.get("bondRef"));
                        if (q.get("limit") != null) qq.limit = (int) Json.asLong(q.get("limit"));
                        out.add(st.list(qq));
                    }
                } catch (Undo.UndoError e) {
                    Map<String, Object> r = new LinkedHashMap<>();
                    r.put("error", e.code);
                    out.add(r);
                }
            }
            return out;
        });
        org.junit.jupiter.api.Assertions.assertTrue(UndoStore.isUndoStore(new MemoryUndoStore()));
        org.junit.jupiter.api.Assertions.assertFalse(UndoStore.isUndoStore(new Object()));
        org.junit.jupiter.api.Assertions.assertFalse(new MemoryUndoStore().durable());
        org.junit.jupiter.api.Assertions.assertTrue(new KvUndoStore(new MemoryAtomicKv(), true).durable());
    }

    @Test void catalogRisk() throws Exception {
        OracleCases.each(MOD, "catalogReversibilityScore", a -> new LinkedHashMap<String, Object>(Catalog.CATALOG_REVERSIBILITY_SCORE));
        OracleCases.each(MOD, "catalogRisk", a -> Catalog.catalogRisk(s(a.get(0)), m(a.get(1)), m(a.get(2)), null, OracleCases.num(a.get(3))));
    }

    private static Map<String, Object> tryOr(java.util.function.Supplier<Object> f) {
        Map<String, Object> r = new LinkedHashMap<>();
        try {
            r.put("v", f.get());
            r.put("ok", true);
        } catch (RuntimeException e) {
            r.clear();
            r.put("ok", false);
        }
        return r;
    }

    @Test void paymentApprovalProfiles() throws Exception {
        OracleCases.each(MOD, "spcExpectation", a -> tryOr(() -> Approval.spcExpectation(m(a.get(0)), "https://shop.example", payeeAs(a))));
        OracleCases.each(MOD, "cibaApprovalDetails", a -> tryOr(() -> Approval.cibaApprovalDetails(m(a.get(0)))));
    }

    private static String payeeAs(List<?> a) { return a.size() > 1 && a.get(1) instanceof String ? (String) a.get(1) : "name"; }
}
