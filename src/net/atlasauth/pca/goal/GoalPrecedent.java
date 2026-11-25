package net.atlasauth.pca.goal;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Escalation;
import net.atlasauth.pca.Pca;

/**
 * Progressive authorization. Widening is only by an escalation request answered by a principal-signed answer; a verified answer
 * becomes an append-only hash-chained precedent bound to (policy digest, decision cell, the answered action's exact quantities
 * as a ceiling). A recorded cell decision is never flipped except by a principal-signed revocation; a deny is never turned into
 * an allow (precedents act only on escalate). Entries, answers and answered cases are parsed-JSON maps.
 */
public final class GoalPrecedent {
    private GoalPrecedent() {}

    private static Map<String, Object> mm(Object o) { return G.m(o); }

    private static String unitKey(Map<String, Object> q) {
        Map<String, Object> u = mm(q.get("u"));
        return G.kind(u).equals("money") ? "money:" + u.get("ccy") : G.kind(u);
    }

    /** Ceilings are keyed by parameter AND unit (kind + currency): a EUR answer never covers a GBP action. */
    public static Map<String, Object> ceilingsOf(Map<String, Object> params) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : params.entrySet()) {
            Map<String, Object> v = mm(e.getValue());
            if (G.kind(v).equals("q")) { Map<String, Object> q = mm(v.get("q")); out.put(e.getKey() + "|" + unitKey(q), q.get("n")); }
        }
        return out;
    }

    private static Map<String, Object> caseOf(Map<String, Object> a) {
        Map<String, Object> act = mm(mm(a.get("pcactn")).get("action"));
        return G.map("act", GoalExamples.mkAct((String) act.get("verb"), (String) act.get("resource"), mm(a.get("params"))), "rels", a.get("rels"));
    }

    public static Map<String, Object> signRevocation(Map<String, Object> p, byte[] seed) { return GoalSign.signPayload("precedent-revocation", p, seed); }

    /** The answer body for a request: bound to the request's exact (policy, action, history head). Sign it with the escalation signer. */
    public static Map<String, Object> answerBodyFor(Map<String, Object> req, String principal, String decision, Object iat, Object expiresAt, String nonce) {
        return G.map("v", G.num(1), "kind", "pca-escalation-answer", "principal", principal, "policy_digest", req.get("policy_digest"), "action_digest", req.get("action_digest"),
            "history_head", req.get("history_head"), "decision", decision, "iat", iat, "expires_at", expiresAt, "nonce", nonce);
    }

    private static final String GENESIS = "0".repeat(64);

    private static Object orNull(Object o) { return o; }

    private static String entryDigest(Map<String, Object> e) {
        Object answered = e.get("answered");
        Object answeredOut = null;
        if (G.truthy(answered)) {
            Map<String, Object> a = new LinkedHashMap<>(mm(answered));
            if (a.get("lastCounter") == null) a.put("lastCounter", null);
            answeredOut = a;
        }
        return Pca.hashCanonical(G.map("d", "atlas-pca/goal-precedent-entry/v1", "seq", e.get("seq"), "prev", e.get("prev"), "kind", e.get("kind"),
            "answer", orNull(e.get("answer")), "answered", answeredOut, "cell", e.get("cell"), "ceilings", e.get("ceilings"), "revocation", e.get("revocation")));
    }

    private static Map<String, Object> ok(Object entry) { return G.map("ok", true, "entry", entry); }
    private static Map<String, Object> no(String reason) { return G.map("ok", false, "reason", reason); }

    /** The append-only precedent log of one verifier, which pins the principals allowed to answer and revoke. */
    public static final class Log {
        private final List<Map<String, Object>> entries = new ArrayList<>();
        private final List<?> principals;

        public Log(List<?> principals) { this.principals = principals; }

        public List<Map<String, Object>> entries() { return entries; }

        public String head() { return entries.isEmpty() ? GENESIS : (String) entries.get(entries.size() - 1).get("digest"); }

        private Object pinFor(String pk) {
            for (Object p : principals) if (pk.equals(p instanceof String ? p : G.get(p, "pk"))) return p;
            return null;
        }

        /** Everything about an answer that does not depend on the clock. Null = sound. */
        private String answerFault(Map<String, Object> answer, Map<String, Object> answered) {
            if (Escalation.answerShapeError(answer) != null) return "malformed answer";
            Object pin = pinFor((String) answer.get("principal"));
            if (pin == null || !GoalSign.verifyArtifactSig(Escalation.ANSWER_DOMAIN, answer, pin)) return "bad signature";
            Map<String, Object> pcactn = mm(answered.get("pcactn"));
            if (!java.util.Objects.equals(answer.get("action_digest"), Escalation.actionDigest(pcactn))) return "answer is bound to another action";
            Long lc = G.safeInt(answered.get("lastCounter"));
            if (!java.util.Objects.equals(answer.get("history_head"), Escalation.historyHead(lc))) return "answer is bound to another history state";
            if (!Pca.paramsDigest(answered.get("params")).equals(mm(pcactn.get("action")).get("params_digest"))) return "params do not match the signed action";
            return null;
        }

        /** Recompute the whole chain, every signature and binding, and every derived cell and ceiling under {@code space}. */
        public boolean verifyChain(GoalExamples.Space space) {
            try {
                String prev = GENESIS;
                for (int i = 0; i < entries.size(); i++) {
                    Map<String, Object> e = entries.get(i);
                    Long seq = G.safeInt(e.get("seq"));
                    if (seq == null || seq != i || !prev.equals(e.get("prev")) || !entryDigest(e).equals(e.get("digest"))) return false;
                    if ("answer".equals(e.get("kind"))) {
                        Map<String, Object> answer = mm(e.get("answer")), answered = mm(e.get("answered"));
                        if (answer == null || answered == null || answerFault(answer, answered) != null) return false;
                        if (!java.util.Objects.equals(e.get("cell"), GoalExamples.cellKey(space, caseOf(answered)))
                            || !G.stringify(e.get("ceilings")).equals(G.stringify(ceilingsOf(mm(answered.get("params")))))) return false;
                    } else if (!(G.truthy(e.get("revocation")) && GoalSign.verifyPayload(mm(e.get("revocation")), "precedent-revocation", principals))) return false;
                    prev = (String) e.get("digest");
                }
                return true;
            } catch (RuntimeException ex) {
                return false;
            }
        }

        private Map<String, Object> live(Object policy, Object cell, double now) {
            Set<Object> revoked = new HashSet<>();
            for (Map<String, Object> e : entries) if ("revocation".equals(e.get("kind"))) revoked.add(mm(mm(e.get("revocation")).get("payload")).get("target_entry"));
            for (int i = entries.size() - 1; i >= 0; i--) {
                Map<String, Object> e = entries.get(i);
                if (!"answer".equals(e.get("kind"))) continue;
                Map<String, Object> a = mm(e.get("answer"));
                if (java.util.Objects.equals(a.get("policy_digest"), policy) && java.util.Objects.equals(e.get("cell"), cell) && Double.isFinite(now) && G.toNum(a.get("expires_at")) > now && !revoked.contains(e.get("digest"))) return e;
            }
            return null;
        }

        /** Verify the answer (pinned signer, bound to this grant's policy digest, this exact action and history, unexpired) and record it: {ok, entry | reason}. */
        public Map<String, Object> append(Map<String, Object> answer, Map<String, Object> answered, Map<String, Object> grant, GoalExamples.Space space, long now) {
            Escalation.Binding bind = new Escalation.Binding(Escalation.policyDigest(grant), Escalation.actionDigest(mm(answered.get("pcactn"))), Escalation.historyHead(G.safeInt(answered.get("lastCounter"))));
            Escalation.Result v = Escalation.verify(answer, principals, bind, now);
            if (!v.ok) return no(v.reason);
            String fault = answerFault(answer, answered);
            if (fault != null) return no(fault);
            String cell = GoalExamples.cellKey(space, caseOf(answered));
            Map<String, Object> existing = live(answer.get("policy_digest"), cell, now);
            if (existing != null && !java.util.Objects.equals(mm(existing.get("answer")).get("decision"), answer.get("decision"))) return no("conflicts with a recorded decision; revoke it first");
            Map<String, Object> fields = new LinkedHashMap<>();
            fields.put("kind", "answer");
            fields.put("answer", answer);
            fields.put("answered", answered);
            fields.put("cell", cell);
            fields.put("ceilings", ceilingsOf(mm(answered.get("params"))));
            return ok(push(fields));
        }

        public Map<String, Object> revoke(Map<String, Object> rev) {
            if (!GoalSign.verifyPayload(rev, "precedent-revocation", principals)) return no("bad signature");
            Map<String, Object> p = mm(rev.get("payload"));
            boolean found = false;
            for (Map<String, Object> e : entries) {
                if ("answer".equals(e.get("kind")) && java.util.Objects.equals(e.get("digest"), p.get("target_entry"))
                    && java.util.Objects.equals(mm(e.get("answer")).get("policy_digest"), p.get("policy_digest")) && java.util.Objects.equals(e.get("cell"), p.get("cell"))) found = true;
            }
            if (!found) return no("no such precedent");
            Map<String, Object> fields = new LinkedHashMap<>();
            fields.put("kind", "revocation");
            fields.put("revocation", rev);
            return ok(push(fields));
        }

        private Map<String, Object> push(Map<String, Object> fields) {
            Map<String, Object> base = new LinkedHashMap<>();
            base.put("seq", G.num(entries.size()));
            base.put("prev", head());
            for (Map.Entry<String, Object> f : fields.entrySet()) if (f.getValue() != null) base.put(f.getKey(), f.getValue());
            Map<String, Object> entry = new LinkedHashMap<>(base);
            entry.put("digest", entryDigest(base));
            entries.add(entry);
            return entry;
        }

        /** The recorded decision covering this case under this policy, or null: {decision, entry}. */
        public Map<String, Object> lookup(String policyDigest, GoalExamples.Space space, Map<String, Object> c, double now) {
            Map<String, Object> e = live(policyDigest, GoalExamples.cellKey(space, c), now);
            if (e == null) return null;
            Map<String, Object> ceil = mm(e.get("ceilings"));
            Map<String, Object> now2 = ceilingsOf(mm(mm(c.get("act")).get("params")));
            for (Map.Entry<String, Object> kv : now2.entrySet()) {
                Object cap = ceil.get(kv.getKey());
                double limit = cap == null ? Double.NEGATIVE_INFINITY : G.toNum(cap);
                if (G.toNum(kv.getValue()) > limit) return null;
            }
            for (String k : ceil.keySet()) if (!now2.containsKey(k)) return null;
            return G.map("decision", mm(e.get("answer")).get("decision"), "entry", e);
        }
    }

    /** Policy decision refined by precedents: {decision, via, precedent?}. Precedents act only on escalate; a recorded deny also tightens. */
    public static Map<String, Object> authorizeWithPrecedents(Map<String, Object> goal, Map<String, Object> ont, String policyDigest, Log log, Map<String, Object> c, double now) {
        String base = (String) GoalExamples.decideCase(goal, ont, c).get("decision");
        if (!base.equals("escalate")) return G.map("decision", base, "via", "policy");
        GoalExamples.Space space = GoalExamples.buildSpace(List.of(goal), new ArrayList<>());
        if (!log.verifyChain(space)) return G.map("decision", "escalate", "via", "policy");
        Map<String, Object> hit = log.lookup(policyDigest, space, c, now);
        if (hit == null) return G.map("decision", "escalate", "via", "policy");
        return G.map("decision", "allow".equals(hit.get("decision")) ? "allow" : "deny", "via", "precedent", "precedent", hit.get("entry"));
    }
}
