package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The policy layer (policy-vectors.json, {@code policy_decision}): EVERY vector reproduced, none skipped. {@code expect.caveats} is the agent-native
 * evaluation of the grant's caveats minus its envelope plus the hop-appended ones; {@code expect.decision} is the whole policy decision (reason codes
 * in order, and the failed caveat types per placement) with the risk inputs and the trust budget held neutral.
 */
public class PolicyVectorsTest {
    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    static Map<String, Object> cctxOf(Map<String, Object> ctx, int depth) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("now", Json.asLong(ctx.get("now")));
        c.put("action", ctx.get("action"));
        c.put("delegation_depth", (long) depth);
        c.put("blast_radius", ctx.get("blast_radius"));
        c.put("reversibility_class", ctx.get("reversibility_class"));
        c.put("recent_action_times", ctx.get("recent_action_times"));
        return c;
    }

    @Test void everyVectorReproducesTheReference() {
        Map<String, Object> doc = Track3Vectors.load("policy-vectors.json");
        List<Object> vs = l(doc.get("policy_decision"));
        assertTrue(vs.size() >= 413, "vectors: " + vs.size());
        for (Object x : vs) {
            Map<String, Object> v = m(x);
            String name = (String) v.get("name");
            Map<String, Object> grant = m(v.get("grant"));
            Object chainO = v.get("chain");
            Map<String, Object> ctx = m(v.get("context"));
            Map<String, Object> act = m(ctx.get("action"));
            Map<String, Object> inner = new LinkedHashMap<>();
            inner.put("verb", act.get("verb"));
            inner.put("resource", act.get("resource"));
            inner.put("params", act.get("params"));
            Map<String, Object> actionCtx = new LinkedHashMap<>();
            actionCtx.put("action", inner);
            Map<String, Object> toolCall = new LinkedHashMap<>();
            toolCall.put("tool", act.get("verb"));
            toolCall.put("args", act.get("params"));

            // the delegated caveats: what the leaf hop appended beyond the grant's own
            List<Object> chain = chainO instanceof List ? l(chainO) : new ArrayList<>();
            List<Object> grantCaveats = grant.get("caveats") instanceof List ? l(grant.get("caveats")) : new ArrayList<>();
            List<Object> extra = new ArrayList<>();
            if (!chain.isEmpty() && chain.get(chain.size() - 1) instanceof Map) {
                List<Object> leaf = m(chain.get(chain.size() - 1)).get("caveats") instanceof List ? l(m(chain.get(chain.size() - 1)).get("caveats")) : new ArrayList<>();
                if (leaf.size() > grantCaveats.size()) extra = new ArrayList<>(leaf.subList(grantCaveats.size(), leaf.size()));
            }
            Map<String, Object> cctx = cctxOf(ctx, chain.isEmpty() ? 0 : chain.size() - 1);

            // expect.caveats: the root caveats outside the envelope, then the hop-appended ones
            List<Object> policyCaveats = new ArrayList<>(l(Authorize.rootCaveats(grant)));
            policyCaveats.addAll(extra);
            Caveats.Result cv = Authorize.evaluateAgentCaveats(policyCaveats, cctx, actionCtx, toolCall);
            Map<String, Object> wantCv = m(m(v.get("expect")).get("caveats"));
            assertEquals(wantCv.get("allow"), cv.ok, name + ": caveats allow");
            assertEquals(l(wantCv.get("failed")), new ArrayList<Object>(cv.failed), name + ": caveats failed");

            // expect.decision
            List<String> reasons = new ArrayList<>();
            Map<String, List<String>> failed = new LinkedHashMap<>();
            failed.put("envelope", new ArrayList<>());
            failed.put("root", new ArrayList<>());
            failed.put("delegated", new ArrayList<>());
            Map<String, Object> env = Authorize.readEnvelope(grant);
            if (env == null) reasons.add("envelope_missing");
            else {
                if (Predicates.denialReason(env.get("predicates"), actionCtx) != null) reasons.add("predicates_unsatisfied");
                if (chain.isEmpty()) reasons.add("chain_malformed");
                Caveats.Result ecv = Authorize.evaluateAgentCaveats(env.get("caveats"), cctx, actionCtx, toolCall);
                if (!ecv.ok) { reasons.add("envelope_caveats_unsatisfied"); failed.get("envelope").addAll(ecv.failed); }
                Caveats.Result rcv = Authorize.evaluateAgentCaveats(Authorize.rootCaveats(grant), cctx, actionCtx, toolCall);
                if (!rcv.ok) { reasons.add("root_caveats_unsatisfied"); failed.get("root").addAll(rcv.failed); }
                Caveats.Result dcv = Authorize.evaluateAgentCaveats(extra, cctx, actionCtx, toolCall);
                if (!dcv.ok) { reasons.add("delegated_caveats_unsatisfied"); failed.get("delegated").addAll(dcv.failed); }
            }
            Map<String, Object> want = m(m(v.get("expect")).get("decision"));
            assertEquals(want.get("allow"), reasons.isEmpty(), name + ": decision allow");
            assertEquals(l(want.get("reasons")), new ArrayList<Object>(reasons), name + ": reasons");
            Map<String, Object> wf = m(want.get("failed"));
            for (String k : new String[] {"envelope", "root", "delegated"}) assertEquals(l(wf.get(k)), new ArrayList<Object>(failed.get(k)), name + ": failed." + k);
        }
    }
}
