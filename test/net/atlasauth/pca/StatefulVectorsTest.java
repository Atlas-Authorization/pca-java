package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The stateful layer (stateful-vectors.json): ordered sequences against ONE fresh store, covering replay, counter ordering, revocation
 * mid-sequence and trust-budget depletion (a replay or a refused step spends nothing). Every sequence and every step must reproduce the reference
 * ({@code allow} and the sorted names of the failed checks). A missing file or a short corpus FAILS.
 */
public class StatefulVectorsTest {
    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }

    static String leafHolder(Map<String, Object> pcactn) {
        List<Object> chain = l(pcactn.get("cap_chain"));
        return (String) m(chain.get(chain.size() - 1)).get("holder");
    }

    static final String DEPLETED = "policy: trust budget depleted: human recharge required";
    static final String NO_VERIFIER = "threshold: t=3 (strong) required but no threshold verifier is enforced";
    static final String NO_BUDGET = "budget: no budget supplied \u2014 fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge";
    /** Reasons lists produced by the TypeScript reference (requirePCA over the same sequences), keyed by sequence and PCActn counter. */
    static final Map<String, List<String>> TS_REASONS = Map.of(
        "st-budget-depletes#4", List.of(DEPLETED, NO_VERIFIER),
        "st-budget-depletes#5", List.of(DEPLETED, NO_VERIFIER),
        "st-budget-depletes#1", List.of(),
        "st-budget-absent#1", List.of(NO_BUDGET, DEPLETED, NO_VERIFIER),
        "st-budget-absent#2", List.of(NO_BUDGET, DEPLETED, NO_VERIFIER));

    static long counterOf(Map<String, Object> pc) { return Json.asLong(pc.get("counter")); }

    @Test void everySequenceReproducesTheReference() {
        Map<String, Object> doc = Track3Vectors.load("stateful-vectors.json");
        List<Object> seqs = l(doc.get("stateful"));
        assertTrue(seqs.size() >= 20, "sequences: " + seqs.size());
        assertTrue(replay(seqs) >= 64);
    }

    /** Sequences with the FULL reasons list of every step, produced by the TypeScript reference (test-data/ts-reasons-probes.json): the order of the budget, policy and threshold reasons. */
    @Test void theReasonsOfEveryMixMatchTheReference() throws Exception {
        Map<String, Object> doc = m(Json.parseLenient(new String(java.nio.file.Files.readAllBytes(java.nio.file.Path.of("test-data/ts-reasons-probes.json")), java.nio.charset.StandardCharsets.UTF_8)));
        List<Object> seqs = l(doc.get("stateful"));
        assertTrue(seqs.size() >= 4, "probe sequences: " + seqs.size());
        assertEquals(8, replay(seqs));
    }

    static int replay(List<Object> seqs) {
        int presents = 0;
        for (Object sx : seqs) {
            Map<String, Object> seq = m(sx);
            String name = (String) seq.get("name");
            Map<String, Object> setup = m(seq.get("setup"));
            Map<String, Map<String, Object>> grants = new HashMap<>();
            for (Object g : l(setup.get("grants"))) grants.put((String) m(g).get("id"), m(g));
            Set<String> revoked = new HashSet<>();
            for (Object r : l(setup.getOrDefault("revoked", new ArrayList<>()))) revoked.add((String) r);
            MemoryStateStore store = new MemoryStateStore();
            // the resource server's own budget store: every holder stream the sequence touches starts with the initial budget
            if (setup.get("initial_budget") != null) {
                for (Object stx : l(seq.get("steps"))) {
                    Map<String, Object> st = m(stx);
                    if (!"present".equals(st.get("op"))) continue;
                    Map<String, Object> pc = m(st.get("pcactn"));
                    if (grants.containsKey(pc.get("grant_ref"))) store.putBudget(Authorize.stateKey((String) pc.get("grant_ref"), leafHolder(pc)), m(setup.get("initial_budget")));
                }
            }
            for (Object stx : l(seq.get("steps"))) {
                Map<String, Object> st = m(stx);
                if ("revoke".equals(st.get("op"))) {
                    revoked.add((String) st.get("id"));
                    continue;
                }
                assertEquals("present", st.get("op"), name);
                Map<String, Object> pc = m(st.get("pcactn"));
                Map<String, Object> action = m(pc.get("action"));
                Map<String, Object> ctx = new LinkedHashMap<>();
                ctx.put("plan", setup.get("plan_nodes"));
                ctx.put("plan_authorized", Boolean.TRUE);
                ctx.put("risk", setup.get("risk"));
                Authorize.Input in = new Authorize.Input()
                    .operation(Authorize.Operation.of((String) action.get("verb"), (String) action.get("resource"), m(st.get("params"))))
                    .audience((String) setup.get("audience")).resolveGrant(ref -> grants.get(ref)).stateStore(store)
                    .isRevoked((p, g) -> {
                        for (Object c : l(p.get("cap_chain"))) if (revoked.contains(m(c).get("id"))) return Boolean.TRUE;
                        return Boolean.FALSE;
                    })
                    .now(Json.asLong(st.get("now"))).seedBudget(false).context(p -> ctx).provenanceGate(ProvHarness.options());
                Authorize.AuthorizeResult r = Authorize.authorize(pc, in);
                Map<String, Object> exp = m(st.get("expect"));
                List<String> failed = new ArrayList<>(r.failed());
                Collections.sort(failed);
                assertEquals(exp.get("allow"), r.allow, name + " step " + presents + ": allow (" + r.reasons + ")");
                assertEquals(l(exp.get("failed")), failed, name + " step " + presents + ": failed checks (" + r.reasons + ")");
                // the full reasons list, as the TypeScript reference produces it (budget first, then the policy and threshold reasons)
                List<String> tsReasons = TS_REASONS.get(name + "#" + counterOf(pc));
                if (tsReasons != null) assertEquals(tsReasons, r.reasons, name + " step " + presents + ": reasons");
                if (exp.containsKey("reasons")) assertEquals(l(exp.get("reasons")), new ArrayList<Object>(r.reasons), name + " step " + presents + ": reasons");
                presents++;
            }
        }
        return presents;
    }
}
