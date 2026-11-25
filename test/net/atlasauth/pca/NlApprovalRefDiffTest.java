package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The approval half of natural-language policy authoring against the reference corpus (ref-nl-approval, 206 cases): the catalog digest, the
 * draft binding and digests, the strict parse of a completion, the draft, the reviewer's approval (v2 and the legacy v1), the load of an approved
 * policy with its rejection codes, and the agent minted from one (only the deterministic envelope is compared, never the goal commitment).
 */
class NlApprovalRefDiffTest {
    static final String MODULE = "ref-nl-approval";
    static final int TOTAL = 206;

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object arg(List<?> a, int i) { return i < a.size() ? a.get(i) : null; }

    @SuppressWarnings("unchecked")
    private static Catalog catalog(Object extras) {
        if (extras == null) return Catalog.DEFAULT;
        List<Catalog.Spec> specs = new ArrayList<>(Catalog.BUILTIN);
        for (Object eo : (List<Object>) extras) {
            Map<String, Object> e = (Map<String, Object>) eo;
            String connector = (String) e.get("connector"), action = (String) e.get("action");
            List<String> aliases = new ArrayList<>();
            if (e.get("aliases") != null) for (Object x : (List<Object>) e.get("aliases")) aliases.add((String) x);
            specs.add(new Catalog.Spec(connector, action, connector + "." + action, (String) e.get("reversibility"), IntentJs.num(e.get("blastRadius")), (String) e.get("amountField"),
                (String) e.get("description"), aliases, null));
        }
        return new Catalog(specs);
    }

    private static byte[] bytes(Object o) { return Keys.unb64u((String) m(o).get("$bytes")); }

    private static Keys.SuiteKey key(String label) throws Exception {
        byte[] seed = MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8));
        return Keys.ed25519(Keys.edFromSeed(seed));
    }

    private static java.util.function.Function<String, String> model(Object raw) {
        return p -> {
            if ("THROWS".equals(raw)) throw new IllegalStateException("llm down");
            return (String) raw;
        };
    }

    private static Map<String, Object> loadOpts(Object o) {
        Map<String, Object> opts = new LinkedHashMap<>(m(o));
        Object extras = opts.remove("extras");
        if (opts.get("now") instanceof Map && ((Map<?, ?>) opts.get("now")).get("$num") instanceof String) opts.put("now", Double.parseDouble((String) ((Map<?, ?>) opts.get("now")).get("$num")));
        if (extras != null) opts.put("catalog", catalog(extras));
        return opts;
    }

    @Test void everyFunction() throws Exception {
        Map<String, OracleCases.Fn> f = new LinkedHashMap<>();
        f.put("constants", x -> Issue.obj("NL_APPROVAL_DOMAIN", NlApproval.NL_APPROVAL_DOMAIN, "NL_APPROVAL_DOMAIN_V2", NlApproval.NL_APPROVAL_DOMAIN_V2,
            "MAX_NL_OUTPUT_BYTES", NlApproval.MAX_NL_OUTPUT_BYTES, "MAX_NL_APPROVAL_TTL_MS", NlApproval.MAX_NL_APPROVAL_TTL_MS));
        f.put("catalogDigest", x -> NlApproval.catalogDigest(catalog(arg(x, 0))));
        f.put("draftBinding", x -> NlApproval.draftBinding((String) arg(x, 0), catalog(arg(x, 1)), (String) arg(x, 2)));
        f.put("draftDigestV2", x -> NlApproval.draftDigestV2(m(arg(x, 0)), m(arg(x, 1)), (String) arg(x, 2), m(arg(x, 3))));
        f.put("draftDigest", x -> NlApproval.draftDigest(m(arg(x, 0)), m(arg(x, 1)), (String) arg(x, 2)));
        f.put("policyFromNL", x -> NlApproval.policyFromNL((String) arg(x, 0), model(arg(x, 1)), arg(x, 2) == null ? null : catalog(arg(x, 2)), (String) arg(x, 3)));
        f.put("draftPolicyFromNL", x -> NlApproval.draftPolicyFromNL((String) arg(x, 0), model(arg(x, 1)), arg(x, 2) == null ? null : catalog(arg(x, 2)), (String) arg(x, 3)));
        f.put("approveDraft", x -> NlApproval.approveDraft(m(arg(x, 0)), bytes(arg(x, 1)), m(arg(x, 2))));
        f.put("approveDraftLegacy", x -> NlApproval.approveDraftLegacyV1(m(arg(x, 0)), bytes(arg(x, 1)), m(arg(x, 2))));
        f.put("loadApproved", x -> NlApproval.loadApprovedPolicy(m(arg(x, 0)), m(arg(x, 1)), loadOpts(arg(x, 2))));
        f.put("agentFromApproved", x -> {
            Map<String, Object> a = m(arg(x, 0));
            NlApproval.ApprovedAgent r = NlApproval.agentFromApprovedNL(m(a.get("draft")), m(a.get("approval")), loadOpts(a.get("opts")), key((String) a.get("principalSeed")),
                (String) a.get("goal"), (String) a.get("aud"), a.get("holderSeed") != null ? key((String) a.get("holderSeed")) : null);
            Map<String, Object> env = Authorize.readEnvelope(r.agent.grant);
            return Issue.obj("reviewer", r.reviewer, "legacy_unbound_instruction", r.legacyUnboundInstruction,
                "envelope", Issue.obj("predicates", env.get("predicates"), "caveats", env.get("caveats"), "risk_policy", env.get("risk_policy"), "agent_binding", env.get("agent_binding")));
        });

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);

        List<String> bad = new ArrayList<>();
        for (Map.Entry<String, OracleCases.Fn> e : f.entrySet()) {
            for (Map<String, Object> c : OracleCases.of(MODULE, e.getKey())) {
                String d = OracleCases.diff(c, c.get("out"), e.getValue());
                if (d != null) bad.add(d);
            }
        }
        assertTrue(bad.isEmpty(), bad.size() + " divergent case(s):\n" + String.join("\n", bad.subList(0, Math.min(bad.size(), 40))));
    }
}
