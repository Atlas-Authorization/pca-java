package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.a2a.A2aPca;
import net.atlasauth.pca.agentcard.AgentCards;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the signed Agent Card / AgentFacts package through the native port. */
public class AgentCardDiffTest {
    private static final String M = "ref-agentcard";
    private static final Pattern LIB_REASON = Pattern.compile("^(signature \\d+ did not verify|could not resolve verification key): ");

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    /** Reasons that quote the JOSE library are compared up to the first colon. */
    @SuppressWarnings("unchecked")
    private static Object norm(Map<String, Object> r) {
        Map<String, Object> c = new LinkedHashMap<>(r);
        Object reason = c.get("reason");
        if (reason instanceof String) { Matcher mt = LIB_REASON.matcher((String) reason); if (mt.find()) c.put("reason", mt.group(1)); }
        if (c.get("attestations") instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object a : (List<Object>) c.get("attestations")) {
                Map<String, Object> x = new LinkedHashMap<>(m(a));
                if (x.get("reason") instanceof String && ((String) x.get("reason")).startsWith("signature did not verify: ")) x.put("reason", "signature did not verify");
                out.add(x);
            }
            c.put("attestations", out);
        }
        return c;
    }

    private static A2aPca.IssueOptions issueOpts(List<?> a) {
        A2aPca.IssueOptions io = new A2aPca.IssueOptions();
        if (a.size() > 2) {
            Map<String, Object> o = m(a.get(2));
            io.alg = (String) o.get("alg");
            io.kid = (String) o.get("kid");
            io.profile = (String) o.get("profile");
            io.schema = (String) o.get("schema");
            io.passport = o.get("passport") == null ? null : m(o.get("passport"));
        }
        return io;
    }

    @Test void constants() throws Exception {
        OracleCases.each(M, "constants", a -> {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("DEFAULT_ALG", AgentCards.DEFAULT_ALG);
            o.put("PCA_ATTESTOR_ID", AgentCards.PCA_ATTESTOR_ID);
            o.put("WELL_KNOWN_AGENT_CARD_PATH", AgentCards.WELL_KNOWN_AGENT_CARD_PATH);
            o.put("WELL_KNOWN_AGENT_FACTS_PATH", AgentCards.WELL_KNOWN_AGENT_FACTS_PATH);
            o.put("AGENT_FACTS_CONTEXT", new ArrayList<Object>(AgentCards.AGENT_FACTS_CONTEXT));
            return o;
        });
    }

    @Test void jcsBytes() throws Exception { OracleCases.each(M, "jcsBytes", a -> AgentCards.jcsBytes(a.get(0))); }
    @Test void validateAgentCard1() throws Exception { OracleCases.each(M, "validateAgentCard1", a -> AgentCards.validateAgentCard1(a.get(0))); }
    @Test void buildAgentCard() throws Exception { OracleCases.each(M, "buildAgentCard", a -> AgentCards.buildAgentCard(a.get(0), m(a.get(1)))); }
    @Test void issueSignedAgentCard() throws Exception { OracleCases.each(M, "issueSignedAgentCard", a -> AgentCards.issueSignedAgentCard(a.get(0), m(a.get(1)), issueOpts(a))); }

    @Test void verifyAgentCard() throws Exception {
        OracleCases.each(M, "verifyAgentCard", a -> {
            Map<String, Object> o = m(a.get(1));
            A2aPca.VerifyCardOptions vo = new A2aPca.VerifyCardOptions();
            vo.jwks = o.get("jwks");
            vo.key = o.get("key");
            vo.alg = (String) o.get("alg");
            vo.schema = (String) o.get("schema");
            return norm(AgentCards.verifyAgentCard(a.get(0), vo));
        });
    }

    @Test void issueAgentFacts() throws Exception { OracleCases.each(M, "issueAgentFacts", a -> AgentCards.issueAgentFacts(a.get(0), m(a.get(1)))); }
    @Test void addAttestation() throws Exception { OracleCases.each(M, "addAttestation", a -> AgentCards.addAttestation(a.get(0), m(a.get(1)))); }
    @Test void verifyAgentFacts() throws Exception { OracleCases.each(M, "verifyAgentFacts", a -> norm(AgentCards.verifyAgentFacts(a.get(0), m(a.get(1))))); }

    @Test void agentCardHandler() throws Exception { OracleCases.each(M, "agentCardHandler", a -> AgentCards.agentCardHandler(a.get(0), (String) a.get(1)).apply((String) a.get(2))); }
    @Test void agentFactsHandler() throws Exception { OracleCases.each(M, "agentFactsHandler", a -> AgentCards.agentFactsHandler(a.get(0), (String) a.get(1)).apply((String) a.get(2))); }
    @Test void toRegistryEntry() throws Exception { OracleCases.each(M, "toRegistryEntry", a -> AgentCards.toRegistryEntry(a.get(0), a.get(1))); }
}
