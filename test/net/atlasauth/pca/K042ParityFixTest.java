package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/**
 * Pins four 0.4.2 Java/TS parity fixes against the TS reference. test-data/k042-parity.json carries TS-oracle cases copied
 * from the Kotlin kill-test data (tools/pca-audit/kotlin-mutate/killFacts-oracle-gen.mjs, killAcc-oracle-gen.mjs):
 * <ul>
 *   <li>rule 17 with a non-string or absent {@code aud}: TS never casts it (a number, null or undefined never equals a site
 *       and never passes a flow rule; the refusal prints it as JavaScript would); Java threw a ClassCastException /
 *       NullPointerException (fail-closed "evaluation error"), even with no labelled parameter at all;</li>
 *   <li>a JSON-null {@code material_tainted} / {@code critical_tainted}: refused with the TS reason (Java threw);</li>
 *   <li>a JSON-null {@code sel.event}: "unknown sel.event" (Java threw);</li>
 *   <li>{@code default: null} is refused BEFORE the principal_neutral_default and accumulates_into checks
 *       (action-schema.ts order); Java reported the later member's error first.</li>
 * </ul>
 */
public class K042ParityFixTest {
    @SuppressWarnings("unchecked")
    static Map<String, Object> data() throws Exception {
        return (Map<String, Object>) Json.parseLenient(new String(Files.readAllBytes(Path.of("test-data/k042-parity.json")), StandardCharsets.UTF_8));
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> cases(String k) throws Exception { return (List<Map<String, Object>>) data().get(k); }

    @Test
    void provenanceAudIsNeverCast() throws Exception {
        List<Map<String, Object>> cs = cases("prov");
        assertEquals(6, cs.size());
        for (Map<String, Object> c : cs) {
            ParamProvenance.ProvResult r = ParamProvenance.decide(IntentJs.normalize(c.get("input")));
            String name = (String) c.get("name");
            assertEquals(c.get("outcome"), r.outcome, name);
            String want = (String) c.get("reason");
            assertEquals(want == null || want.isEmpty() ? null : want, r.reason, name);
        }
    }

    @Test
    void nullTaintedModeIsRefused() throws Exception {
        List<Map<String, Object>> cs = cases("policy");
        assertEquals(2, cs.size());
        for (Map<String, Object> c : cs)
            assertEquals(c.get("reason"), ParamProvenance.validateProvenancePolicy(IntentJs.normalize(c.get("arg"))), (String) c.get("name"));
        assertEquals(false, ParamProvenance.isMode(null));
        assertEquals(false, ParamProvenance.isMode(1L));
        assertEquals(true, ParamProvenance.isMode("deny"));
        assertEquals(false, ParamProvenance.isMode("Deny"));
    }

    @Test
    void nullSelEventIsUnknown() throws Exception {
        List<Map<String, Object>> cs = cases("acc");
        assertEquals(3, cs.size());
        for (Map<String, Object> c : cs)
            assertEquals(c.get("reason"), IntentAcc.accumulatorDeclError(IntentJs.normalize(c.get("arg"))), (String) c.get("name"));
    }

    static final String DOC_HEAD = "{\"v\":1,\"kind\":\"pca-action-schema\",\"site\":\"https://s.example\",\"aud\":\"s.example\",\"version\":\"1\","
        + "\"units\":{\"usd_cents\":{\"kind\":\"money\"}},"
        + "\"verbs\":[{\"verb\":\"a.b\",\"kind\":\"write\",\"params\":{\"action.params.x\":";
    static final String DOC_TAIL = "}}],\"sig\":{\"alg\":\"ed25519\",\"kid\":\"k1\",\"value\":\"AA\"}}";

    static String shape(String decl) { return ActionSchema.shapeError(IntentJs.normalize(Json.parseLenient(DOC_HEAD + decl + DOC_TAIL))); }

    @Test
    void nullDefaultIsCheckedFirst() {
        String nul = "verb 'a.b': action.params.x: default must not be null (absent = no default)";
        assertEquals(nul, shape("{\"type\":\"string\",\"semantic\":\"s\",\"sensitivity\":\"free\",\"default\":null}"));
        assertEquals(nul, shape("{\"type\":\"string\",\"semantic\":\"s\",\"sensitivity\":\"free\",\"default\":null,\"principal_neutral_default\":1}"));
        assertEquals(nul, shape("{\"type\":\"string\",\"semantic\":\"s\",\"sensitivity\":\"free\",\"default\":null,\"accumulates_into\":[\"spend\"]}"));
        assertEquals(nul, shape("{\"type\":\"integer\",\"semantic\":\"s\",\"sensitivity\":\"free\",\"default\":null,\"accumulates_into\":[]}"));
        // without the null default, the later members are reached as before
        assertEquals("verb 'a.b': action.params.x: principal_neutral_default must be a boolean",
            shape("{\"type\":\"string\",\"semantic\":\"s\",\"sensitivity\":\"free\",\"default\":\"x\",\"principal_neutral_default\":1}"));
        assertEquals("verb 'a.b': action.params.x: accumulates_into applies to integer parameters only",
            shape("{\"type\":\"string\",\"semantic\":\"s\",\"sensitivity\":\"free\",\"accumulates_into\":[\"spend\"]}"));
    }
}
