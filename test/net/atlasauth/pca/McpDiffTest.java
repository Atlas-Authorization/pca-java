package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.mcp.Mcp;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference vectors of the MCP adapter through the native port, plus the tool-call reader the oracle cannot reach. */
public class McpDiffTest {
    private static final String M = "ref-mcp";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    @Test void constants() throws Exception {
        OracleCases.each(M, "constants", a -> {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("MCP_CLIENT_REVISIONS", new java.util.ArrayList<Object>(Mcp.MCP_CLIENT_REVISIONS));
            o.put("MCP_AUTH_CLIENT_ROWS", new java.util.ArrayList<Object>(Mcp.mcpAuthClientRows()));
            return o;
        });
    }

    @Test void parseChallenges() throws Exception { OracleCases.each(M, "parseChallenges", a -> Mcp.parseChallenges(a.get(0))); }
    @Test void pcaNeedProblem() throws Exception { OracleCases.each(M, "pcaNeedProblem", a -> Mcp.pcaNeedProblem(a.get(0))); }
    @Test void planStepUp() throws Exception { OracleCases.each(M, "planStepUp", a -> Mcp.planStepUp(a.get(0), a.get(1), m(a.get(2)))); }
    @Test void checkAuthorizationResponseIss() throws Exception { OracleCases.each(M, "checkAuthorizationResponseIss", a -> Mcp.checkAuthorizationResponseIss(m(a.get(0)))); }
    @Test void guardToolResult() throws Exception { OracleCases.each(M, "guardToolResult", a -> Mcp.guardToolResult(a.get(0), a.get(1))); }
    @Test void pcaHeaders() throws Exception { OracleCases.each(M, "pcaHeaders", a -> Mcp.pcaHeaders((String) a.get(0))); }
    @Test void draftActionSchemaFromMcp() throws Exception { OracleCases.each(M, "draftActionSchemaFromMcp", a -> Mcp.draftActionSchemaFromMcp(l(a.get(0)), m(a.get(1)))); }
    @Test void applySchemaDecisions() throws Exception { OracleCases.each(M, "applySchemaDecisions", a -> Mcp.applySchemaDecisions(a.get(0), m(a.get(1)))); }
    @Test void verbOfTool() throws Exception { OracleCases.each(M, "verbOfTool", a -> Mcp.verbOfTool(a.get(0), a.get(1))); }
    @Test void conformToolCall() throws Exception { OracleCases.each(M, "conformToolCall", a -> Mcp.conformToolCall(a.get(0), (String) a.get(1), a.get(2))); }

    @Test void toolCallOfReadsOnlyToolsCall() {
        Map<String, Object> c = Mcp.toolCallOf("{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"pay\",\"arguments\":{\"a\":1}}}");
        assertNotNull(c);
        assertEquals("pay", c.get("name"));
        assertEquals(1, m(c.get("arguments")).size());
        Map<String, Object> noArgs = Mcp.toolCallOf("{\"method\":\"tools/call\",\"params\":{\"name\":\"pay\",\"arguments\":[1]}}");
        assertNotNull(noArgs);
        assertEquals(0, m(noArgs.get("arguments")).size()); // arguments that are not an object count as none
        assertNull(Mcp.toolCallOf("{\"method\":\"tools/list\"}"));
        assertNull(Mcp.toolCallOf("{\"method\":\"tools/call\",\"params\":{\"name\":5}}"));
        assertNull(Mcp.toolCallOf("not json"));
        assertNull(Mcp.toolCallOf("[]"));
        assertNull(Mcp.toolCallOf(null));
    }
}
