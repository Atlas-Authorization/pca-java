package net.atlasauth.pca.actions.importers;

import static net.atlasauth.pca.actions.importers.ImportCommon.*;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Actions.ActionKitError;

/**
 * MCP {@code tools/list} to drafts. The annotations are hints from the tool's own server and are untrusted: they can only add
 * restriction (destructive, network egress) or describe a harmless-looking shape; every output is {@code unreviewed}.
 */
public final class McpImporter {
    private McpImporter() {}

    /** {@code tools/list} result {@code {tools: [...]}}, or the tool array itself. */
    public static Map<String, Object> importMcp(Object source, Map<String, Object> opts) {
        Ctx c = newCtx("mcp", source, opts);
        List<Object> tools = source instanceof List ? Jx.a(source) : source instanceof Map && Jx.m(source).get("tools") instanceof List ? Jx.a(Jx.m(source).get("tools")) : null;
        if (tools == null) throw new ActionKitError("bad_source", "an MCP source is a tool array or a tools/list result {tools: [...]}");
        Set<String> seen = new HashSet<>();
        for (Object raw : tools) {
            if (!(raw instanceof Map) || !(Jx.m(raw).get("name") instanceof String) || ((String) Jx.m(raw).get("name")).isEmpty() || ((String) Jx.m(raw).get("name")).length() > 256) {
                addTodo(c, "(tool)", "skipped_op", "an entry without a usable name is skipped");
                continue;
            }
            Map<String, Object> t = Jx.m(raw);
            String name = (String) t.get("name");
            if (seen.contains(name)) { addTodo(c, name, "duplicate_tool", "a tool name listed twice; the first is kept"); continue; }
            seen.add(name);
            c.root = t.get("inputSchema");
            Budget bud = newBudget(c);
            Map<String, Object> input = resolveSchema(t.get("inputSchema"), c, bud, name + ": inputSchema");
            Map<String, Object> params = new LinkedHashMap<>();
            flattenObject(input, c, bud, name, params);
            Map<String, Object> a = t.get("annotations") instanceof Map ? Jx.m(t.get("annotations")) : new LinkedHashMap<>();
            // readOnly claims safety, so it is honoured only when nothing contradicts it
            boolean read = Boolean.TRUE.equals(a.get("readOnlyHint")) && !Boolean.TRUE.equals(a.get("destructiveHint"));
            List<String> effects = read ? List.of("read") : Boolean.TRUE.equals(a.get("destructiveHint")) ? List.of("update", "delete") : List.of("update");
            Draft d = new Draft();
            d.name = name;
            d.title = a.get("title") instanceof String && !((String) a.get("title")).isEmpty() ? a.get("title") : t.get("title");
            d.description = t.get("description");
            d.effects = new ArrayList<>(effects);
            d.scope = "one";
            d.params = params;
            if (Boolean.TRUE.equals(a.get("idempotentHint"))) d.idempotency = Jx.obj("mode", "natural");
            if (Boolean.TRUE.equals(a.get("openWorldHint"))) d.traits = withTrait(null, "pca.network_egress");
            d.bindings = Jx.obj("mcp", Jx.obj("tool", clip(name, 256)));
            emitDef(c, d);
        }
        return finish(c);
    }
}
