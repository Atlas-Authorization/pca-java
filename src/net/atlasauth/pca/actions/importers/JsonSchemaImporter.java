package net.atlasauth.pca.actions.importers;

import static net.atlasauth.pca.actions.importers.ImportCommon.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Actions.ActionKitError;
import net.atlasauth.pca.ActionsBridge;

/** "I have a function signature": one JSON Schema plus a verb the caller gives, to one def. */
public final class JsonSchemaImporter {
    private JsonSchemaImporter() {}

    /** {@code opts}: the common import options plus {@code verb} (required, in the namespace), {@code title}, {@code description}, {@code effects} (default update). */
    public static Map<String, Object> importJsonSchema(Object schema, Map<String, Object> opts) {
        Ctx c = newCtx("jsonschema", schema, opts);
        Object verbO = opts.get("verb");
        String ns = (String) opts.get("ns");
        if (!(verbO instanceof String) || !VERB_RE.matcher((String) verbO).matches() || !((String) verbO).startsWith(ns + ".")) throw new ActionKitError("bad_verb", "verb must be a valid verb in namespace '" + ns + "'");
        String verb = (String) verbO;
        Object effO = opts.get("effects") == null ? Jx.list("update") : opts.get("effects");
        if (!(effO instanceof List) || Jx.a(effO).isEmpty() || !Jx.a(effO).stream().allMatch(e -> e instanceof String && ActionsBridge.effects().contains(e))) throw new ActionKitError("bad_effects", "effects must be 1+ known effects");
        List<String> effects = new ArrayList<>();
        for (Object e : Jx.a(effO)) effects.add((String) e);
        if (!(schema instanceof Map)) throw new ActionKitError("bad_source", "a JSON Schema must be an object");
        Budget bud = newBudget(c);
        Map<String, Object> root = resolveSchema(schema, c, bud, verb);
        Map<String, Object> params = new LinkedHashMap<>();
        if ("object".equals(root.get("type")) || root.get("properties") instanceof Map) flattenObject(root, c, bud, verb, params);
        else addTodo(c, verb, "not_object", "the schema is not an object schema: the def has no parameters");
        Draft d = new Draft();
        String[] parts = verb.split("\\.", -1);
        d.name = String.join("_", java.util.Arrays.copyOfRange(parts, 1, parts.length));
        d.verb = verb;
        d.title = opts.get("title") != null ? opts.get("title") : root.get("title") instanceof String ? root.get("title") : null;
        d.description = opts.get("description") != null ? opts.get("description") : clip(root.get("description"), 600);
        d.effects = effects;
        d.scope = "one";
        d.params = params;
        d.bindings = new LinkedHashMap<>();
        emitDef(c, d);
        return finish(c);
    }
}
