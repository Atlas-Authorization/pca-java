package net.atlasauth.pca.actions.importers;

import static net.atlasauth.pca.actions.importers.ImportCommon.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.Actions.ActionKitError;
import net.atlasauth.pca.IntentJs;

/**
 * AsyncAPI 2.x / 3.x to drafts. Sending to a channel is effect {@code send}, receiving is {@code read}; the message payload becomes the
 * params. A broker publish leaves the trust domain, so it stays {@code send} unless the channel carries the allow-listed {@code x-pca-internal: true}.
 */
public final class AsyncApiImporter {
    private AsyncApiImporter() {}

    private static final Pattern VERSION = Pattern.compile("^[23]\\.");

    private static Map<String, Object> deref(Ctx c, Object x, String where, int depth) {
        if (!(x instanceof Map)) return null;
        Map<String, Object> m = Jx.m(x);
        if (!(m.get("$ref") instanceof String)) return m;
        if (depth > c.lim.maxRefDepth) { addTodo(c, where, "ref_depth", "a reference chain is too deep"); return null; }
        Object t = pointer(c.root, m.get("$ref"));
        if (t == null) { addTodo(c, where, "unresolved_ref", "reference '" + clip(m.get("$ref"), 120) + "' does not resolve locally"); return null; }
        return deref(c, t, where, depth + 1);
    }

    private static Map<String, Object> deref(Ctx c, Object x, String where) { return deref(c, x, where, 0); }

    private static void payloadParams(Ctx c, List<Object> msgs, String where, Map<String, Object> params, Budget bud) {
        List<Map<String, Object>> resolved = new ArrayList<>();
        for (Object m : msgs) { Map<String, Object> r = deref(c, m, where); if (r != null) resolved.add(r); }
        if (resolved.isEmpty()) return;
        if (resolved.size() > 1) addTodo(c, where, "message_variants", resolved.size() + " message variants: only the first is declared");
        Object payload = Jx.getU(resolved.get(0), "payload");
        if (payload == Jx.UNDEF) return;
        Map<String, Object> s = resolveSchema(payload, c, bud, where + ": payload");
        if ("object".equals(s.get("type")) || s.get("properties") instanceof Map) flattenObject(s, c, bud, where, params);
        else addTodo(c, where, "payload_shape", "the message payload is not an object schema; it is not declared");
    }

    private static void channelParams(Ctx c, Map<String, Object> ch, String where, Map<String, Object> params) {
        Map<String, Object> ps = deref(c, ch.get("parameters"), where);
        if (ps == null) return;
        List<String> names = new ArrayList<>(ps.keySet());
        names.sort(IntentJs::compareUtf8);
        for (String name : names) {
            String s = paramSeg(name);
            if (params.containsKey(s)) continue;
            params.put(s, Jx.obj("type", "string", "max_len", Jx.n(256)));
        }
    }

    private static void emit(Ctx c, Map<String, Object> source, String ns, String opName, String chName, Map<String, Object> ch, String action, Map<String, Object> op, List<Object> msgs) {
        String where = action + " " + clip(chName, 100);
        Budget bud = newBudget(c);
        c.root = source;
        Map<String, Object> params = new LinkedHashMap<>();
        channelParams(c, ch, where, params);
        payloadParams(c, msgs, where, params, bud);
        boolean internal = c.ext.contains("x-pca-internal") && Boolean.TRUE.equals(ch.get("x-pca-internal"));
        Draft d = new Draft();
        d.name = opName != null ? opName : where;
        d.noAlias = opName == null;
        d.verb = opName == null ? verbOf(ns, chName + " " + action) : null;
        d.title = op.get("summary") instanceof String ? op.get("summary") : null;
        d.description = op.get("description") instanceof String ? op.get("description") : null;
        d.effects = new ArrayList<>(List.of(action.equals("receive") ? "read" : internal ? "create" : "send"));
        d.scope = "one";
        d.params = params;
        d.bindings = Jx.obj("asyncapi", Jx.obj("channel", clip(chName, 250), "op", action));
        emitDef(c, d);
    }

    public static Map<String, Object> importAsyncApi(Object source, Map<String, Object> opts) {
        Ctx c = newCtx("asyncapi", source, opts);
        if (!(source instanceof Map) || !(Jx.m(source).get("asyncapi") instanceof String) || !VERSION.matcher((String) Jx.m(source).get("asyncapi")).find())
            throw new ActionKitError("bad_source", "not an AsyncAPI 2.x or 3.x document (missing 'asyncapi: 2.x|3.x')");
        Map<String, Object> src = Jx.m(source);
        String ns = (String) opts.get("ns");
        boolean v3 = ((String) src.get("asyncapi")).startsWith("3");
        Map<String, Object> channels = src.get("channels") instanceof Map ? Jx.m(src.get("channels")) : new LinkedHashMap<>();
        if (v3) {
            Map<String, Object> ops = src.get("operations") instanceof Map ? Jx.m(src.get("operations")) : new LinkedHashMap<>();
            List<String> ids = new ArrayList<>(ops.keySet());
            ids.sort(IntentJs::compareUtf8);
            for (String id : ids) {
                Map<String, Object> op = deref(c, ops.get(id), id);
                if (op == null || (!"send".equals(op.get("action")) && !"receive".equals(op.get("action")))) { addTodo(c, id, "skipped_op", "an operation without action send|receive is skipped"); continue; }
                Map<String, Object> chRef = deref(c, op.get("channel"), id);
                if (chRef == null) continue;
                String chName;
                if (chRef.get("address") instanceof String) chName = (String) chRef.get("address");
                else if (op.get("channel") instanceof Map && Jx.m(op.get("channel")).get("$ref") instanceof String) {
                    String[] p = ((String) Jx.m(op.get("channel")).get("$ref")).split("/", -1);
                    chName = p[p.length - 1];
                } else chName = id;
                List<Object> msgs;
                if (op.get("messages") instanceof List && !Jx.a(op.get("messages")).isEmpty()) msgs = Jx.a(op.get("messages"));
                else if (chRef.get("messages") instanceof Map) {
                    Map<String, Object> cm = Jx.m(chRef.get("messages"));
                    List<String> ks = new ArrayList<>(cm.keySet());
                    ks.sort(IntentJs::compareUtf8);
                    msgs = new ArrayList<>();
                    for (String k : ks) msgs.add(cm.get(k));
                } else msgs = new ArrayList<>();
                emit(c, src, ns, id, chName, chRef, (String) op.get("action"), op, msgs);
            }
        } else {
            List<String> chNames = new ArrayList<>(channels.keySet());
            chNames.sort(IntentJs::compareUtf8);
            for (String chName : chNames) {
                Map<String, Object> ch = deref(c, channels.get(chName), chName);
                if (ch == null) continue;
                // 2.x: publish is what a client does to the channel (a send); subscribe is what a client receives
                for (String[] ka : new String[][] {{"publish", "send"}, {"subscribe", "receive"}}) {
                    Map<String, Object> op = deref(c, ch.get(ka[0]), chName);
                    if (op == null) continue;
                    Map<String, Object> m = deref(c, op.get("message"), chName);
                    List<Object> msgs = m != null && m.get("oneOf") instanceof List ? Jx.a(m.get("oneOf")) : m != null ? Jx.list(m) : new ArrayList<>();
                    String oid = op.get("operationId") instanceof String && !((String) op.get("operationId")).isEmpty() ? (String) op.get("operationId") : null;
                    emit(c, src, ns, oid, chName, ch, ka[1], op, msgs);
                }
            }
        }
        return finish(c);
    }
}
