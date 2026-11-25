package net.atlasauth.pca.a2a;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Json;

/**
 * Two things A2A 1.0 section 8.4 needs from an Agent Card implementation: {@link #jcsBytes} (RFC 8785 canonical JSON, the bytes a card
 * signature covers) and {@link #validateAgentCard1} (the A2A 1.0 {@code AgentCard} message). Shared by the A2A and agent-card ports.
 * Values are parsed JSON (Map, List, String, Boolean, {@link Json.Num}, null) or plain Java numbers.
 */
public final class A2aCard {
    private A2aCard() {}

    private static final int MAX_DEPTH = 64;

    /** RFC 8785 canonical UTF-8 bytes of a JSON value; IllegalArgumentException for a value with no JSON form (non-finite number, lone surrogate, nesting over 64). */
    public static byte[] jcsBytes(Object value) { return jcs(value, 1).getBytes(StandardCharsets.UTF_8); }

    private static String jcs(Object v, int depth) {
        if (v == null) return "null";
        if (v instanceof Boolean) return ((Boolean) v) ? "true" : "false";
        if (v instanceof Json.Num || v instanceof Number) {
            double d = v instanceof Json.Num ? Double.parseDouble(((Json.Num) v).raw) : ((Number) v).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) throw new IllegalArgumentException("jcs: non-finite number");
            return AttestCommon.jsNumString(d); // -0 prints 0, as RFC 8785 requires
        }
        if (v instanceof String) return str((String) v, "jcs: lone surrogate in string");
        if (!(v instanceof Map) && !(v instanceof List)) throw new IllegalArgumentException("jcs: unsupported type");
        if (depth > MAX_DEPTH) throw new IllegalArgumentException("jcs: nesting too deep");
        StringBuilder sb = new StringBuilder();
        if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) sb.append(',');
                first = false;
                sb.append(jcs(x, depth + 1));
            }
            return sb.append(']').toString();
        }
        Map<?, ?> m = (Map<?, ?>) v;
        List<String> keys = new ArrayList<>();
        for (Object k : m.keySet()) keys.add((String) k);
        Collections.sort(keys); // String.compareTo is UTF-16 code unit order, as the default JavaScript sort
        sb.append('{');
        boolean first = true;
        for (String k : keys) {
            if (!first) sb.append(',');
            first = false;
            sb.append(str(k, "jcs: lone surrogate in key")).append(':').append(jcs(m.get(k), depth + 1));
        }
        return sb.append('}').toString();
    }

    /** JSON.stringify of a string (well-formed: a lone surrogate is refused first). */
    static String str(String s, String loneMsg) {
        if (Json.hasLoneSurrogate(s)) throw new IllegalArgumentException(loneMsg);
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) c)); else sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    private static boolean isObj(Object v) { return v instanceof Map; }
    private static boolean isStr(Object v) { return v instanceof String; }
    private static Object get(Object o, String k) { return ((Map<?, ?>) o).get(k); }
    private static boolean has(Object o, String k) { return ((Map<?, ?>) o).containsKey(k); }

    private static void reqStr(List<String> p, Object o, String k, String at) {
        if (!isStr(get(o, k)) || "".equals(get(o, k))) p.add(at + "." + k + ": required non-empty string");
    }
    private static void optStr(List<String> p, Object o, String k, String at) {
        if (has(o, k) && !isStr(get(o, k))) p.add(at + "." + k + ": must be a string");
    }
    private static void optBool(List<String> p, Object o, String k, String at) {
        if (has(o, k) && !(get(o, k) instanceof Boolean)) p.add(at + "." + k + ": must be a boolean");
    }
    private static void strArray(List<String> p, Object v, String at, boolean nonEmpty) {
        boolean ok = v instanceof List;
        if (ok) for (Object x : (List<?>) v) if (!isStr(x)) { ok = false; break; }
        if (!ok) p.add(at + ": must be an array of strings");
        else if (nonEmpty && ((List<?>) v).isEmpty()) p.add(at + ": must not be empty");
    }

    private interface Each { void run(Object e, String at); }

    private static void objArray(List<String> p, Object o, String k, String at, boolean required, boolean nonEmpty, Each each) {
        if (!has(o, k)) {
            if (required) p.add(at + "." + k + ": required array");
            return;
        }
        Object v = get(o, k);
        if (!(v instanceof List)) { p.add(at + "." + k + ": must be an array"); return; }
        List<?> l = (List<?>) v;
        if (nonEmpty && l.isEmpty()) p.add(at + "." + k + ": must not be empty");
        for (int i = 0; i < l.size(); i++) {
            String ea = at + "." + k + "[" + i + "]";
            if (isObj(l.get(i))) each.run(l.get(i), ea); else p.add(ea + ": must be an object");
        }
    }

    /** Check an object against the A2A 1.0 {@code AgentCard} message. Returns the problems found, each with a JSON path (empty = valid). */
    public static List<String> validateAgentCard1(Object card) {
        List<String> p = new ArrayList<>();
        if (!isObj(card)) { p.add("$: the agent card must be an object"); return p; }
        reqStr(p, card, "name", "$");
        reqStr(p, card, "description", "$");
        reqStr(p, card, "version", "$");
        optStr(p, card, "documentationUrl", "$");
        optStr(p, card, "iconUrl", "$");
        objArray(p, card, "supportedInterfaces", "$", true, true, (e, at) -> {
            reqStr(p, e, "url", at);
            reqStr(p, e, "protocolBinding", at);
            reqStr(p, e, "protocolVersion", at);
            optStr(p, e, "tenant", at);
        });
        if (has(card, "provider")) {
            Object pr = get(card, "provider");
            if (!isObj(pr)) p.add("$.provider: must be an object");
            else {
                reqStr(p, pr, "url", "$.provider");
                reqStr(p, pr, "organization", "$.provider");
            }
        }
        if (!isObj(get(card, "capabilities"))) p.add("$.capabilities: required object");
        else {
            Object c = get(card, "capabilities");
            optBool(p, c, "streaming", "$.capabilities");
            optBool(p, c, "pushNotifications", "$.capabilities");
            optBool(p, c, "extendedAgentCard", "$.capabilities");
            objArray(p, c, "extensions", "$.capabilities", false, false, (e, at) -> {
                optStr(p, e, "uri", at);
                optStr(p, e, "description", at);
                optBool(p, e, "required", at);
                if (has(e, "params") && !isObj(get(e, "params"))) p.add(at + ".params: must be an object");
            });
        }
        if (has(card, "securitySchemes") && !isObj(get(card, "securitySchemes"))) p.add("$.securitySchemes: must be an object");
        if (has(card, "securityRequirements") && !(get(card, "securityRequirements") instanceof List)) p.add("$.securityRequirements: must be an array");
        if (!has(card, "defaultInputModes")) p.add("$.defaultInputModes: required array of strings");
        else strArray(p, get(card, "defaultInputModes"), "$.defaultInputModes", true);
        if (!has(card, "defaultOutputModes")) p.add("$.defaultOutputModes: required array of strings");
        else strArray(p, get(card, "defaultOutputModes"), "$.defaultOutputModes", true);
        objArray(p, card, "skills", "$", true, false, (e, at) -> {
            reqStr(p, e, "id", at);
            reqStr(p, e, "name", at);
            reqStr(p, e, "description", at);
            if (!has(e, "tags")) p.add(at + ".tags: required array of strings");
            else strArray(p, get(e, "tags"), at + ".tags", false);
            for (String k : new String[] {"examples", "inputModes", "outputModes"}) if (has(e, k)) strArray(p, get(e, k), at + "." + k, false);
            if (has(e, "securityRequirements") && !(get(e, "securityRequirements") instanceof List)) p.add(at + ".securityRequirements: must be an array");
        });
        objArray(p, card, "signatures", "$", false, false, (e, at) -> {
            reqStr(p, e, "protected", at);
            reqStr(p, e, "signature", at);
            if (has(e, "header") && !isObj(get(e, "header"))) p.add(at + ".header: must be an object");
        });
        return p;
    }
}
