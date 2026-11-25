package net.atlasauth.pca.ai;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.function.Function;
import net.atlasauth.pca.ArgProvenance;
import net.atlasauth.pca.Facade;
import net.atlasauth.pca.Json;

/**
 * Feeds a conversation into the agent's provenance chain: which messages are the PRINCIPAL's (trusted) and which are tool output
 * (untrusted). Framework adapters call {@link #recordMessages} before each model turn and {@link #recordInput} with the request they were
 * handed; a conversation shape this does not understand records nothing, so the provenance gate keeps the context at {@code agent}
 * (fail closed). A {@code target} is a {@link Prover}, an {@link ArgProvenance.Recorder} or a {@link Facade.Handle}.
 */
public final class Messages {
    private Messages() {}

    /** One context segment a chat message adds: {@code origin} is {@code principal} or {@code tool}. */
    public static final class Segment {
        public final String origin, source;
        public final Object content;
        Segment(String origin, String source, Object content) { this.origin = origin; this.source = source; this.content = content; }
    }

    private static final Set<String> PRINCIPAL_ROLES = Set.of("user", "human");
    private static final Set<String> MODEL_ROLES = Set.of("assistant", "ai", "model", "system", "developer");

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static String roleOf(Map<String, Object> m) {
        if (m.get("role") instanceof String) return (String) m.get("role");
        return m.get("type") instanceof String ? (String) m.get("type") : "";
    }

    /** {@code String(v)} for a JSON value. */
    private static String text(Object v) { return v == null ? "null" : v instanceof String ? (String) v : Json.stringify(v); }

    private static String toolName(Map<String, Object> x, Map<String, Object> msg) {
        for (String k : new String[] {"toolName", "name", "tool_use_id", "toolCallId", "tool_call_id"}) if (x.get(k) != null) return text(x.get(k));
        for (String k : new String[] {"name", "tool_call_id"}) if (msg.get(k) != null) return text(msg.get(k));
        return "tool";
    }

    /**
     * The context segments a chat message adds, by the conversation's own roles: a user / human turn is the PRINCIPAL (its text, and its other
     * parts); a {@code tool_result} / {@code tool-result} / {@code function_call_output} part inside any turn, a {@code tool} / {@code function}
     * turn and a turn of an unknown role are UNTRUSTED tool output; assistant, system and developer turns add nothing (the model's output and the
     * developer's prompt are not the principal's choice).
     */
    public static List<Segment> messageSegments(Object m) {
        List<Segment> out = new ArrayList<>();
        Map<String, Object> msg = obj(m);
        if (msg == null) return out;
        String role = roleOf(msg).toLowerCase(java.util.Locale.ROOT);
        if (MODEL_ROLES.contains(role)) return out;
        Object content = msg.get("content");
        if (!PRINCIPAL_ROLES.contains(role)) {
            out.add(new Segment("tool", toolName(msg, msg), content != null ? content : msg));
            return out;
        }
        if (!(content instanceof List)) {
            out.add(new Segment("principal", "user", content != null ? content : ""));
            return out;
        }
        List<String> texts = new ArrayList<>();
        for (Object part : (List<?>) content) {
            Map<String, Object> pt = obj(part);
            if (pt == null) { texts.add(text(part)); continue; }
            String t = pt.get("type") instanceof String ? (String) pt.get("type") : "";
            if (t.equals("tool_result") || t.equals("tool-result") || t.equals("function_call_output")) {
                Object c = pt.get("content") != null ? pt.get("content") : pt.get("result") != null ? pt.get("result") : pt.get("output") != null ? pt.get("output") : pt;
                out.add(new Segment("tool", toolName(pt, msg), c));
            } else if (pt.get("text") instanceof String) texts.add((String) pt.get("text"));
            else out.add(new Segment("principal", "user", pt));
        }
        if (!texts.isEmpty()) out.add(0, new Segment("principal", "user", String.join("\n", texts)));
        return out;
    }

    /** Where the segments go: a recorder's two entry points. */
    private interface Sink {
        void principal(String text);
        void tool(String source, Object content);
    }

    private static Sink sinkOf(Object target) {
        if (target instanceof Prover) {
            Prover p = (Prover) target;
            return new Sink() {
                @Override public void principal(String t) { p.principal(t); }
                @Override public void tool(String s, Object c) { p.tool(s, c); }
            };
        }
        ArgProvenance.Recorder r = target instanceof ArgProvenance.Recorder ? (ArgProvenance.Recorder) target : target instanceof Facade.Handle ? ((Facade.Handle) target).provenance : null;
        if (r == null) return null;
        return new Sink() {
            @Override public void principal(String t) { r.principal(t); }
            @Override public void tool(String s, Object c) { r.tool(s, c); }
        };
    }

    private static final Map<Object, Integer> SEEN = Collections.synchronizedMap(new WeakHashMap<>());

    /**
     * Record a conversation's new messages (call it with the whole list before each model turn: messages already recorded are skipped and a
     * shorter list starts over). A null target or a non-list records nothing.
     */
    public static void recordMessages(Object target, List<?> messages) {
        Sink sink = sinkOf(target);
        if (sink == null || messages == null) return;
        int from = SEEN.getOrDefault(target, 0);
        int start = messages.size() < from ? 0 : from;
        for (int i = start; i < messages.size(); i++) {
            for (Segment seg : messageSegments(messages.get(i))) {
                if (seg.origin.equals("principal")) sink.principal(seg.content instanceof String ? (String) seg.content : Json.stringify(seg.content));
                else sink.tool(seg.source, seg.content);
            }
        }
        SEEN.put(target, messages.size());
    }

    /**
     * Record what the principal asked for: a string is the principal's message; a message list (or {@code {messages}}) is recorded with
     * {@link #recordMessages}; an object's {@code input} / {@code prompt} / {@code query} / {@code question} / {@code message} / {@code text}
     * string (or message list) is the principal's message. Anything else records nothing.
     */
    public static void recordInput(Object target, Object input) {
        Sink sink = sinkOf(target);
        if (sink == null) return;
        if (input instanceof String) sink.principal((String) input);
        else if (input instanceof List) recordMessages(target, (List<?>) input);
        else if (obj(input) != null) {
            Map<String, Object> o = obj(input);
            if (o.get("messages") instanceof List) recordMessages(target, (List<?>) o.get("messages"));
            for (String k : new String[] {"input", "prompt", "query", "question", "message", "text"}) {
                Object v = o.get(k);
                if (v instanceof String) sink.principal((String) v);
                else if (v instanceof List) recordMessages(target, (List<?>) v);
            }
        }
    }

    /** Wrap a framework entry point so its first argument, the principal's request, is recorded before it runs. */
    public static <A, R> Function<A, R> withPrincipalInput(Object target, Function<A, R> fn) {
        return a -> {
            recordInput(target, a);
            return fn.apply(a);
        };
    }

    /**
     * Wrap a model call that takes a request map with {@code messages} ({@code chat.completions.create}, {@code messages.create}, ...) so every
     * model turn first records the conversation's new messages: user turns are the principal, tool turns untrusted.
     */
    public static <R> Function<Map<String, Object>, R> withPcaMessages(Object target, Function<Map<String, Object>, R> create) {
        return params -> {
            if (params != null && params.get("messages") instanceof List) recordMessages(target, (List<?>) params.get("messages"));
            return create.apply(params);
        };
    }

    /** The OpenAI spelling of {@link #withPcaMessages}. */
    public static <R> Function<Map<String, Object>, R> withPcaCompletions(Object target, Function<Map<String, Object>, R> create) { return withPcaMessages(target, create); }
}
