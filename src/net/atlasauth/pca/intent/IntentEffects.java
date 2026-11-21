package net.atlasauth.pca.intent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Predicates;
import net.atlasauth.pca.intent.IntentOmega.Outcome;
import net.atlasauth.pca.intent.IntentOmega.VerbSpace;

/**
 * Outcome verification: postconditions on observed effects. A postcondition is a set of conditions in the ordinary predicate
 * language over the requested action ({@code action.params.*}, {@code action.resource}) and the observed effect at
 * {@code env.effect.*}, evaluated by the one evaluator. A clause whose {@code ref} names an action parameter the action does not
 * carry is not applicable and is skipped. Results: ok, violated (a negative runtime observation), pending (the effect record
 * lacks a field a clause reads).
 */
public final class IntentEffects {
    private IntentEffects() {}

    private static Map<String, Object> leaf(String field, String op, String ref, Object value) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("field", "env.effect." + field);
        m.put("op", op);
        if (ref != null) m.put("ref", ref);
        else m.put("value", value);
        return m;
    }

    private static Map<String, Object> pc(String id, String verb, String description, Object... where) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("verb", verb);
        m.put("description", description);
        m.put("where", new ArrayList<Object>(List.of(where)));
        return m;
    }

    private static final Json.Num ZERO = new Json.Num("0");

    /** Postconditions for the built-in connectors' state-changing verbs. */
    public static final List<Map<String, Object>> DEFAULT_POSTCONDITIONS = Collections.unmodifiableList(List.of(
        pc("stripe.refund.amount", "stripe.refund", "the refunded amount is at most the requested amount", leaf("amount", "lte", "action.params.amount", null), leaf("amount", "gte", null, ZERO)),
        pc("stripe.refund.recipient", "stripe.refund", "the refund went to the requested recipient", leaf("recipient", "eq", "action.params.recipient", null)),
        pc("stripe.charge.amount", "stripe.charge", "the charged amount is at most the requested amount", leaf("amount", "lte", "action.params.amount", null), leaf("amount", "gte", null, ZERO)),
        pc("stripe.payout.amount", "stripe.payout", "the paid-out amount is at most the requested amount", leaf("amount", "lte", "action.params.amount", null), leaf("amount", "gte", null, ZERO)),
        pc("stripe.payout.recipient", "stripe.payout", "the payout went to the requested recipient", leaf("recipient", "eq", "action.params.recipient", null)),
        pc("gmail.send.to", "gmail.send", "the mail went only to the requested address", leaf("to", "eq", "action.params.to", null)),
        pc("slack.post_message.channel", "slack.post_message", "the message was posted in the requested channel", leaf("channel", "eq", "action.params.channel", null)),
        pc("files.write.path", "files.write", "the written path is the requested resource", leaf("path", "eq", "action.resource", null)),
        pc("files.delete.path", "files.delete", "the deleted path is the requested resource", leaf("path", "eq", "action.resource", null)),
        pc("github.merge_pr.repo", "github.merge_pr", "the merge landed in the requested repository", leaf("repo", "eq", "action.resource", null)),
        pc("calendar.create_event.hour", "calendar.create_event", "the event starts at the requested hour", leaf("hour", "eq", "env.hour", null))));

    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    private static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    private static void leaves(Object c, List<String[]> out) {
        if (!(c instanceof Map)) return;
        if (has(c, "all_of") || has(c, "any_of") || has(c, "not")) {
            if (has(c, "all_of") && get(c, "all_of") instanceof List) for (Object x : (List<?>) get(c, "all_of")) leaves(x, out);
            else if (has(c, "any_of") && get(c, "any_of") instanceof List) for (Object x : (List<?>) get(c, "any_of")) leaves(x, out);
            else if (has(c, "not")) leaves(get(c, "not"), out);
            return;
        }
        if (get(c, "field") instanceof String) out.add(new String[] {(String) get(c, "field"), get(c, "ref") instanceof String ? (String) get(c, "ref") : null});
    }

    /** The own-property walk of a dotted path; {@code found[0]} says whether the value exists (undefined = not found). */
    private static Object walk(Object root, String path, boolean[] found) {
        Object cur = root;
        for (String k : path.split("\\.", -1)) {
            if (!(cur instanceof Map) || !((Map<?, ?>) cur).containsKey(k)) { found[0] = false; return null; }
            cur = ((Map<?, ?>) cur).get(k);
        }
        found[0] = true;
        return cur;
    }

    private static boolean defined(Object root, String path) {
        boolean[] f = new boolean[1];
        walk(root, path, f);
        return f[0];
    }

    /** The evaluator's context for an action plus its observed effect. */
    public static Map<String, Object> effectContext(VerbSpace vs, Outcome o, Map<String, Object> effect) {
        Map<String, Object> a = IntentPolicy.outcomeToAction(vs, o);
        Map<String, Object> action = new LinkedHashMap<>();
        action.put("verb", a.get("verb"));
        action.put("resource", a.get("resource"));
        action.put("params", IntentRuntime.jsonNums(a.get("params")));
        action.put("reversibility_class", vs.reversibility);
        Map<String, Object> ctx = new LinkedHashMap<>();
        ctx.put("action", action);
        if (a.get("subject") != null) ctx.put("subject", IntentRuntime.jsonNums(a.get("subject")));
        Map<String, Object> env = new LinkedHashMap<>();
        if (a.get("env") != null) env.putAll(IntentOmega.obj(IntentRuntime.jsonNums(a.get("env"))));
        env.put("effect", effect);
        ctx.put("env", env);
        return ctx;
    }

    public static Map<String, Object> checkPostconditions(VerbSpace vs, Outcome o, Map<String, Object> effect) { return checkPostconditions(vs, o, effect, new ArrayList<Object>(DEFAULT_POSTCONDITIONS)); }

    /** {status, violated, missing, checked, notApplicable}. */
    public static Map<String, Object> checkPostconditions(VerbSpace vs, Outcome o, Map<String, Object> effect, List<?> pcs) {
        Map<String, Object> ctx = effectContext(vs, o, effect);
        List<String> violated = new ArrayList<>(), checked = new ArrayList<>(), notApplicable = new ArrayList<>();
        List<String> missing = new ArrayList<>();
        for (Object pc : pcs) {
            if (!o.verb().equals(get(pc, "verb"))) continue;
            List<String[]> ls = new ArrayList<>();
            for (Object c : (List<?>) get(pc, "where")) leaves(c, ls);
            boolean na = false;
            for (String[] l : ls) if (l[1] != null && !l[1].startsWith("env.effect.") && !defined(ctx, l[1])) na = true;
            if (na) { notApplicable.add((String) get(pc, "id")); continue; }
            Set<String> need = new LinkedHashSet<>();
            for (String[] l : ls) {
                if (l[0].startsWith("env.effect.")) need.add(l[0]);
                if (l[1] != null && !l[1].isEmpty() && l[1].startsWith("env.effect.")) need.add(l[1]);
            }
            List<String> lacking = new ArrayList<>();
            for (String f : need) if (!defined(ctx, f)) lacking.add(f);
            if (!lacking.isEmpty()) { missing.addAll(lacking); continue; }
            checked.add((String) get(pc, "id"));
            Map<String, Object> pred = new LinkedHashMap<>();
            pred.put("verb", o.verb());
            pred.put("resource", "*");
            pred.put("where", get(pc, "where"));
            if (!Predicates.evaluatePredicates(List.of(pred), ctx)) violated.add((String) get(pc, "id"));
        }
        List<String> miss = new ArrayList<>(new java.util.TreeSet<>(missing));
        Map<String, Object> rep = new LinkedHashMap<>();
        rep.put("status", !violated.isEmpty() ? "violated" : !miss.isEmpty() ? "pending" : "ok");
        rep.put("violated", new ArrayList<Object>(violated));
        rep.put("missing", new ArrayList<Object>(miss));
        rep.put("checked", new ArrayList<Object>(checked));
        rep.put("notApplicable", new ArrayList<Object>(notApplicable));
        return rep;
    }
}
