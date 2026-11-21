package net.atlasauth.pca.actions;

import java.util.Collection;
import java.util.Map;

/**
 * Trait selectors and the registry-growth semantics. A selector is a positive predicate over the trait closure of an action.
 * Prohibit selectors float (they cover every present and future action that matches); allow selectors are pinned to a set of
 * verbs and may not use negation (the absence of a trait is never a safety claim). A selector is {@code {k: 'trait', id}},
 * {@code {k: 'all_of'|'any_of', ids}}, {@code {k: 'not', s}} or {@code {k: 'and', a, b}}.
 */
public final class ActionSelectors {
    private ActionSelectors() {}

    /** Does the selector match an action whose trait closure is {@code closure}? */
    public static boolean selectorMatches(Object s, Collection<?> closure) {
        Object k = J.get(s, "k");
        if ("trait".equals(k)) return closure.contains(J.get(s, "id"));
        if ("all_of".equals(k)) { for (Object i : J.a(J.get(s, "ids"))) if (!closure.contains(i)) return false; return true; }
        if ("any_of".equals(k)) { for (Object i : J.a(J.get(s, "ids"))) if (closure.contains(i)) return true; return false; }
        if ("not".equals(k)) return !selectorMatches(J.get(s, "s"), closure);
        if ("and".equals(k)) return selectorMatches(J.get(s, "a"), closure) && selectorMatches(J.get(s, "b"), closure);
        throw new IllegalArgumentException("unknown selector kind");
    }

    /**
     * Does a selector of the given mode ({@code allow} or {@code prohibit}) match an action? An UNCONFIRMED action is maximally
     * dangerous: every prohibit selector matches it whatever it says, and no allow selector ever does.
     */
    public static boolean selectorMatchesFor(Object s, String mode, Collection<?> closure, boolean confirmed) {
        if (!confirmed) return "prohibit".equals(mode);
        return selectorMatches(s, closure);
    }

    public static boolean selectorHasNot(Object s) {
        Object k = J.get(s, "k");
        return "not".equals(k) || ("and".equals(k) && (selectorHasNot(J.get(s, "a")) || selectorHasNot(J.get(s, "b"))));
    }

    private static boolean anyOf(Object s) {
        Object k = J.get(s, "k");
        return "any_of".equals(k) || ("and".equals(k) && (anyOf(J.get(s, "a")) || anyOf(J.get(s, "b"))));
    }

    /** The typing rule for an ALLOW selector: no negation anywhere, and any_of only inside a pinned allow. Null = allowed. */
    public static String allowSelectorError(Object s, boolean pinned) {
        if (selectorHasNot(s)) return "an allow selector must not use negation: the absence of a trait is never a safety claim";
        if (!pinned && anyOf(s)) return "any_of in an allow selector requires the grant to be pinned to a pack digest";
        return null;
    }

    /**
     * The policy component of the decision for one action: a matching prohibit denies; otherwise a pinned verb with a matching allow
     * is allowed; an unpinned verb is deny/escalate; a pinned verb with no allow is deny. {@code p} is
     * {@code {pinned, allow, prohibit, on_new_action?}}.
     */
    public static String policyDecision(Map<String, Object> p, String verb, Collection<?> closure, boolean confirmed) {
        for (Object s : J.a(p.get("prohibit"))) if (selectorMatchesFor(s, "prohibit", closure, confirmed)) return "deny";
        if (!J.a(p.get("pinned")).contains(verb)) return "escalate".equals(p.get("on_new_action")) ? "escalate" : "deny";
        for (Object s : J.a(p.get("allow"))) if (selectorMatchesFor(s, "allow", closure, confirmed)) return "allow";
        return "deny";
    }
}
