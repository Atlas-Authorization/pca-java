package net.atlasauth.pca;

import java.util.List;
import java.util.Map;

/** Public access to the package-private helpers of the action kit, for the action-kit ports in {@code net.atlasauth.pca.actions}. */
public final class ActionsBridge {
    private ActionsBridge() {}

    /** The machine/author view of a def's traits: declared plus implied by its own facts. */
    public static List<String> hintTraits(Map<String, Object> d) { return Actions.hintTraits(d); }

    /** Traits implied by effects, roles, tags, scope and reversibility. */
    public static List<String> impliedFromFacts(List<?> effects, List<Map<String, Object>> params, String scope, String worstRev) {
        return Actions.impliedFromFacts(effects, params, scope, worstRev);
    }

    /** Conservative class of a (possibly value-dependent) reversibility declaration. */
    public static String worstReversibility(Object rev, Map<String, Object> params) { return Actions.worstReversibility(rev, params); }

    /** A parameter's sensitivity after the role and tag floors. */
    public static String effectiveParamSensitivity(Map<String, Object> param) { return Actions.effectiveParamSensitivity(param); }

    /** The reversibility rank (reversible 0, rate_limited 1, irreversible 2). */
    public static int revRank(String r) { return Actions.revRank(r); }

    /** The sensitivity floor a core role implies ({@code free} when the role has none). */
    public static String roleSensitivityFloor(String role) { String f = Actions.ROLE_SENSITIVITY_FLOOR.get(role); return f; }

    /** The ids of the core roles. */
    public static List<String> coreRoles() { return Actions.CORE_ROLES; }

    /** Is the role a context key (approval_ref ... or a taint context)? */
    public static boolean isContextKey(Object k) { return Actions.isContextKey(k); }

    /** Is the value a known role (core role, or a custom role id)? */
    public static boolean isRole(Object r) { return Actions.isRole(r); }

    /** Is the value a known param format (a listed format or an {@code id:} format)? */
    public static boolean isFormat(Object f) { return Actions.isFormat(f); }

    /** The known effects. */
    public static List<String> effects() { return Actions.EFFECTS; }

    /** The known fixed context keys. */
    public static List<String> contextKeys() { return Actions.CONTEXT_KEYS; }
}
