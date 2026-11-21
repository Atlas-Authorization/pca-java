package net.atlasauth.pca.policyci;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Pca;

/**
 * The action-kit lint rule list ({id, severity, title}, in order) and its digest. The list is part of what an action pack is checked
 * against, so a policy gate pins the digest: adding, removing or rewording a rule is a visible, reviewed change.
 */
public final class ActionLintRules {
    private ActionLintRules() {}

    public static final String LINT_RULES_DIGEST_DOMAIN = "atlas-pca/action-lint-rules/v1";

    /** The rules: {id, severity, title} rows. */
    public static final String[][] LINT_RULES = {
        { "LD-001", "error", "a destroy-like verb whose effects do not delete" },
        { "LD-002", "error", "a money parameter without a currency, or a currency without the iso_currency format" },
        { "LD-003", "error", "a numeric parameter without min and max" },
        { "LD-004", "error", "a money-moving action without idempotency" },
        { "LD-005", "error", "personal data can leave without the matching effect" },
        { "LD-006", "error", "a declared reversibility or blast below the effective floor" },
        { "LD-007", "error", "an unknown trait, role, format, effect or context key, or an invalid custom trait" },
        { "LD-008", "error", "resource id '*' with scope one" },
        { "LD-009", "error", "a duplicate verb or alias collision" },
        { "LD-010", "error", "a write marked reversible with no compensating action in the pack" },
        { "LD-011", "error", "review state confirmed without a valid attestation for this digest" },
        { "LD-012", "error", "a structural param rule that the effective traits require is violated" },
        { "LD-013", "error", "a read-only action that can mutate or handles credentials" },
        { "LD-014", "error", "one binding in two defs" },
        { "LW-001", "warning", "description missing or too long, or title not imperative" },
        { "LW-002", "warning", "a string parameter without max_len" },
        { "LW-003", "warning", "free text flows into an outbound action without the free_text_outbound tag" },
        { "LW-004", "warning", "an unreviewed def in a stable pack" },
        { "LW-005", "warning", "a dismissed suggested trait without a reason" },
        { "LW-006", "warning", "an array parameter without max_items" },
        { "LW-007", "warning", "a critical parameter without provenance_min" },
        { "LW-008", "warning", "verb naming inconsistent with its siblings or with the file namespace" },
        { "LW-009", "warning", "a money-moving, destructive or privilege-changing action without an example" },
        { "LW-010", "warning", "since is missing" },
    };

    /** The digest the policy gate pins: the canonical hash of the ordered (id, severity, title) list. */
    public static String lintRulesDigest() {
        List<Object> rules = new ArrayList<>();
        for (String[] r : LINT_RULES) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", r[0]);
            m.put("severity", r[1]);
            m.put("title", r[2]);
            rules.add(m);
        }
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("d", LINT_RULES_DIGEST_DOMAIN);
        doc.put("rules", rules);
        return Pca.hashCanonical(doc);
    }
}
