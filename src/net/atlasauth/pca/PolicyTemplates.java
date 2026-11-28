package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Policy templates and a fluent authoring builder: the deterministic backbone of "natural language to policy". A request maps onto a named
 * ROLE template (read-only, support agent, finance bot, dev assistant) or is composed with the typed builder; both compile through the
 * facade's {@code compilePolicy}, so what you author is exactly what the verifier enforces. Pure.
 */
public final class PolicyTemplates {
    private PolicyTemplates() {}

    /** A named role template: permissions (connector to actions), optional limits and risk-policy members. */
    public static final class PolicyTemplate {
        public final String name, description;
        public final Map<String, Object> permissions;
        public final Map<String, Object> limits, riskPolicy;
        PolicyTemplate(String name, String description, Map<String, Object> permissions, Map<String, Object> limits, Map<String, Object> riskPolicy) {
            this.name = name; this.description = description; this.permissions = permissions; this.limits = limits; this.riskPolicy = riskPolicy;
        }
    }

    private static Map<String, Object> perms(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            List<Object> actions = new ArrayList<>();
            for (String a : (String[]) kv[i + 1]) actions.add(a);
            m.put((String) kv[i], actions);
        }
        return m;
    }

    private static Map<String, Object> limits(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    /** Built-in role templates: conservative starting points, meant to be narrowed, not widened. */
    public static final Map<String, PolicyTemplate> TEMPLATES;
    static {
        Map<String, PolicyTemplate> t = new LinkedHashMap<>();
        t.put("read-only", new PolicyTemplate("read-only", "Read access only — no side effects anywhere.",
            perms("github", new String[] {"read"}, "slack", new String[] {"read"}, "files", new String[] {"read"}, "http", new String[] {"get"}), null, null));
        t.put("support-agent", new PolicyTemplate("support-agent", "Draft + send customer email and post to Slack, rate-limited.",
            perms("gmail", new String[] {"draft", "send"}, "slack", new String[] {"post_message"}), limits("send", "50/day", "post_message", "100/day"), null));
        t.put("finance-bot", new PolicyTemplate("finance-bot", "Issue reversible refunds within a daily cap; no payouts.",
            perms("stripe", new String[] {"refund"}), limits("refund", "$500/day"), null));
        t.put("dev-assistant", new PolicyTemplate("dev-assistant", "Read repos, open PRs and comment — never merge or delete.",
            perms("github", new String[] {"read", "create_pr", "comment"}), limits("create_pr", "20/day"), null));
        TEMPLATES = Collections.unmodifiableMap(t);
    }

    public static List<PolicyTemplate> listTemplates() { return new ArrayList<>(TEMPLATES.values()); }

    /** Inputs of {@link #fromTemplate}; the {@code overrides} members (permissions, limits, riskPolicy, agentBinding, budgetModel) replace the template's. */
    public static final class FromTemplateOptions {
        public Keys.SuiteKey principal, holder;
        public String goal, aud, budgetModel;
        public Long now;
        public Map<String, Object> permissions, limits, riskPolicy, agentBinding;
        public FromTemplateOptions(Keys.SuiteKey principal, String goal) { this.principal = principal; this.goal = goal; }
    }

    /** Mint an agent from a named template. Throws IllegalArgumentException on an unknown template. */
    public static Facade.Handle fromTemplate(String name, FromTemplateOptions o) {
        PolicyTemplate t = name == null ? null : TEMPLATES.get(name);
        if (t == null) throw new IllegalArgumentException("fromTemplate: unknown template '" + name + "' (have: " + String.join(", ", TEMPLATES.keySet()) + ")");
        Facade.AgentOptions a = new Facade.AgentOptions(o.principal, o.goal, o.permissions != null ? o.permissions : t.permissions);
        Map<String, Object> lim = o.limits != null ? o.limits : t.limits;
        if (lim != null) a.limits(lim);
        Map<String, Object> risk = o.riskPolicy != null ? o.riskPolicy : t.riskPolicy;
        if (risk != null) a.riskPolicy(risk);
        if (o.agentBinding != null) a.agentBinding(o.agentBinding);
        if (o.budgetModel != null) a.budgetModel(o.budgetModel);
        if (o.aud != null) a.aud(o.aud);
        if (o.holder != null) a.holder(o.holder);
        if (o.now != null) a.now(o.now);
        return Facade.agent(a);
    }

    /** The output of {@link PolicyBuilder#build}: permissions, limits and an optional risk-policy override. */
    public static final class BuiltPolicy {
        public final Map<String, Object> permissions, limits, riskPolicy;
        BuiltPolicy(Map<String, Object> permissions, Map<String, Object> limits, Map<String, Object> riskPolicy) { this.permissions = permissions; this.limits = limits; this.riskPolicy = riskPolicy; }
    }

    /** A typed, chainable policy builder: {@code policy().allow("stripe", List.of("refund")).limit("refund", "$500/day")}. */
    public static final class PolicyBuilder {
        private final Map<String, Object> perms = new LinkedHashMap<>();
        private final Map<String, Object> lims = new LinkedHashMap<>();
        private Map<String, Object> riskOverride;

        /** Start from a named template (its permissions, limits and risk seed the builder). */
        public static PolicyBuilder from(String name) {
            PolicyTemplate t = name == null ? null : TEMPLATES.get(name);
            if (t == null) throw new IllegalArgumentException("PolicyBuilder.from: unknown template '" + name + "'");
            PolicyBuilder b = new PolicyBuilder();
            for (Map.Entry<String, Object> e : t.permissions.entrySet()) b.allow(e.getKey(), strings(e.getValue()));
            if (t.limits != null) for (Map.Entry<String, Object> e : t.limits.entrySet()) b.limit(e.getKey(), (String) e.getValue());
            if (t.riskPolicy != null) b.risk(t.riskPolicy);
            return b;
        }

        private static List<String> strings(Object o) {
            List<String> out = new ArrayList<>();
            for (Object x : (List<?>) o) out.add((String) x);
            return out;
        }

        /** Allow {@code actions} on a connector (the union with what was allowed before, first-seen order). */
        public PolicyBuilder allow(String connector, List<String> actions) {
            Set<String> merged = new LinkedHashSet<>();
            Object cur = perms.get(connector);
            if (cur instanceof List) merged.addAll(strings(cur));
            merged.addAll(actions);
            perms.put(connector, new ArrayList<Object>(merged));
            return this;
        }

        public PolicyBuilder limit(String verbOrAction, String spec) { lims.put(verbOrAction, spec); return this; }

        /** Merge risk-policy members over the earlier ones. */
        public PolicyBuilder risk(Map<String, Object> partial) {
            Map<String, Object> m = new LinkedHashMap<>();
            if (riskOverride != null) m.putAll(riskOverride);
            m.putAll(partial);
            riskOverride = m;
            return this;
        }

        /** The built policy (a deep copy). Throws when no permission was added. */
        public BuiltPolicy build() {
            if (perms.isEmpty()) throw new IllegalStateException("PolicyBuilder: no permissions added");
            Map<String, Object> p = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : perms.entrySet()) p.put(e.getKey(), new ArrayList<Object>((List<?>) e.getValue()));
            return new BuiltPolicy(p, new LinkedHashMap<>(lims), riskOverride == null ? null : new LinkedHashMap<>(riskOverride));
        }

        /** Mint an agent directly from the built policy. */
        public Facade.Handle agent(Keys.SuiteKey principal, String goal, String aud, Keys.SuiteKey holder, Long now) {
            BuiltPolicy b = build();
            Facade.AgentOptions a = new Facade.AgentOptions(principal, goal, b.permissions).limits(b.limits);
            if (b.riskPolicy != null) a.riskPolicy(b.riskPolicy);
            if (aud != null) a.aud(aud);
            if (holder != null) a.holder(holder);
            if (now != null) a.now(now);
            return Facade.agent(a);
        }
    }

    /** Entry point for the fluent builder. */
    public static PolicyBuilder policy() { return new PolicyBuilder(); }
}
