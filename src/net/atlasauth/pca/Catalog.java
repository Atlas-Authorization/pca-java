package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The connector catalog the facade compiles {@code permissions} against: each action's PCA verb, reversibility class, blast radius
 * and (for money-moving actions) the params field that carries the amount, plus the other names it answers to. This is data, not
 * enforcement: the resource server's verifier stays authoritative.
 *
 * <p>{@link #BUILTIN} is the reference's 21 built-in actions with their EFFECTIVE reversibility and blast radius. Generated data:
 * do not edit by hand (a test compares it with the reference catalog).
 */
public final class Catalog {
    /**
     * One catalogued action. {@code amountField} is null for an action that moves no money; {@code resource} is the predicate's
     * resource matcher, null for any resource ({@code *}).
     */
    public static final class Spec {
        public final String connector, action, verb, reversibility, amountField, description, resource;
        public final double blastRadius;
        public final List<String> aliases, traits;

        public Spec(String connector, String action, String verb, String reversibility, double blastRadius, String amountField, String description,
                    List<String> aliases, List<String> traits) {
            this(connector, action, verb, reversibility, blastRadius, amountField, description, aliases, traits, null);
        }

        public Spec(String connector, String action, String verb, String reversibility, double blastRadius, String amountField, String description,
                    List<String> aliases, List<String> traits, String resource) {
            this.connector = connector;
            this.action = action;
            this.verb = verb;
            this.reversibility = reversibility;
            this.blastRadius = blastRadius;
            this.amountField = amountField;
            this.description = description;
            this.resource = resource;
            this.aliases = aliases == null ? Collections.<String>emptyList() : Collections.unmodifiableList(new ArrayList<>(aliases));
            this.traits = traits == null ? Collections.<String>emptyList() : Collections.unmodifiableList(new ArrayList<>(traits));
        }

        /** The row as the reference's JSON object: {@code amountField}, {@code resource} and {@code aliases} only when set, {@code traits} always. */
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("connector", connector);
            m.put("action", action);
            m.put("verb", verb);
            m.put("reversibility", reversibility);
            m.put("blastRadius", StoreJs.num(blastRadius));
            if (amountField != null) m.put("amountField", amountField);
            if (resource != null) m.put("resource", resource);
            m.put("description", description);
            if (!aliases.isEmpty()) m.put("aliases", new ArrayList<Object>(aliases));
            m.put("traits", new ArrayList<Object>(traits));
            return m;
        }

        /** The typed view of a JSON row, or null when a member the typed view needs has another type (such a row stays reachable as JSON only). */
        static Spec of(Map<String, Object> m) {
            Double blast = IntentJs.num(m.get("blastRadius"));
            for (String k : new String[] {"connector", "action", "verb", "reversibility"}) if (!(m.get(k) instanceof String)) return null;
            if (blast == null || !optString(m, "amountField") || !optString(m, "description") || !optString(m, "resource")) return null;
            List<String> aliases = strings(m.get("aliases")), traits = strings(m.get("traits"));
            if (aliases == null || traits == null) return null;
            return new Spec((String) m.get("connector"), (String) m.get("action"), (String) m.get("verb"), (String) m.get("reversibility"), blast,
                (String) m.get("amountField"), (String) m.get("description"), aliases, traits, (String) m.get("resource"));
        }

        private static boolean optString(Map<String, Object> m, String k) { return m.get(k) == null || m.get(k) instanceof String; }

        private static List<String> strings(Object v) {
            List<String> out = new ArrayList<>();
            if (v == null) return out;
            if (!(v instanceof List)) return null;
            for (Object x : (List<?>) v) {
                if (!(x instanceof String)) return null;
                out.add((String) x);
            }
            return out;
        }
    }

    /** Blast-radius presets by shape of action: conservative, and a caller may override them. */
    public static final Map<String, Double> BLAST;
    static {
        Map<String, Double> m = new LinkedHashMap<>();
        m.put("read", 0.05); m.put("reversibleWrite", 0.2); m.put("rateLimitedWrite", 0.5); m.put("irreversibleWrite", 0.8); m.put("moneyMovement", 0.9);
        BLAST = Collections.unmodifiableMap(m);
    }

    // BEGIN GENERATED (the reference's built-in catalog)
    public static final List<Spec> BUILTIN = Collections.unmodifiableList(java.util.Arrays.asList(
        new Spec("stripe", "charge", "stripe.charge", "irreversible", 0.9, "amount", "Charge a customer. Refundable in practice, but a charge is treated as final.", java.util.Arrays.asList("bill", "charge_customer"), java.util.Arrays.asList("pca.irreversible", "pca.money_moving")),
        new Spec("stripe", "refund", "stripe.refund", "irreversible", 0.9, "amount", "Returns money for a charge to the customer.", java.util.Arrays.asList("issue_refund", "refund", "refund_charge", "reimburse"), java.util.Arrays.asList("pca.irreversible", "pca.money_moving")),
        new Spec("stripe", "payout", "stripe.payout", "irreversible", 0.9, "amount", "Moves funds from a Stripe balance to a bank account.", java.util.Arrays.asList("pay_out", "payout"), java.util.Arrays.asList("pca.irreversible", "pca.money_moving")),
        new Spec("stripe", "create_customer", "stripe.create_customer", "rate_limited", 0.2, null, "Creates a customer record.", java.util.Arrays.asList(), java.util.Arrays.asList("pca.pii_access")),
        new Spec("gmail", "send", "gmail.send", "irreversible", 0.8, null, "Sends an email to people outside your organisation.", java.util.Arrays.asList("send_email"), java.util.Arrays.asList("pca.external_communication", "pca.irreversible", "pca.pii_access")),
        new Spec("gmail", "draft", "gmail.draft", "reversible", 0.2, null, "Saves an email draft without sending it.", java.util.Arrays.asList(), java.util.Arrays.asList("pca.pii_access")),
        new Spec("gmail", "delete", "gmail.delete", "irreversible", 0.8, null, "Permanently deletes a message.", java.util.Arrays.asList(), java.util.Arrays.asList("pca.destructive", "pca.irreversible")),
        new Spec("github", "read", "github.read", "reversible", 0.05, null, "Reads files from a repository.", java.util.Arrays.asList(), java.util.Arrays.asList()),
        new Spec("github", "create_pr", "github.create_pr", "irreversible", 0.2, null, "Opens a pull request, which is visible to everyone with access to the repository.", java.util.Arrays.asList(), java.util.Arrays.asList("pca.external_communication", "pca.irreversible")),
        new Spec("github", "comment", "github.comment", "irreversible", 0.2, null, "Posts a comment, visible to everyone with access to the repository.", java.util.Arrays.asList(), java.util.Arrays.asList("pca.external_communication", "pca.irreversible")),
        new Spec("github", "merge_pr", "github.merge_pr", "irreversible", 0.5, null, "Merges a pull request, which can trigger deploys and other downstream effects.", java.util.Arrays.asList(), java.util.Arrays.asList("pca.irreversible")),
        new Spec("github", "delete_repo", "github.delete_repo", "irreversible", 0.8, null, "Deletes a repository and everything in it.", java.util.Arrays.asList(), java.util.Arrays.asList("pca.destructive", "pca.irreversible")),
        new Spec("slack", "post_message", "slack.post_message", "irreversible", 0.5, null, "Posts a message that members of the channel can read.", java.util.Arrays.asList(), java.util.Arrays.asList("pca.bulk", "pca.external_communication", "pca.irreversible")),
        new Spec("slack", "read", "slack.read", "reversible", 0.05, null, "Reads the message history of a channel.", java.util.Arrays.asList(), java.util.Arrays.asList()),
        new Spec("calendar", "create_event", "calendar.create_event", "irreversible", 0.2, null, "Creates an event and sends invitations to its attendees.", java.util.Arrays.asList(), java.util.Arrays.asList("pca.external_communication", "pca.irreversible", "pca.pii_access")),
        new Spec("calendar", "delete_event", "calendar.delete_event", "rate_limited", 0.5, null, "Deletes a calendar event.", java.util.Arrays.asList(), java.util.Arrays.asList("pca.destructive")),
        new Spec("files", "read", "files.read", "reversible", 0.05, null, "Reads files.", java.util.Arrays.asList(), java.util.Arrays.asList("pca.bulk")),
        new Spec("files", "write", "files.write", "rate_limited", 0.5, null, "Writes or overwrites files.", java.util.Arrays.asList(), java.util.Arrays.asList("pca.bulk")),
        new Spec("files", "delete", "files.delete", "irreversible", 0.8, null, "Deletes files.", java.util.Arrays.asList(), java.util.Arrays.asList("pca.bulk", "pca.destructive", "pca.irreversible")),
        new Spec("http", "get", "http.get", "reversible", 0.05, null, "Fetches a URL.", java.util.Arrays.asList(), java.util.Arrays.asList("pca.bulk", "pca.network_egress")),
        new Spec("http", "post", "http.post", "rate_limited", 0.5, null, "Posts a body to a URL.", java.util.Arrays.asList(), java.util.Arrays.asList("pca.bulk", "pca.network_egress"))    ));
    // END GENERATED

    /** The catalog of the built-in actions. */
    public static final Catalog DEFAULT = new Catalog(BUILTIN);

    /** The built-in catalog under the reference's name. */
    public static final Catalog DEFAULT_CATALOG = DEFAULT;

    private final Map<String, Spec> byVerb = new LinkedHashMap<>();
    /** Every row as its JSON object, keyed by verb in order of first appearance (a later row replaces in place, as a JavaScript Map does). */
    private final Map<Object, Map<String, Object>> rows = new LinkedHashMap<>();

    /** A catalog over {@code specs}; a later spec with the same verb replaces an earlier one. */
    public Catalog(List<Spec> specs) {
        for (Spec s : specs) {
            byVerb.put(s.verb, s);
            rows.put(s.verb, s.toJson());
        }
    }

    private Catalog(List<?> actions, boolean json) {
        for (Object a : actions) {
            Map<String, Object> row = StoreJs.map(a);
            if (row == null) throw new IllegalArgumentException("buildCatalog: an action is not an object");
            // shortcut: a verb that is not a string is keyed as an absent one (the reference keys a Map by the raw value); no caller builds such rows
            Object verb = row.get("verb") instanceof String ? row.get("verb") : null;
            rows.put(verb, row);
            Spec typed = verb == null ? null : Spec.of(row);
            if (typed != null) byVerb.put(typed.verb, typed); else byVerb.remove(verb);
        }
    }

    // ---- the reference's catalog functions over JSON rows -----------------------------------------------------------------------------

    /**
     * Validate one action spec and give it its verb ({@code connector.action} unless {@code verb} is given): connector and action are
     * non-empty strings, the connector holds no white space and no dot, {@code amountField} (when present) is a non-empty string,
     * {@code reversibility} is one of the three classes and {@code blastRadius} a number in [0, 1]. Other members are kept. Throws
     * IllegalArgumentException with the reference's message.
     */
    public static Map<String, Object> defineAction(Object spec) {
        Map<String, Object> s = StoreJs.map(spec);
        if (s == null || !(s.get("connector") instanceof String) || !(s.get("action") instanceof String) || ((String) s.get("connector")).isEmpty() || ((String) s.get("action")).isEmpty())
            throw new IllegalArgumentException("defineAction: connector and action are required");
        String connector = (String) s.get("connector");
        if (connector.indexOf('.') >= 0 || connector.chars().anyMatch(AttestCommon::isJsSpace)) throw new IllegalArgumentException("defineAction: connector must not contain whitespace or a dot");
        if (s.containsKey("amountField") && !(s.get("amountField") instanceof String && !((String) s.get("amountField")).isEmpty())) throw new IllegalArgumentException("defineAction: amountField must be a non-empty string");
        if (!Caveats.REVERSIBILITY_ORDER.contains(s.get("reversibility"))) throw new IllegalArgumentException("defineAction: bad reversibility '" + IntentRevocation.jsText(s.get("reversibility"), s.containsKey("reversibility")) + "'");
        Double blast = IntentJs.num(s.get("blastRadius"));
        if (!(blast != null && blast >= 0 && blast <= 1)) throw new IllegalArgumentException("defineAction: blastRadius must be in [0,1]");
        Map<String, Object> out = new LinkedHashMap<>(s);
        if (s.get("verb") == null) out.put("verb", connector + "." + s.get("action"));
        return out;
    }

    /** A catalog over JSON action rows, taken as they are (not validated); a later row replaces an earlier one with the same verb, in place. */
    public static Catalog buildCatalog(List<?> actions) { return new Catalog(actions, true); }

    /** The catalog of the built-in actions. */
    public static Catalog buildCatalog() { return DEFAULT; }

    /** The JSON row of a verb, or null. */
    public Map<String, Object> getJson(String verb) { return verb == null ? null : rows.get(verb); }

    /** Every row of a connector, in catalog order. */
    public List<Map<String, Object>> forConnector(String connector) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> r : rows.values()) if (connector != null && connector.equals(r.get("connector"))) out.add(r);
        return out;
    }

    /** Every row, in order of first appearance by verb. */
    public List<Map<String, Object>> allJson() { return new ArrayList<>(rows.values()); }

    /** {@link #resolve} over the JSON rows: the exact verb, else the single row of {@code connector} that lists {@code action} as an alias. */
    public Map<String, Object> resolveJson(String connector, String action) {
        if (connector == null || action == null) return null;
        Map<String, Object> exact = rows.get(connector + "." + action);
        if (exact != null) return exact;
        Map<String, Object> hit = null;
        int n = 0;
        for (Map<String, Object> r : rows.values()) {
            if (!connector.equals(r.get("connector"))) continue;
            Object al = r.get("aliases");
            boolean listed;
            if (al == null) listed = false;
            else if (al instanceof List) listed = ((List<?>) al).contains(action);
            else if (al instanceof String) listed = ((String) al).contains(action); // the reference's includes() on a string
            else throw new IllegalArgumentException("resolve: aliases is not a list");
            if (listed) { hit = r; n++; }
        }
        return n == 1 ? hit : null;
    }

    /** What a verb the catalog does not know is treated as: irreversible, the largest blast radius. */
    public static Map<String, Object> uncataloguedSpec(String verb) {
        int dot = verb.indexOf('.');
        String rest = dot < 0 ? "" : verb.substring(dot + 1);
        return Issue.obj("connector", dot < 0 ? verb : verb.substring(0, dot), "action", rest.isEmpty() ? verb : rest, "verb", verb,
            "reversibility", "irreversible", "blastRadius", StoreJs.num(1L), "description", "(uncatalogued) " + verb);
    }

    /** Resolve a verb, failing closed: {@code {spec, catalogued}}, where an unknown verb is {@link #uncataloguedSpec} with {@code catalogued:false}. */
    public static Map<String, Object> resolveAction(Catalog catalog, String verb) {
        Map<String, Object> spec = catalog.getJson(verb);
        return spec != null ? Issue.obj("spec", spec, "catalogued", true) : Issue.obj("spec", uncataloguedSpec(verb), "catalogued", false);
    }

    /**
     * The digest of the whole catalog: SHA-256 over the canonical JSON of its rows sorted by verb. Pin it, so a deployment can refuse
     * to start on a catalog other than the one it reviewed. Throws on a row with no canonical form (a non-finite number).
     */
    public static String catalogDigest(Catalog catalog) {
        List<Map<String, Object>> specs = catalog.allJson();
        specs.sort((a, b) -> a.get("verb") instanceof String && b.get("verb") instanceof String ? ((String) a.get("verb")).compareTo((String) b.get("verb")) : 0);
        return Pca.hashCanonical(specs);
    }

    /** Throws IllegalStateException unless {@code catalog} hashes to {@code expected}. */
    public static void assertCatalogPinned(Catalog catalog, Object expected) {
        if (!catalogDigest(catalog).equals(expected)) throw new IllegalStateException("catalog does not match the pinned digest");
    }

    /**
     * A catalog of {@code base} plus {@code extra}. Unlike building one over both lists, an extra row may not replace an existing verb
     * with a less cautious one (a lower reversibility class or a lower blast radius): throws IllegalArgumentException.
     */
    public static Catalog extendCatalog(Catalog base, List<?> extra) {
        for (Object x : extra) {
            Map<String, Object> e = StoreJs.map(x);
            if (e == null) throw new IllegalArgumentException("extendCatalog: an action is not an object");
            Map<String, Object> old = e.get("verb") instanceof String ? base.getJson((String) e.get("verb")) : null;
            if (old == null) continue;
            int sevNew = Caveats.REVERSIBILITY_ORDER.indexOf(e.get("reversibility")), sevOld = Caveats.REVERSIBILITY_ORDER.indexOf(old.get("reversibility"));
            // a blast radius that is not a number compares as the reference's ToNumber does (NaN is never lower)
            if (sevNew < sevOld || Actions.jsNumber(e.get("blastRadius"), e.containsKey("blastRadius")) < Actions.jsNumber(old.get("blastRadius"), old.containsKey("blastRadius")))
                throw new IllegalArgumentException("extendCatalog: '" + e.get("verb") + "' would be less cautious than the existing entry");
        }
        List<Object> all = new ArrayList<Object>(base.allJson());
        all.addAll(extra);
        return buildCatalog(all);
    }

    /** The spec of a verb ({@code connector.action}), or null. */
    public Spec get(String verb) { return byVerb.get(verb); }

    public List<Spec> all() { return new ArrayList<>(byVerb.values()); }

    /** The exact verb, else the one action of {@code connector} that lists {@code action} as an alias (never a guess: two hits are none). */
    public Spec resolve(String connector, String action) {
        Spec exact = byVerb.get(connector + "." + action);
        if (exact != null) return exact;
        Spec hit = null;
        int n = 0;
        for (Spec s : byVerb.values()) if (s.connector.equals(connector) && s.aliases.contains(action)) { hit = s; n++; }
        return n == 1 ? hit : null;
    }

    /** Reversibility score per class (1 = fully reversible): the scale the hosted adjudicator uses. */
    public static final Map<String, Double> CATALOG_REVERSIBILITY_SCORE;
    static {
        Map<String, Double> m = new java.util.LinkedHashMap<>();
        m.put("reversible", 1.0); m.put("rate_limited", 0.4); m.put("costly", 0.4); m.put("irreversible", 0.0);
        CATALOG_REVERSIBILITY_SCORE = Collections.unmodifiableMap(m);
    }

    private static double unit(double x) { return Math.min(1, Math.max(0, x)); }

    /**
     * The server's risk inputs for an action the catalog knows: {@code reversibility} from the class score, {@code blastRadius} from the catalog
     * (or, for an amount-bearing action, {@code amount / kappa} from the verified params and the grant's risk policy, the worst case 1 when
     * either is unusable), {@code confidence} 1 and, when {@code taint} is supplied, {@code taint} in [0, 1]. An unknown verb yields an empty map
     * (the verifier then prices the inputs at the worst case). {@code catalog} null is the built-in one.
     */
    public static Map<String, Object> catalogRisk(String verb, Map<String, ?> params, Map<String, Object> grant, Catalog catalog, Double taint) {
        Spec spec = (catalog != null ? catalog : DEFAULT).get(verb);
        Map<String, Object> out = new java.util.LinkedHashMap<>();
        if (spec == null) return out;
        Double rev = CATALOG_REVERSIBILITY_SCORE.get(spec.reversibility);
        double blast = unit(spec.blastRadius);
        if (spec.amountField != null) {
            Object amount = params != null && params.containsKey(spec.amountField) ? params.get(spec.amountField) : null;
            Map<String, Object> env = Authorize.readEnvelope(grant);
            Object rp = env == null ? null : env.get("risk_policy");
            Double kappa = rp instanceof Map ? Caveats.fin(((Map<?, ?>) rp).get("kappa")) : null;
            Double amt = Caveats.fin(amount);
            blast = amt != null && amt >= 0 && kappa != null && kappa > 0 ? unit(amt / kappa) : 1;
        }
        out.put("reversibility", StoreJs.num(rev != null ? rev : 0.0));
        out.put("blastRadius", StoreJs.num(blast));
        out.put("confidence", StoreJs.num(1.0));
        if (taint != null && !taint.isNaN() && !taint.isInfinite()) out.put("taint", StoreJs.num(unit(taint)));
        return out;
    }
}
