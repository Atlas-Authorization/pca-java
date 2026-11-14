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
    /** One catalogued action. {@code amountField} is null for an action that moves no money. */
    public static final class Spec {
        public final String connector, action, verb, reversibility, amountField, description;
        public final double blastRadius;
        public final List<String> aliases, traits;

        public Spec(String connector, String action, String verb, String reversibility, double blastRadius, String amountField, String description,
                    List<String> aliases, List<String> traits) {
            this.connector = connector;
            this.action = action;
            this.verb = verb;
            this.reversibility = reversibility;
            this.blastRadius = blastRadius;
            this.amountField = amountField;
            this.description = description;
            this.aliases = aliases == null ? Collections.<String>emptyList() : Collections.unmodifiableList(new ArrayList<>(aliases));
            this.traits = traits == null ? Collections.<String>emptyList() : Collections.unmodifiableList(new ArrayList<>(traits));
        }
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

    private final Map<String, Spec> byVerb = new LinkedHashMap<>();

    /** A catalog over {@code specs}; a later spec with the same verb replaces an earlier one. */
    public Catalog(List<Spec> specs) { for (Spec s : specs) byVerb.put(s.verb, s); }

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
}
