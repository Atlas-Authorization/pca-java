package net.atlasauth.pca.actions.importers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.Actions.ActionKitError;
import net.atlasauth.pca.ActionsBridge;
import net.atlasauth.pca.W3Bridge;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.actions.ActionConfirmation;
import net.atlasauth.pca.actions.ActionDerive;
import net.atlasauth.pca.actions.ActionEffective;

/**
 * The confirmation flow and signed review attestations. This is the ONE non-monotone step in the system: a def WITHOUT a valid
 * attestation has the top of the registry as its effective traits, and a valid one sets them to exactly what the reviewer signed. It counts
 * only when a key pinned with the {@code reviewer} role has signed this exact def digest. Any change to the def or to the trait registry the
 * reviewer saw makes the attestation stale and the def reverts to unconfirmed. Defs, pins and verdicts are JSON trees.
 */
public final class ImportReview {
    private ImportReview() {}

    private static final Pattern TRAIT_ID_RE = Pattern.compile("[a-z][a-z0-9_]{0,31}\\.[a-z][a-z0-9_]{0,63}");

    private static Map<String, Object> fail(String reason, String detail) { return Jx.obj("ok", false, "reason", reason, "detail", detail); }

    private static boolean strings(Object v) {
        if (!(v instanceof List)) return false;
        for (Object x : Jx.a(v)) if (!(x instanceof String)) return false;
        return true;
    }

    private static List<String> sortUniq(Object xs) {
        TreeSet<String> s = new TreeSet<>();
        if (xs instanceof List) for (Object x : Jx.a(xs)) s.add((String) x);
        return new ArrayList<>(s);
    }

    /**
     * Is this def's confirmation valid? True only if: state is {@code confirmed}; the attestation covers THIS def digest and an accepted
     * registry digest; its final traits are the def's declared traits; the signer is pinned with the {@code reviewer} role (and not as a
     * machine key) and the timestamp is inside the key's validity; the signature verifies. Never throws. Returns {@code {ok: true, kid}} or
     * {@code {ok: false, reason, detail}}.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyAttestation(Map<String, Object> def, Map<String, Object> pins, Actions.Registry registry) {
        try {
            String pe = ActionConfirmation.reviewerPinsError(pins);
            if (pe != null) return fail("bad_pins", pe);
            Object review = def.get("review");
            if (!"confirmed".equals(Jx.get(review, "state"))) return fail("not_confirmed", "review.state is not confirmed");
            Object ao = Jx.get(review, "attestation");
            if (!Jx.has(review, "attestation")) return fail("no_attestation", "a confirmed def carries an attestation");
            Map<String, Object> a = Jx.m(ao);
            if (!(a.get("sig") instanceof String)) return fail("no_signature", "the attestation is unsigned");
            if (!(a.get("facts_digest") instanceof String)) return fail("malformed", "the attestation facts_digest must be a string");
            // shape before meaning: a missing / null / "" final_traits must not read as "no traits" for a read def
            boolean dismissedOk = a.get("dismissed") instanceof List;
            if (dismissedOk) for (Object d : Jx.a(a.get("dismissed"))) if (!(d instanceof Map) || !(Jx.m(d).get("trait") instanceof String) || !(Jx.m(d).get("reason") instanceof String)) { dismissedOk = false; break; }
            if (!strings(a.get("final_traits")) || !dismissedOk || !Jx.isInt(a.get("ts")) || !(a.get("reviewer_kid") instanceof String))
                return fail("malformed", "the attestation final_traits, dismissed, ts or reviewer_kid is malformed");
            if (!Actions.defDigest(def).equals(a.get("def_digest"))) return fail("digest_mismatch", "the def changed after it was reviewed");
            Set<Object> accepted = new LinkedHashSet<>();
            accepted.add(Actions.traitsDigest(registry));
            if (pins.get("traits_digests") instanceof List) accepted.addAll(Jx.a(pins.get("traits_digests")));
            if (!accepted.contains(a.get("traits_digest"))) return fail("traits_digest_mismatch", "the trait registry changed since the review");
            if (!sortUniq(a.get("final_traits")).equals(sortUniq(def.get("traits")))) return fail("final_traits_mismatch", "the attested final traits are not the def's declared traits");
            Set<Object> fin = new LinkedHashSet<>(Jx.a(a.get("final_traits")));
            for (Object d : Jx.a(a.get("dismissed"))) if (fin.contains(Jx.m(d).get("trait")) || ActionConfirmation.blankReason((String) Jx.m(d).get("reason"))) return fail("dismissed_conflict", "a dismissed trait is also final, or has no reason");
            Map<String, Object> key = null;
            for (Object k : Jx.a(pins.get("keys"))) if (a.get("reviewer_kid").equals(Jx.m(k).get("kid"))) { key = Jx.m(k); break; }
            if (key == null) return fail("unknown_reviewer", "no pinned key '" + a.get("reviewer_kid") + "'");
            if (!Jx.a(key.get("roles")).contains("reviewer")) return fail("not_a_reviewer", "key '" + key.get("kid") + "' does not hold the reviewer role");
            double ts = Jx.num(a.get("ts"));
            if ((key.containsKey("not_before") && ts < Jx.num(key.get("not_before"))) || (key.containsKey("not_after") && ts > Jx.num(key.get("not_after")))) return fail("outside_validity", "the attestation time is outside the key validity");
            Map<String, Object> body = new LinkedHashMap<>(a);
            body.remove("sig");
            return W3Bridge.verifyB64u((String) key.get("pk"), ActionConfirmation.reviewMessage(body), (String) a.get("sig"))
                ? Jx.obj("ok", true, "kid", key.get("kid")) : fail("bad_signature", "the attestation signature is invalid");
        } catch (RuntimeException e) {
            return fail("malformed", String.valueOf(e.getMessage()));
        }
    }

    /** The state that counts: a {@code confirmed} def with an invalid attestation is {@code stale} (it behaves as unreviewed). */
    public static Object reviewStatus(Map<String, Object> def, Map<String, Object> pins, Actions.Registry registry) {
        if (def.get("review") == null) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'state')");
        Object st = Jx.get(def.get("review"), "state");
        if (!"confirmed".equals(st)) return st;
        return Boolean.TRUE.equals(verifyAttestation(def, pins, registry).get("ok")) ? "confirmed" : "stale";
    }

    /** Defs whose confirmation no longer holds go back to {@code unreviewed} (the attestation is dropped). Others are returned as they are. */
    public static Map<String, Object> revertStale(Map<String, Object> def, Map<String, Object> pins, Actions.Registry registry) {
        if (!"stale".equals(reviewStatus(def, pins, registry))) return def;
        Map<String, Object> review = new LinkedHashMap<>(Jx.m(def.get("review")));
        review.remove("attestation");
        review.put("state", "unreviewed");
        Map<String, Object> out = new LinkedHashMap<>(def);
        out.put("review", review);
        return out;
    }

    // ---- review view and confirm ----

    private static final List<String> SUSPECT = List.of("pca.money_moving", "pca.privilege_change", "pca.code_execution", "pca.destructive", "pca.external_communication");
    private static final List<String> NEXT = List.of("pca.credential_access", "pca.data_export", "pca.regulated_data", "pca.public_exposure", "pca.infra_mutation", "pca.legal_binding", "pca.impersonation", "pca.persistence");

    /** The profile the def would have once reviewed (its own facts and traits, without the review marker that every unreviewed def shares). */
    private static Map<String, Object> intrinsic(Map<String, Object> def, Actions.Registry registry) {
        return Jx.m(ActionEffective.effective(def, registry, null).get("hint"));
    }

    /** Review queue priority: 0 = a core suspect trait, 1 = other risky, 2 = the rest. Lower first. */
    public static int reviewPriority(Map<String, Object> def, Actions.Registry registry) {
        Set<Object> cl = new LinkedHashSet<>(Jx.a(intrinsic(def, registry).get("closure")));
        for (String t : SUSPECT) if (cl.contains(t)) return 0;
        for (String t : NEXT) if (cl.contains(t)) return 1;
        return 2;
    }

    /** Defs in review order: suspect traits first, then by risk (highest first), then by verb. Deterministic. */
    public static List<Map<String, Object>> reviewQueueOrder(List<Map<String, Object>> defs, Actions.Registry registry) {
        List<Object[]> rows = new ArrayList<>();
        for (Map<String, Object> d : defs) rows.add(new Object[] {d, reviewPriority(d, registry), Jx.num(Jx.m(intrinsic(d, registry).get("eff")).get("risk"))});
        rows.sort((x, y) -> {
            int p = Integer.compare((Integer) x[1], (Integer) y[1]);
            if (p != 0) return p;
            int r = Double.compare((Double) y[2], (Double) x[2]);
            if (r != 0) return r;
            return Jx.m(x[0]).get("verb").toString().compareTo(Jx.m(y[0]).get("verb").toString());
        });
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object[] r : rows) out.add(Jx.m(r[0]));
        return out;
    }

    /** Traits implied by the def's own facts (effects, roles, tags, scope, reversibility). */
    static List<String> impliedTraits(Map<String, Object> def) {
        Map<String, Object> n = Actions.normalize(def);
        List<Map<String, Object>> ps = new ArrayList<>();
        for (Object p : Jx.m(n.get("params")).values()) ps.add(Jx.m(p));
        return ActionsBridge.impliedFromFacts(Jx.a(n.get("effects")), ps, (String) Jx.m(n.get("resource")).get("scope"), ActionsBridge.worstReversibility(n.get("reversibility"), Jx.m(n.get("params"))));
    }

    public static Map<String, Object> prepareReview(Map<String, Object> def, Actions.Registry registry) { return prepareReview(def, registry, null); }

    /** The reviewer's view of a def: facts, implied and suggested traits, the effective profile, the policy card, what changed since {@code previous}. */
    public static Map<String, Object> prepareReview(Map<String, Object> def, Actions.Registry registry, Map<String, Object> previous) {
        Map<String, Object> eff = ActionEffective.effective(def, registry, null);
        // the card shows what the reviewer would be signing (the hint), not the all-traits view that applies until they sign
        Map<String, Object> shown = new LinkedHashMap<>(eff);
        shown.putAll(Jx.m(eff.get("hint")));
        shown.put("confirmed", Boolean.TRUE);
        Object sbo = Jx.get(def.get("review"), "suggested_by");
        Object added = Jx.get(sbo, "added");
        List<Object> changes = new ArrayList<>();
        if (previous != null) {
            Map<String, Object> a = strip(previous), b = strip(def);
            Set<String> ks = new TreeSet<>(a.keySet());
            ks.addAll(b.keySet());
            for (String k : ks) if (!Jx.sameJsonMember(a, b, k)) changes.add(k);
        }
        return Jx.obj("verb", def.get("verb"), "def_digest", Actions.defDigest(def), "state", Jx.get(def.get("review"), "state"),
            "declared_traits", new ArrayList<Object>(sortUniq(def.get("traits"))), "implied_traits", new ArrayList<Object>(impliedTraits(def)),
            "suggested", added != null ? added : Jx.obj("traits", new ArrayList<>(), "roles", new LinkedHashMap<>(), "tags", new LinkedHashMap<>()),
            "effective", eff, "card", ActionDerive.cardOf(def, shown, registry), "changes", changes, "priority", Jx.n(reviewPriority(def, registry)));
    }

    private static Map<String, Object> strip(Map<String, Object> d) {
        Map<String, Object> o = new LinkedHashMap<>(d);
        for (String k : List.of("review", "examples", "source", "since")) o.remove(k);
        return o;
    }

    /** Release step: confirm every def with the release reviewer key, final traits = the def's declared traits. The key is the caller's, never stored. */
    public static List<Object> signBuiltins(Actions.Registry registry, String kid, byte[] secret, Object ts, List<?> defs) {
        List<Object> out = new ArrayList<>();
        for (Object d : defs) {
            Map<String, Object> def = Jx.m(d);
            out.add(confirmDef(def, registry == null ? Actions.CORE_REGISTRY : registry, kid, secret, null, new ArrayList<Object>(sortUniq(def.get("traits"))), null, ts));
        }
        return out;
    }

    /**
     * Review one def: validates the decision, writes the final traits, signs an attestation over the resulting digest and returns the
     * confirmed def. Throws ActionKitError ({@code bad_confirm}, {@code undismissed_suggestion}, {@code not_reviewer}) rather than guessing.
     *
     * @param pins when not null, the reviewer must be pinned with the {@code reviewer} role under this key
     * @param finalTraits the final DECLARED trait set (the reviewer's decision)
     * @param dismissed {@code [{trait, reason}]} or null: every suggested trait left out of the final set needs a reason
     * @param ts seconds, a non-negative safe integer
     */
    public static Map<String, Object> confirmDef(Map<String, Object> def, Actions.Registry registry, String reviewerKid, byte[] reviewerSecret, Map<String, Object> pins,
                                                  List<Object> finalTraits, List<Object> dismissed, Object ts) {
        if (!Jx.isInt(ts) || Jx.num(ts) < 0) throw new ActionKitError("bad_confirm", "ts must be a non-negative integer");
        List<String> fin = sortUniq(finalTraits);
        if (fin.size() != finalTraits.size()) throw new ActionKitError("bad_confirm", "final traits must be distinct");
        for (String t : fin) {
            if (!TRAIT_ID_RE.matcher(t).matches() || !registry.traits.containsKey(t)) throw new ActionKitError("bad_confirm", "unknown trait '" + t + "'");
            if (t.equals("pca.unreviewed")) throw new ActionKitError("bad_confirm", "'pca.unreviewed' is the review marker, not a final trait");
        }
        // copied: a batch shares one dismissal list across defs
        List<Object> dis = new ArrayList<>();
        if (dismissed != null) for (Object d : dismissed) dis.add(Jx.obj("trait", Jx.get(d, "trait"), "reason", Jx.get(d, "reason")));
        Set<Object> dset = new LinkedHashSet<>();
        for (Object d : dis) {
            Object reason = Jx.get(d, "reason"), trait = Jx.get(d, "trait");
            if (!(reason instanceof String) || Jx.jsTrim((String) reason).isEmpty() || ((String) reason).length() > 256) throw new ActionKitError("bad_confirm", "dismissed trait '" + Jx.jsStr(trait) + "' needs a reason (1..256 characters)");
            if (dset.contains(trait)) throw new ActionKitError("bad_confirm", "trait '" + Jx.jsStr(trait) + "' is dismissed twice");
            dset.add(trait);
            if (fin.contains(trait)) throw new ActionKitError("bad_confirm", "trait '" + Jx.jsStr(trait) + "' is both final and dismissed");
        }
        // what the reviewer was shown: the importer's and the suggesters' traits, plus what the def already declares
        Object sbAdded = Jx.get(Jx.get(def.get("review"), "suggested_by"), "added");
        List<Object> shownAll = new ArrayList<>();
        if (def.get("traits") instanceof List) shownAll.addAll(Jx.a(def.get("traits")));
        if (Jx.get(sbAdded, "traits") instanceof List) shownAll.addAll(Jx.a(Jx.get(sbAdded, "traits")));
        List<String> shown = sortUniq(shownAll);
        List<String> seed = new ArrayList<>(fin);
        seed.addAll(impliedTraits(def));
        Set<String> covered = new LinkedHashSet<>(Actions.closure(registry, sortUniq(new ArrayList<Object>(seed))));
        for (String t : shown) {
            if (fin.contains(t) || covered.contains(t)) continue;
            if (!dset.contains(t)) throw new ActionKitError("undismissed_suggestion", "trait '" + t + "' was suggested and is not in the final set: record it as dismissed with a reason");
        }
        for (Object t : dset) if (!shown.contains(t)) throw new ActionKitError("bad_confirm", "trait '" + Jx.jsStr(t) + "' was never suggested; nothing to dismiss");
        if (pins != null) {
            String pe = ActionConfirmation.reviewerPinsError(pins);
            if (pe != null) throw new ActionKitError("bad_confirm", pe);
            Map<String, Object> key = null;
            for (Object k : Jx.a(pins.get("keys"))) if (reviewerKid.equals(Jx.m(k).get("kid"))) { key = Jx.m(k); break; }
            if (key == null || !Jx.a(key.get("roles")).contains("reviewer")) throw new ActionKitError("not_reviewer", "key '" + reviewerKid + "' is not pinned with the reviewer role");
            if (!Keys.edFromSeed(reviewerSecret).id().equals(key.get("pk"))) throw new ActionKitError("not_reviewer", "the secret does not belong to the pinned key '" + reviewerKid + "'");
        }
        Map<String, Object> body = new LinkedHashMap<>(def);
        if (fin.isEmpty()) body.remove("traits"); else body.put("traits", new ArrayList<Object>(fin));
        String digest = Actions.defDigest(body);
        // the facts of the verb this definition publishes: the verifier will recompute them from the schema and compare
        Map<String, Object> verb = Jx.m(ActionDerive.toSchemaVerb(body, registry, null).get("verb"));
        Map<String, Object> att = ActionConfirmation.signReview(Jx.obj("def_digest", digest, "traits_digest", Actions.traitsDigest(registry), "facts_digest", ActionConfirmation.factsDigest(verb),
            "final_traits", new ArrayList<Object>(fin), "dismissed", dis, "reviewer_kid", reviewerKid, "ts", ts), reviewerSecret);
        Map<String, Object> review = new LinkedHashMap<>(Jx.m(def.get("review")));
        review.put("state", "confirmed");
        review.put("attestation", att);
        Map<String, Object> out = new LinkedHashMap<>(body);
        out.put("review", review);
        String bad = Actions.validateDef(out);
        if (bad != null) throw new ActionKitError("bad_confirm", "the confirmed def is invalid: " + bad);
        return out;
    }
}
