package net.atlasauth.pca.actions;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.EdStrict;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;

/**
 * The signed human confirmation of an action: the only thing that can set an action's effective trait set below the top of the
 * registry ("unconfirmed means maximally dangerous"). Signing, and the verifier's view of a confirmation on a schema verb.
 */
public final class ActionConfirmation {
    private ActionConfirmation() {}

    public static final String REVIEW_DOMAIN = "atlas-pca/action-review/v2";
    public static final String VERB_FACTS_DOMAIN = "atlas-pca/action-verb-facts/v1";
    public static final List<String> KEY_ROLES = List.of("reviewer", "importer", "model", "publisher");

    private static boolean jsSpace(char c) {
        return (c >= 9 && c <= 13) || c == 32 || c == 0xa0 || c == 0x1680 || (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 || c == 0x202f
            || c == 0x205f || c == 0x3000 || c == 0xfeff || (c >= 0x1c && c <= 0x1f);
    }

    /** A dismissal reason with no content: only white space (which, as in Java's isWhitespace / isSpaceChar, includes U+001C..U+001F). */
    public static boolean blankReason(String s) {
        for (int i = 0; i < s.length(); i++) if (!jsSpace(s.charAt(i))) return false;
        return true;
    }

    /** The verb as published minus the members a confirmation decides or carries, hashed with its domain. */
    public static String factsDigest(Map<String, Object> verb) { return Actions.factsDigest(verb); }

    /** Null if the pin set is sound (distinct kids, canonical keys, known roles, no key both reviewer and machine). */
    public static String reviewerPinsError(Object pins) { return Actions.reviewerPinsError(pins); }

    /** The bytes a reviewer signs: {@code REVIEW_DOMAIN \0} then the strict canonical body. */
    public static byte[] reviewMessage(Map<String, Object> b) {
        List<Object> dis = new ArrayList<>(J.a(b.get("dismissed")));
        dis.sort((x, y) -> ((String) J.get(x, "trait")).compareTo((String) J.get(y, "trait")));
        List<Object> dm = new ArrayList<>();
        for (Object d : dis) dm.add(J.obj("trait", J.get(d, "trait"), "reason", J.get(d, "reason")));
        Map<String, Object> body = J.obj("def_digest", b.get("def_digest"), "traits_digest", b.get("traits_digest"), "facts_digest", b.get("facts_digest"),
            "final_traits", J.objs(J.sortUniq(b.get("final_traits"))), "dismissed", dm, "reviewer_kid", b.get("reviewer_kid"), "ts", b.get("ts"));
        byte[] dom = (REVIEW_DOMAIN + "\0").getBytes(StandardCharsets.UTF_8);
        byte[] bd = Json.canonicalizeStrict(body).getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[dom.length + bd.length];
        System.arraycopy(dom, 0, out, 0, dom.length);
        System.arraycopy(bd, 0, out, dom.length, bd.length);
        return out;
    }

    /** Sign a review body ({@code def_digest, traits_digest, facts_digest, final_traits, dismissed, reviewer_kid, ts}) with an Ed25519 seed. */
    public static Map<String, Object> signReview(Map<String, Object> b, byte[] secret) {
        Map<String, Object> norm = new LinkedHashMap<>(b);
        norm.put("final_traits", J.objs(J.sortUniq(b.get("final_traits"))));
        List<Object> dis = new ArrayList<>(J.a(b.get("dismissed")));
        dis.sort((x, y) -> ((String) J.get(x, "trait")).compareTo((String) J.get(y, "trait")) < 0 ? -1 : 1);
        norm.put("dismissed", dis);
        Map<String, Object> out = new LinkedHashMap<>(norm);
        out.put("sig", Keys.b64u(Keys.edFromSeed(secret).sign(reviewMessage(norm))));
        return out;
    }

    private static boolean str(Object o) { return o instanceof String; }

    /**
     * Null iff the verb carries a VALID human confirmation: an attestation over exactly the def digest the verb names, against an accepted
     * trait registry digest, whose final traits are carried by the verb, signed by a key pinned with the reviewer role inside its validity
     * window. Anything else is a reason string and the verb is UNCONFIRMED. Never throws.
     */
    public static String verbConfirmationError(Map<String, Object> v, Actions.Registry reg, Object pins) {
        try {
            if (pins == null) return "no reviewer keys are pinned";
            String pe = reviewerPinsError(pins);
            if (pe != null) return "bad pins: " + pe;
            if (!v.containsKey("confirmation")) return "no confirmation";
            Object a = v.get("confirmation");
            if (a instanceof List) return "the confirmation is unsigned"; // an array is an object with no sig member
            if (!(a instanceof Map)) return "confirmation is not an object";
            Map<String, Object> am = J.m(a);
            if (!str(am.get("sig"))) return "the confirmation is unsigned";
            if (!str(v.get("def")) || !v.get("def").equals(am.get("def_digest"))) return "the confirmation covers a different def digest";
            Set<Object> accepted = new HashSet<>();
            accepted.add(Actions.traitsDigest(reg));
            Object extra = J.get(pins, "traits_digests");
            if (extra instanceof List) accepted.addAll(J.a(extra));
            if (!accepted.contains(am.get("traits_digest"))) return "the confirmation was made against a different trait registry";
            if (!str(am.get("facts_digest")) || !am.get("facts_digest").equals(factsDigest(v))) return "the verb facts differ from the facts the reviewer confirmed";
            if (!(am.get("final_traits") instanceof List) || !(am.get("dismissed") instanceof List) || !J.isInt(am.get("ts")) || !str(am.get("reviewer_kid"))) return "malformed confirmation";
            Object tr = v.get("traits");
            Set<Object> carried = new HashSet<>(tr instanceof List ? J.a(tr) : List.of());
            for (Object t : J.a(am.get("final_traits"))) if (!str(t) || !carried.contains(t)) return "the verb does not carry every trait the reviewer signed";
            Set<Object> fin = new HashSet<>(J.a(am.get("final_traits")));
            for (Object d : J.a(am.get("dismissed"))) {
                if (!str(J.get(d, "trait")) || !str(J.get(d, "reason")) || fin.contains(J.get(d, "trait")) || blankReason((String) J.get(d, "reason"))) return "a dismissed trait is also final, or has no reason";
            }
            Map<String, Object> key = null;
            for (Object k : J.a(J.get(pins, "keys"))) if (J.get(k, "kid").equals(am.get("reviewer_kid"))) { key = J.m(k); break; }
            if (key == null) return "no pinned key '" + am.get("reviewer_kid") + "'";
            if (!J.a(key.get("roles")).contains("reviewer")) return "key '" + key.get("kid") + "' does not hold the reviewer role";
            double ts = J.num(am.get("ts"));
            if ((key.containsKey("not_before") && ts < J.num(key.get("not_before"))) || (key.containsKey("not_after") && ts > J.num(key.get("not_after")))) return "the confirmation time is outside the key validity";
            Map<String, Object> body = new LinkedHashMap<>(am);
            body.remove("sig");
            byte[] pk = Pca.decodeB64uStrict(key.get("pk"), 32), sg = Pca.decodeB64uStrict(am.get("sig"), 64);
            return pk != null && sg != null && EdStrict.verify(pk, reviewMessage(body), sg) ? null : "the confirmation signature is invalid";
        } catch (RuntimeException e) {
            return "malformed confirmation: " + e.getMessage();
        }
    }
}
