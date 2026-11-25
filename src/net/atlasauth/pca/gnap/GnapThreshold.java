package net.atlasauth.pca.gnap;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.Pq;
import net.atlasauth.pca.Threshold;

/**
 * The t-of-n distinct-role count of the reference's {@code verifyThreshold} (the continuation passes no agent-leaf baseline, as the
 * reference does), over the explicit shares folded into a PCActn. The signer set is validated first and the whole verification fails
 * closed if it is malformed; a share counts iff its role and key are registered and its signature (Ed25519, pure PQ or hybrid, against
 * the role's registered pq_pk) verifies over the role/signer-set/t-bound share message. A suite this verifier does not implement is refused
 * as an unknown algorithm.
 */
final class GnapThreshold {
    private GnapThreshold() {}

    private static final Set<String> ROLES = Set.of("agent", "guardian", "principal");
    private static final Set<Integer> PQ_PK_LENGTHS = Set.of(1952, 2592, 32, 64, 897, 1793, 97484);

    /** Reason text for a possibly hostile value: primitives as String(v), containers by kind only. */
    private static String show(Object v) {
        if (v instanceof Map) return "<object>";
        if (v instanceof List) return "<array>";
        return Js.str(v);
    }

    private static Object member(Object o, String k) { return Js.member(o, k); }

    private static boolean pqPkOk(Object v) {
        if (!(v instanceof String)) return false;
        byte[] b = Pca.decodeB64uStrict(v, -1);
        return b != null && PQ_PK_LENGTHS.contains(b.length);
    }

    private static Map<String, Object> verdict(boolean ok, int count, List<String> roles, String reason) {
        Map<String, Object> m = Issue.obj("ok", ok, "count", (long) count, "roles", new ArrayList<Object>(roles));
        if (reason != null) m.put("reason", reason);
        return m;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> verify(Map<String, Object> threshold, byte[] message, List<Object> signerSet, int t) {
        if (t < 1 || t > 3) return verdict(false, 0, new ArrayList<>(), "invalid threshold t=" + t + " (must be 1, 2 or 3)");
        // ---- the signer set (BuildReg): role -> key, role -> registered pq_pk
        Map<String, String> keyOfRole = new HashMap<>();
        Map<String, String> roleOfKey = new HashMap<>();
        Map<String, String> pqOfRole = new HashMap<>();
        Map<String, String> seenEntry = new HashMap<>();
        for (int i = 0; i < signerSet.size(); i++) {
            Object s = signerSet.get(i);
            Object ro = member(s, "role"), ko = member(s, "publicKey");
            String role = ro instanceof String && ROLES.contains(ro) ? (String) ro : null;
            boolean keyOk = s != null && Pca.decodeB64uStrict(ko, 32) != null;
            boolean hasPq = Js.has(s, "pq_pk"); // a present pq_pk (JSON null is present)
            boolean pqOk = !hasPq || pqPkOk(member(s, "pq_pk"));
            if (role != null && keyOk && pqOk) {
                String id = role + "\0" + ko;
                String pq = member(s, "pq_pk") instanceof String ? (String) member(s, "pq_pk") : null;
                // a duplicate (role, key) entry is harmless only if it registers the SAME pq_pk (or none on both)
                if (seenEntry.containsKey(id) && !java.util.Objects.equals(seenEntry.get(id), pq)) pqOk = false;
                else seenEntry.put(id, pq);
                if (pqOk && !pqOfRole.containsKey(role) && !keyOfRole.containsKey(role)) { if (pq != null) pqOfRole.put(role, pq); }
            }
            if (!(role != null && keyOk)) return verdict(false, 0, new ArrayList<>(), "malformed signer set");
            if (!pqOk) return verdict(false, 0, new ArrayList<>(), "malformed signer set (pq_pk)");
            String prevKey = keyOfRole.get(role);
            if (prevKey != null && !prevKey.equals(ko)) return verdict(false, 0, new ArrayList<>(), "signer set registers more than one key for role " + show(ro));
            String prevRole = roleOfKey.get((String) ko);
            if (prevRole != null && !prevRole.equals(role)) return verdict(false, 0, new ArrayList<>(), "signer set registers one key under two roles");
            if (prevKey == null) { keyOfRole.put(role, (String) ko); roleOfKey.put((String) ko, role); }
        }

        // ---- the shares, in order
        Object sh0 = threshold == null ? null : threshold.get("shares");
        List<Object> shares = sh0 instanceof List ? (List<Object>) sh0 : new ArrayList<>();
        List<String> keys = new ArrayList<>();
        List<String> roles = new ArrayList<>();
        String reason = null;
        for (Object share : shares) {
            boolean wellFormed = share instanceof Map && member(share, "role") instanceof String && member(share, "publicKey") instanceof String;
            if (!wellFormed) { if (reason == null) reason = "malformed share"; continue; }
            String pub = (String) member(share, "publicKey");
            if (keys.contains(pub)) continue;
            String roleName = (String) member(share, "role");
            String regKey = ROLES.contains(roleName) ? keyOfRole.get(roleName) : null;
            String fail = null;
            if (regKey == null) fail = "role " + show(roleName) + " is not in the signer set";
            else if (!regKey.equals(pub)) fail = "share for role " + show(roleName) + " uses a key not registered for that role";
            else if (!Pq.sigAlgKnown(member(share, "alg"), Js.has(share, "alg")))
                fail = "share for role " + show(roleName) + " declares an unknown signature alg";
            else if (Js.has(share, "pq_pk") && !(member(share, "pq_pk") instanceof String && member(share, "pq_pk").equals(pqOfRole.get(roleName))))
                fail = "share for role " + show(roleName) + " names a pq_pk that is not the key its role registers";
            else if (!Threshold.verifyShare(roleName, message, signerSet, t, (Map<String, Object>) share))
                fail = "invalid signature for role " + show(roleName); // PQ / hybrid shares verify against the role's registered pq_pk; a role that registers one refuses an Ed25519-only share
            if (fail != null) { if (reason == null) reason = fail; continue; }
            keys.add(pub);
            roles.add(roleName);
        }
        int count = keys.size();
        if (count >= t) return verdict(true, count, roles, null);
        return verdict(false, count, roles, reason != null ? reason : "only " + count + " distinct valid key(s), need " + t);
    }
}
