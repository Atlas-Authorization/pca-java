package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Rule 13 step 7: session revocation (packages/pca/src/intent-revocation.ts {@code checkSessionRevocation}). Session ids,
 * map digests, delta-grant ids and profile versions are namespaced ids in the session's revocation set. ONE dedicated
 * revocation authority ({@code S.revocation.key}, never a principal) signs epochs that carry the FULL revoked list (sorted,
 * distinct, its revset root the signed {@code root}, its length {@code set_size == epoch}); the verifier needs an epoch at
 * most {@code max_age} old that lists none of the ids the action relies on and, when it tracks the last accepted epoch,
 * extends it append-only (no rollback, no drop, no equivocation).
 */
public final class IntentRevocation {
    private IntentRevocation() {}

    public static final String REVEPOCH_DOMAIN = "atlas-pca/revepoch/v1\0";
    private static final byte[] REVSET_PREFIX = "pca-revset/v1\0".getBytes(StandardCharsets.UTF_8);

    public static String sessionRevocationId(String session) { return "pca-intent:session:" + session; }
    public static String mapRevocationId(String mapDigest) { return "pca-intent:map:" + mapDigest; }
    public static String deltaRevocationId(String grantId) { return "pca-intent:delta:" + grantId; }
    public static String profileRevocationId(String profile, String version) { return "pca-intent:profile:" + profile + "@" + version; }
    public static String sessionRevocationScope(String session) { return "pca-intent-session:" + session; }

    /** JavaScript template-literal text of a JSON value ({@code `${x}`}). */
    static String jsText(Object x, boolean present) {
        if (!present) return "undefined";
        if (x == null) return "null";
        if (x instanceof Json.Num) return ((Json.Num) x).raw.equals("-0") ? "0" : ((Json.Num) x).raw;
        if (x instanceof List || x instanceof Map) return x instanceof List ? listText((List<?>) x) : "[object Object]";
        return String.valueOf(x);
    }
    private static String listText(List<?> l) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < l.size(); i++) {
            if (i > 0) b.append(',');
            Object e = l.get(i);
            if (e != null) b.append(jsText(e, true));
        }
        return b.toString();
    }

    private static String bindRoot(Object size, String treeRoot) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("size", size);
        m.put("tree", treeRoot);
        return Pca.b64(Pca.sha(REVSET_PREFIX, IntentJs.canonBytes(m)));
    }

    private static final String EMPTY_TREE = Pca.b64(Pca.sha(new byte[0]));

    /**
     * {@code revset_root(L)}: {@code base64url(SHA-256("pca-revset/v1\0" || canonical({size: |L|, tree})))} over the RFC 6962
     * Merkle root of {@code L} in order (leaf {@code SHA-256(0x00 || canonical(id))}, node {@code SHA-256(0x01 || l || r)}),
     * {@code tree = base64url(SHA-256(""))} for the empty list.
     */
    static String revsetRoot(List<String> ids) {
        return bindRoot(IntentJs.ofLong(ids.size()), ids.isEmpty() ? EMPTY_TREE : Pca.merkleRoot(new ArrayList<Object>(ids)));
    }

    /** JavaScript truthiness of a JSON value. */
    static boolean truthy(Object v) {
        if (v == null) return false;
        if (v instanceof Boolean) return (Boolean) v;
        if (v instanceof String) return !((String) v).isEmpty();
        Double d = IntentJs.num(v);
        if (d != null) return d != 0 && !Double.isNaN(d);
        return true;
    }

    /**
     * The revoked list is well-formed and is exactly what the epoch signs: an array of strings strictly ascending in UTF-8
     * byte order, {@code length == set_size == epoch}, {@code revset_root(revoked) == root}. Null = ok.
     */
    static String revokedListError(Map<String, Object> ep, Object revoked) {
        if (!(revoked instanceof List)) return "revoked must be an array of ids";
        List<String> r = new ArrayList<>();
        for (Object x : (List<?>) revoked) { if (!(x instanceof String)) return "revoked must be an array of ids"; r.add((String) x); }
        for (int i = 1; i < r.size(); i++) if (!(Json.compareUtf8(r.get(i - 1), r.get(i)) < 0)) return "revoked must be sorted by UTF-8 bytes and distinct";
        if (r.size() != IntentJs.num(ep.get("set_size")) || !IntentJs.num(ep.get("epoch")).equals(IntentJs.num(ep.get("set_size"))))
            return "the epoch must be numbered by its set size and list exactly set_size ids";
        if (!revsetRoot(r).equals(ep.get("root"))) return "the revoked list is not the signed set (root mismatch)";
        return null;
    }

    /**
     * The revocation epoch, strictly typed before any comparison: {@code instance_id}, {@code grant_ref}, {@code root},
     * {@code guardian}, {@code sig} strings; {@code epoch}, {@code set_size}, {@code issued_at}, {@code not_after} (and
     * {@code guardian_epoch} when present) non-negative safe integers; {@code alg} a suite this verifier implements;
     * {@code pq_pk} / {@code pq_sig} strings when present. Null = well-formed.
     */
    static String revocationEpochShapeError(Object epO) {
        if (!(epO instanceof Map)) return "the revocation epoch must be an object";
        Map<String, Object> ep = IntentJs.obj(epO);
        for (String k : new String[] {"instance_id", "grant_ref", "root", "guardian", "sig"}) if (!(ep.get(k) instanceof String)) return "revocation epoch " + k + " must be a string";
        for (String k : new String[] {"epoch", "set_size", "issued_at", "not_after"}) if (!IntentJs.isNonNeg(ep.get(k))) return "revocation epoch " + k + " must be a non-negative safe integer";
        if (ep.containsKey("guardian_epoch") && !IntentJs.isNonNeg(ep.get("guardian_epoch"))) return "revocation epoch guardian_epoch must be a non-negative safe integer";
        String se = IntentJs.suiteError(ep.get("alg"), ep.containsKey("alg"));
        if (se != null) return "revocation epoch alg: " + se;
        for (String k : new String[] {"pq_pk", "pq_sig"}) if (ep.containsKey(k) && !(ep.get(k) instanceof String)) return "revocation epoch " + k + " must be a string";
        return null;
    }

    /**
     * The signed epoch (shape already checked): signature under the guardian (a PQ epoch only under the PQ key pinned for
     * it), grant binding, {@code now <= not_after}, issued at most 60 s ahead.
     */
    static String checkRevocationEpoch(Map<String, Object> ep, String guardian, double now, String grantRef, Map<String, Object> pqPins) {
        try {
            if (!guardian.equals(ep.get("guardian")) || IntentJs.suiteOf(ep) == null) return "revocation epoch not signed by the pinned guardian";
            Map<String, Object> body = new LinkedHashMap<>();
            for (String k : new String[] {"instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after"}) body.put(k, ep.get(k));
            byte[] msg = Pca.concat(REVEPOCH_DOMAIN.getBytes(StandardCharsets.UTF_8),
                IntentJs.canonBytes(IntentJs.bindSuiteFields(body, ep.get("alg"), ep.containsKey("alg"), ep.get("pq_pk"), ep.containsKey("pq_pk"))));
            if (!IntentJs.verifyPinnedSuite(ep.get("alg"), ep.containsKey("alg"), guardian, ep.get("pq_pk"), msg, ep.get("sig"), ep.get("pq_sig"), pqPins))
                return "revocation epoch signature invalid";
            if (!grantRef.equals(ep.get("grant_ref"))) return "revocation epoch is for a different grant";
            if (!(now <= IntentJs.num(ep.get("not_after")))) return "revocation epoch expired (stale revocation root)";
            if (!(IntentJs.num(ep.get("issued_at")) <= now + 60_000)) return "revocation epoch issued in the future";
            return null;
        } catch (RuntimeException e) {
            return "revocation epoch check error";
        }
    }

    /**
     * The session revocation step (rule 13 step 7). First failure wins: a. {@code maxAgeMs} a safe integer &gt;= 0, the clock a
     * safe integer, {@code ids} a list, the authority a string; b. the evidence an object with a well-formed epoch whose
     * guardian is the dedicated {@code authority}; c. the epoch verifies for the scope (PQ only under {@code pqPins}); d. it is
     * at most {@code maxAgeMs} old; e. {@code revoked} is the full signed set; f. APPEND-ONLY against the tracked
     * {@code last} when present; g. no id of {@code ids} is revoked. Null = ok.
     */
    public static String checkSessionRevocation(Object ev, String session, Object authority, List<?> ids, double now, double maxAgeMs,
                                                String scope, Map<String, Object> pqPins, boolean lastPresent, Object last) {
        try {
            if (!(Double.isFinite(maxAgeMs) && maxAgeMs == Math.rint(maxAgeMs) && maxAgeMs <= IntentJs.MAX_SAFE && maxAgeMs >= 0 && !IntentJs.isNegZero(maxAgeMs)))
                return "revocation max age misconfigured (fail closed)";
            if (!(Double.isFinite(now) && now == Math.rint(now) && Math.abs(now) <= IntentJs.MAX_SAFE && !IntentJs.isNegZero(now))) return "the verifier clock is not a safe integer (fail closed)";
            if (ids == null || !(authority instanceof String)) return "ids must be an array and the authority a key";
            if (!(ev instanceof Map)) return "no session revocation epoch supplied";
            String ce = closedEvidenceError(ev);
            if (ce != null) return "the revocation evidence " + ce;
            Object epO = IntentJs.get(ev, "epoch");
            String shape = revocationEpochShapeError(epO);
            if (shape != null) return shape;
            Map<String, Object> ep = IntentJs.obj(epO);
            if (!authority.equals(ep.get("guardian"))) return "the revocation epoch is not signed by the session revocation authority";
            String r = checkRevocationEpoch(ep, (String) authority, now, scope != null ? scope : sessionRevocationScope(session), pqPins);
            if (r != null) return r;
            if (!(now - IntentJs.num(ep.get("issued_at")) <= maxAgeMs)) return "the session revocation epoch is older than " + (long) maxAgeMs + " ms";
            Object revoked = IntentJs.get(ev, "revoked");
            String le = revokedListError(ep, revoked);
            if (le != null) return le;
            if (lastPresent) {
                Object lep = IntentJs.get(last, "epoch");
                if (!(last instanceof Map) || closedEvidenceError(last) != null || revocationEpochShapeError(lep) != null || revokedListError(IntentJs.obj(lep), IntentJs.get(last, "revoked")) != null)
                    return "the tracked last epoch is malformed (fail closed)";
                if (IntentJs.num(ep.get("epoch")) < IntentJs.num(IntentJs.get(lep, "epoch"))) return "revocation epoch rollback (older than the last accepted)";
                Set<Object> cur = new HashSet<>((List<?>) revoked);
                for (Object id : (List<?>) IntentJs.get(last, "revoked"))
                    if (!cur.contains(id)) return "the epoch drops '" + id + "', revoked in the last accepted epoch (not append-only)";
                if (IntentJs.num(ep.get("epoch")).equals(IntentJs.num(IntentJs.get(lep, "epoch"))) && !ep.get("root").equals(IntentJs.get(lep, "root")))
                    return "two different revocation sets under one epoch number (equivocation)";
            }
            Set<Object> rv = new HashSet<>((List<?>) revoked);
            for (Object id : ids) if (!(id instanceof String) || rv.contains(id)) return "'" + jsText(id, true) + "' is revoked";
            return null;
        } catch (RuntimeException e) {
            return "session revocation check error (fail closed): " + e.getClass().getSimpleName();
        }
    }

    /** The evidence is CLOSED: exactly the members {@code epoch} and {@code revoked} (an extra member is malformed). Null = ok. */
    static String closedEvidenceError(Object ev) {
        for (Object k : ((Map<?, ?>) ev).keySet()) if (!"epoch".equals(k) && !"revoked".equals(k)) return "has the unknown member '" + k + "' (it is exactly {epoch, revoked})";
        return null;
    }

    /** The parameters of {@code primitives.intent_revocation}; every other input member belongs to the (closed) evidence. */
    static final List<String> PRIMITIVE_PARAMS = List.of("session", "scope", "authority", "ids", "now", "max_age_ms", "last");

    /**
     * The {@code primitives.intent_revocation} entry point: {@code {epoch, revoked, session, authority, ids, now, max_age_ms,
     * last?}} with the scope {@code "pca-intent-session:" + session}.
     */
    public static boolean checkPrimitive(Object input) { return primitiveReason(input) == null; }

    /** As {@link #checkPrimitive}, with the refusal reason (null = ok). */
    public static String primitiveReason(Object input) {
        try {
            Map<String, Object> in = IntentJs.obj(IntentJs.normalize(input));
            Map<String, Object> ev = new LinkedHashMap<>(in);
            for (String k : PRIMITIVE_PARAMS) ev.remove(k);
            double maxAge = IntentJs.isInt(in.get("max_age_ms")) ? IntentJs.num(in.get("max_age_ms")) : Double.NaN;
            double now = IntentJs.isInt(in.get("now")) ? IntentJs.num(in.get("now")) : Double.NaN;
            List<?> ids = in.get("ids") instanceof List ? (List<?>) in.get("ids") : null;
            return checkSessionRevocation(ev, in.get("session") instanceof String ? (String) in.get("session") : null, in.get("authority"), ids, now, maxAge,
                null, null, in.containsKey("last"), in.get("last"));
        } catch (RuntimeException e) {
            return "session revocation check error (fail closed)";
        }
    }
}
