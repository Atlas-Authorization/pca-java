package net.atlasauth.pca.evidence;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.revoke.JsVal;

/**
 * The dispute-evidence replay: {@link #verifyEvidenceBundle} plus its pure helpers (the anchor leaf, the grant cap reader and the
 * trust-input validators).
 */
public final class EvidenceVerify {
    private EvidenceVerify() {}

    public static final String EVIDENCE_REPORT_DOMAIN = "atlas-pca/intent-evidence-report/v1";
    public static final String INTENT_ANCHOR_DOMAIN = "atlas-pca/intent-anchor/v1";
    public static final String INTENT_ANCHOR_LOG = "pca-intent:v1";

    /** The intent-log leaf for an anchored artifact (the {@code intentAnchorCommit} construction, any kind). */
    public static String anchorCommit(String kind, String digest) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", INTENT_ANCHOR_DOMAIN);
        m.put("kind", kind);
        m.put("digest", digest);
        return Pca.hashCanonical(m);
    }

    private static boolean isGroup(Object c) {
        return c instanceof Map && (((Map<?, ?>) c).containsKey("all_of") || ((Map<?, ?>) c).containsKey("any_of") || ((Map<?, ?>) c).containsKey("not"));
    }

    private static boolean isLeaf(Object c) { return c instanceof Map && !isGroup(c) && ((Map<?, ?>) c).get("field") instanceof String; }

    private static void leafCaps(Object conds, String path, List<Double> out) {
        if (conds == null) return;
        if (conds instanceof String) return; // iterating a string yields characters, none of them a condition
        if (!(conds instanceof List)) throw new IllegalArgumentException("TypeError: conditions are not iterable");
        for (Object c : (List<?>) conds) {
            if (isLeaf(c)) {
                Map<?, ?> m = (Map<?, ?>) c;
                // `c.ref !== undefined`: a JSON null member is a defined value
                if (!path.equals(m.get("field")) || m.containsKey("ref") || JsVal.num(m.get("value")) == null) continue;
                double v = JsVal.num(m.get("value"));
                if ("lte".equals(m.get("op"))) out.add(v);
                else if ("lt".equals(m.get("op"))) out.add(v - 1);
            } else if (isGroup(c) && ((Map<?, ?>) c).containsKey("all_of")) {
                leafCaps(((Map<?, ?>) c).get("all_of"), path, out);
            }
        }
    }

    /**
     * The cap {@code env.acc.<id>.post <= v} the grant's envelope states for {@code verb}: per predicate the tightest bound in
     * its {@code where} (descending into {@code all_of}); across predicates the loosest. Null when a predicate admitting the
     * verb states no bound, or none admits it.
     */
    public static Double capOf(Object grant, String accId, String verb) {
        Map<String, Object> env = Authorize.readEnvelope(grant);
        if (env == null) return null;
        String path = "env.acc." + accId + ".post";
        Double cap = null;
        for (Object p : (List<?>) env.get("predicates")) {
            Object pv = JsVal.member(p, "verb");
            List<String> verbs = new ArrayList<>();
            if (pv instanceof List) for (Object x : (List<?>) pv) verbs.add(JsVal.str(x));
            else verbs.add(JsVal.str(pv));
            if (!verbs.contains(verb) && !verbs.contains("*")) continue;
            List<Double> caps = new ArrayList<>();
            leafCaps(JsVal.opt(p, "where"), path, caps);
            if (caps.isEmpty()) return null;
            double m = Double.POSITIVE_INFINITY;
            for (double d : caps) { if (Double.isNaN(d)) { m = Double.NaN; break; } m = Math.min(m, d); }
            cap = cap == null ? m : (Double.isNaN(cap) || Double.isNaN(m) ? Double.NaN : Math.max(cap, m));
        }
        return cap;
    }

    /** Validate {@code trust.principals}: a non-empty array of closed {key, pq_pk?} with canonical keys. Null = valid. */
    public static String principalsTrustError(Object p) {
        if (!(p instanceof List) || ((List<?>) p).isEmpty()) return "trust.principals must be a non-empty array of {key, pq_pk?}";
        List<?> l = (List<?>) p;
        for (int i = 0; i < l.size(); i++) {
            Object x = l.get(i);
            if (!(x instanceof Map)) return "trust.principals[" + i + "] must be an object {key, pq_pk?}";
            for (String k : EvidenceBundle.jsKeys((Map<?, ?>) x)) {
                if (!k.equals("key") && !k.equals("pq_pk")) return "trust.principals[" + i + "]: unknown member '" + k + "'";
            }
            Map<?, ?> o = (Map<?, ?>) x;
            if (Pca.decodeB64uStrict(o.get("key"), 32) == null) return "trust.principals[" + i + "].key must be canonical base64url (32 bytes)";
            if (o.containsKey("pq_pk") && Pca.decodeB64uStrict(o.get("pq_pk"), -1) == null) return "trust.principals[" + i + "].pq_pk must be canonical base64url";
        }
        return null;
    }

    /** Validate {@code trust.acc} like core {@code policy.acc}: closed members, non-negative safe integers. Null = valid. */
    public static String accTrustError(Object a) {
        if (!(a instanceof Map)) return "trust.acc must be an object";
        Map<?, ?> m = (Map<?, ?>) a;
        for (String k : EvidenceBundle.jsKeys(m)) {
            if (!k.equals("max_receipt_age_s") && !k.equals("max_keyset_age_s")) return "trust.acc: unknown member '" + k + "'";
            if (!EvidenceBundle.isNonNegInt(m.get(k))) return "trust.acc." + k + " must be a non-negative safe integer";
        }
        return null;
    }

    /**
     * Replay a bundle (spec section 3.11). {@code trust} is the reader's trust input as a JSON tree (siteKeys, principals, minTier, typedValues,
     * credentials, canaryLabels, oracleKeys, judges, labelKeys, anchorGuardian, acc, jitTier, sessionRootDigest); {@code verifiers} are the optional
     * ports keyed sessionRoot, schema, receipt, fact, classifier, offerSet, labels, effect, verdict, settlement. Never throws: a malformed bundle is a
     * report with a failed {@code shape} finding.
     */
    public static Map<String, Object> verifyEvidenceBundle(Object input, Map<String, Object> trust, Map<String, EvidenceReplay.Port> verifiers) {
        return EvidenceReplay.verify(input, trust, verifiers);
    }

    public static Map<String, Object> verifyEvidenceBundle(Object input, Map<String, Object> trust) { return EvidenceReplay.verify(input, trust, null); }
}
