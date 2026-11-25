package net.atlasauth.pca.evidence;

import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.revoke.JsVal;
import net.atlasauth.pca.scitt.Scitt;

/**
 * Registration reference of an evidence bundle: its digest anchors in the intent anchor log (kind {@code evidence}) and a SCITT
 * signed statement names the bundle by that digest. {@link #evidenceRef} is the payload; {@link #evidenceSignedStatement} signs it as a
 * COSE Signed Statement through the SCITT port.
 */
public final class EvidenceScitt {
    private EvidenceScitt() {}

    public static final String EVIDENCE_CONTENT_TYPE = "application/pca-intent-evidence+json";

    @SuppressWarnings("unchecked")
    public static Map<String, Object> evidenceRef(Object bundle) {
        Map<String, Object> ref = new LinkedHashMap<>();
        ref.put("kind", "pca-intent-evidence-ref");
        ref.put("digest", EvidenceBundle.evidenceDigest(bundle));
        Object subj = JsVal.member(bundle, "subject");
        // {...bundle.subject}: a spread of a non-object is empty
        ref.put("subject", subj instanceof Map ? new LinkedHashMap<>((Map<String, Object>) subj) : new LinkedHashMap<String, Object>());
        return ref;
    }

    /**
     * A COSE Signed Statement over the bundle reference, ready to register with a SCITT service. The subject defaults to the bundle's
     * {@code subject.pcactn_digest}; the content type is always {@link #EVIDENCE_CONTENT_TYPE} (any {@code opts.contentType} is replaced).
     * A non-string subject digest is refused (the statement's subject claim is text).
     */
    public static byte[] evidenceSignedStatement(Object bundle, Scitt.SignStatementOpts opts) {
        Map<String, Object> ref = evidenceRef(bundle);
        String subject = opts.subject;
        if (subject == null) {
            Object d = ((Map<?, ?>) ref.get("subject")).get("pcactn_digest");
            if (d != null && !(d instanceof String)) throw new IllegalArgumentException("evidenceSignedStatement: subject.pcactn_digest must be a string");
            subject = (String) d;
        }
        Scitt.SignStatementOpts o = new Scitt.SignStatementOpts(opts.alg, opts.key, opts.issuer).contentType(EVIDENCE_CONTENT_TYPE);
        if (subject != null) o.subject(subject);
        return Scitt.signStatement(ref, o);
    }

    /** The intent-anchor-log leaf for a bundle digest ({@code intentAnchorCommit} construction, kind {@code evidence}). */
    public static String evidenceAnchorCommit(String digest) { return EvidenceVerify.anchorCommit("evidence", digest); }
}
