package net.atlasauth.pca.research;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import net.atlasauth.pca.BondSettlement;

/**
 * Reputation from verifiable records: disputes are derived ONLY from guardian-signed settlement records (open, release, slash). A record
 * whose signature does not verify (or whose claim has no known subject) is counted in {@code rejected}, never as a dispute.
 */
public final class ReputationEvidence {
    private ReputationEvidence() {}

    /**
     * {@code {disputes: [{id, subject, slashed, at, amount}], rejected}}. {@code subjectOf} maps a bond or claim handle to the subject it was
     * posted for (null = unknown, and the record is rejected); {@code pin} is the post-quantum pin policy for hybrid records (may be null).
     */
    public static Map<String, Object> disputesFromSettlements(List<?> records, String guardianPublicKey, Function<String, String> subjectOf, Map<String, Object> pin) {
        List<Object> disputes = new ArrayList<>();
        long rejected = 0;
        for (Object ro : records) {
            Map<String, Object> r = Js.map(ro);
            String subject = r != null && r.get("claimId") instanceof String ? subjectOf.apply((String) r.get("claimId")) : null;
            if (subject == null || !BondSettlement.verifySettlement(ro, guardianPublicKey, pin)) { rejected++; continue; }
            if ("open".equals(r.get("action"))) continue; // an open bond is not an outcome
            Map<String, Object> d = Js.obj();
            d.put("id", BondSettlement.settlementRecordDigest(r));
            d.put("subject", subject);
            d.put("slashed", "slash".equals(r.get("action")));
            if (r.containsKey("at")) d.put("at", r.get("at"));
            if (r.containsKey("amount")) d.put("amount", r.get("amount"));
            disputes.add(d);
        }
        Map<String, Object> out = Js.obj();
        out.put("disputes", disputes);
        out.put("rejected", Js.n(rejected));
        return out;
    }
}
