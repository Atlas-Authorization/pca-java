package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Action receipts: the principal's own tamper-evident, hash-chained log of what their agents did and how each action was verified. Each receipt
 * commits to the previous one, so a dropped or altered entry is detectable. Pure (hashing only). A receipt is
 * {@code {seq, at, actionDigest, verb, resource, outcome: allow|deny, checks?, prev, hash}}.
 */
public final class Receipts {
    private Receipts() {}

    /** A missing member is undefined in the reference, and canonicalizing an undefined value throws. */
    private static Object member(Map<String, Object> r, String k) {
        if (!r.containsKey(k)) throw new IllegalArgumentException("cannot canonicalize undefined (" + k + ")");
        return r.get(k);
    }

    private static Map<String, Object> body(Map<String, Object> r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", "atlas-pca/receipt/v1");
        m.put("seq", member(r, "seq"));
        m.put("at", member(r, "at"));
        m.put("actionDigest", member(r, "actionDigest"));
        m.put("verb", member(r, "verb"));
        m.put("resource", member(r, "resource"));
        m.put("outcome", member(r, "outcome"));
        m.put("checks", r.containsKey("checks") ? r.get("checks") : null);
        m.put("prev", member(r, "prev"));
        return m;
    }

    /** The next receipt in a chain for a verified action; {@code checks} may be null, {@code at} may be null (the action's {@code iat}). */
    public static Map<String, Object> receiptFor(String prevHash, long seq, Map<String, Object> pcactn, boolean allow, Map<String, Object> checks, Double at) {
        Map<String, Object> action = StoreJs.map(pcactn.get("action"));
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("seq", StoreJs.num(seq));
        b.put("at", at != null ? StoreJs.num(at) : pcactn.get("iat"));
        b.put("actionDigest", Pca.hashCanonical(pcactn));
        b.put("verb", action.get("verb"));
        b.put("resource", action.get("resource"));
        b.put("outcome", allow ? "allow" : "deny");
        if (checks != null) b.put("checks", checks);
        b.put("prev", prevHash);
        Map<String, Object> r = new LinkedHashMap<>(b);
        r.put("hash", Pca.hashCanonical(body(b)));
        return r;
    }

    /** A copy of {@code log} with the verified action appended, chained to the last entry. */
    public static List<Object> appendReceipt(List<Object> log, Map<String, Object> pcactn, boolean allow, Map<String, Object> checks, Double at) {
        Map<String, Object> last = log.isEmpty() ? null : StoreJs.map(log.get(log.size() - 1));
        String prev = last != null && last.get("hash") != null ? (String) last.get("hash") : "";
        long seq = last != null && last.get("seq") != null ? Json.asLong(last.get("seq")) + 1 : 0;
        List<Object> out = new ArrayList<>(log);
        out.add(receiptFor(prev, seq, pcactn, allow, checks, at));
        return out;
    }

    /** Verify a receipt log is an intact hash chain: {@code {ok}} or {@code {ok:false, brokenAt, reason}} for the first broken link. */
    public static Map<String, Object> verifyReceiptChain(List<Object> log) {
        String prev = "";
        for (int i = 0; i < log.size(); i++) {
            Map<String, Object> r = StoreJs.map(log.get(i));
            Object seq = r.get("seq");
            boolean has = r.containsKey("seq");
            String st = IntentRevocation.jsText(seq, has);
            if (!Ledger.jsEq(seq, StoreJs.num((long) i))) return broken(seq, has, "seq " + st + " out of order (expected " + i + ")");
            if (!Ledger.jsEq(r.get("prev"), prev)) return broken(seq, has, "prev link mismatch at seq " + st);
            if (!Ledger.jsEq(Pca.hashCanonical(body(r)), r.get("hash"))) return broken(seq, has, "hash mismatch at seq " + st + " (tampered body)");
            prev = (String) r.get("hash");
        }
        Map<String, Object> ok = new LinkedHashMap<>();
        ok.put("ok", true);
        return ok;
    }

    private static Map<String, Object> broken(Object seq, boolean has, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        if (has) m.put("brokenAt", seq);
        m.put("reason", reason);
        return m;
    }

    /** The head hash of a log: one value that commits to the entire history ("" for an empty log). */
    public static String receiptHead(List<Object> log) {
        if (log.isEmpty()) return "";
        Object h = StoreJs.map(log.get(log.size() - 1)).get("hash");
        return h == null ? "" : (String) h;
    }
}
