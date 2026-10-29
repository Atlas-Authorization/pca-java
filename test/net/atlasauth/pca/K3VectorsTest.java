package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The K3 operational-plane corpus (k3-vectors.json): every vector of every primitive must reproduce the reference outcome exactly
 * (codes, reasons, digests). The set of kinds and each table's size are pinned; a missing file, kind or table FAILS, it is never skipped.
 */
public class K3VectorsTest {
    static final Map<String, Object> DOC = Track3Vectors.load("k3-vectors.json");

    static final Map<String, Integer> COUNTS = Map.ofEntries(
        Map.entry("fresh_at_verify", 5), Map.entry("fresh_at_digest", 2), Map.entry("fresh_at_check", 14), Map.entry("bundle_digest", 2),
        Map.entry("bundle_verify", 15), Map.entry("log_commit", 3), Map.entry("log_head_verify", 4), Map.entry("log_inclusion", 6),
        Map.entry("log_batch_verify", 9), Map.entry("list_objects_digest", 1), Map.entry("list_receipt_verify", 6), Map.entry("list_bind", 2),
        Map.entry("list_cursor_verify", 11), Map.entry("authority_digest", 2), Map.entry("authority_compare", 11), Map.entry("amend_verify", 16),
        Map.entry("revoke_verify", 7), Map.entry("need_approve_verify", 11));

    @SuppressWarnings("unchecked")
    static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    static String s(Object o) { return o instanceof String ? (String) o : null; }

    static Map<String, Object> obj(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) out.put((String) kv[i], kv[i + 1]);
        return out;
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> rows(String kind) {
        Object prim = DOC.get("primitives");
        if (!(prim instanceof Map) || !(m(prim).get(kind) instanceof List)) { fail(kind + ": missing table"); return null; }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object o : (List<Object>) m(prim).get(kind)) out.add(m(o));
        assertEquals(COUNTS.get(kind).intValue(), out.size(), kind + ": vector count");
        return out;
    }

    static void run(String kind, java.util.function.Function<Map<String, Object>, Object> fn) {
        for (Map<String, Object> v : rows(kind)) {
            Object got;
            try { got = fn.apply(m(v.get("input"))); } catch (Throwable t) { fail(kind + "/" + v.get("name") + ": THREW " + t); return; }
            assertEquals(Json.canonicalize(v.get("expect")), Json.canonicalize(got), kind + "/" + v.get("name"));
        }
    }

    @Test void everyKindIsCovered() {
        assertEquals(COUNTS.keySet(), m(DOC.get("primitives")).keySet());
        assertEquals(1L, Json.asLong(DOC.get("format")));
    }

    @Test void freshAtVerify() {
        run("fresh_at_verify", in -> obj("valid", K3.verifyFreshAt(in.get("token"), s(in.get("signer")))));
    }

    @Test void freshAtDigest() {
        run("fresh_at_digest", in -> obj("digest", K3.freshAtDigest(in.get("token"))));
    }

    @Test void freshAtCheck() {
        run("fresh_at_check", in -> {
            Map<String, Object> o = m(in.get("options"));
            Double max = o.containsKey("maxTokenAgeMs") ? IntentJs.num(o.get("maxTokenAgeMs")) : null;
            K3.FreshVerdict r = K3.checkFreshAt(in.get("token"), m(in.get("local")), s(o.get("signer")), s(o.get("scope")), Json.asLong(o.get("now")), max);
            Map<String, Object> out = obj("decision", r.decision);
            if (r.code != null) out.put("code", r.code);
            if (r.decision.equals("escalate")) out.put("behind", new ArrayList<Object>(r.behind));
            return out;
        });
    }

    @Test void bundleDigest() {
        run("bundle_digest", in -> obj("digest", K3.bundleDigest(in.get("bundle"))));
    }

    @Test void bundleVerify() {
        run("bundle_verify", in -> {
            Map<String, Object> o = m(in.get("options"));
            Map<String, Object> last = o.containsKey("last") ? m(o.get("last")) : null;
            K3.BundleVerdict r = K3.verifyBundle(in.get("bundle"), (List<?>) o.get("signers"), o.get("threshold"), s(o.get("verifierVersion")),
                last == null ? null : Long.valueOf(Json.asLong(last.get("revision"))), last == null ? null : s(last.get("digest")));
            if (!r.ok) return obj("ok", false, "code", r.code, "reason", r.reason);
            return obj("ok", true, "revision", IntentJs.ofLong(r.revision), "digest", r.digest, "signers", new ArrayList<Object>(r.signers));
        });
    }

    @Test void logCommit() {
        run("log_commit", in -> obj("commit", K3.recordCommit(in.get("record"))));
    }

    @Test void logHeadVerify() {
        run("log_head_verify", in -> obj("valid", K3.verifyLogHead(in.get("head"), s(in.get("signer")))));
    }

    @Test void logInclusion() {
        run("log_inclusion", in -> obj("valid", K3.verifyRecordInclusion(in.get("record"), in.get("proof"), in.get("head"), s(in.get("signer")))));
    }

    @Test void logBatchVerify() {
        run("log_batch_verify", in -> {
            Map<String, Object> st = m(in.get("state"));
            K3.BatchVerdict r = K3.verifyBatch(in.get("batch"), Json.asLong(st.get("next")), s(st.get("lastCommit")), s(in.get("signer")));
            return r.ok ? obj("ok", true, "next", IntentJs.ofLong(r.next), "lastCommit", r.lastCommit) : obj("ok", false, "reason", r.reason);
        });
    }

    @Test void listObjectsDigest() {
        run("list_objects_digest", in -> obj("digest", K3.objectsDigest((List<?>) in.get("objects"))));
    }

    @Test void listReceiptVerify() {
        run("list_receipt_verify", in -> obj("valid", K3.verifyListReceipt(in.get("receipt"), s(in.get("signer")), (List<?>) in.get("objects"))));
    }

    @Test void listBind() {
        run("list_bind", in -> obj("digest", K3.listBind(m(in.get("bind")))));
    }

    @Test void listCursorVerify() {
        run("list_cursor_verify", in -> {
            K3.CursorVerdict r = K3.verifyListCursor(in.get("cursor"), s(in.get("signer")), in.containsKey("bind") ? m(in.get("bind")) : null);
            if (!r.ok) return obj("ok", false, "reason", r.reason);
            Map<String, Object> out = obj("ok", true);
            if (r.inner != null) out.put("inner", r.inner);
            out.put("skip", IntentJs.ofLong(r.skip));
            return out;
        });
    }

    @Test void authorityDigest() {
        run("authority_digest", in -> obj("digest", K3.authorityDigest(in.get("authority"))));
    }

    @Test void authorityCompare() {
        run("authority_compare", in -> obj("order", K3.compareAuthority(in.get("old"), in.get("new"))));
    }

    @Test void amendVerify() {
        run("amend_verify", in -> {
            K3.AmendVerdict r = K3.verifyAmendment(in.get("grant"), in.get("request"), Boolean.TRUE.equals(in.get("step_up_ok")));
            return r.ok ? obj("ok", true, "widens", r.widens, "next_digest", K3.authorityDigest(r.next)) : obj("ok", false, "code", r.code);
        });
    }

    @Test void revokeVerify() {
        run("revoke_verify", in -> {
            K3.RevokeVerdict r = K3.verifyRevokeSignature(in.get("root"), in.get("scope"), in.get("sig"));
            return r.ok ? obj("ok", true, "scope", r.scope) : obj("ok", false, "code", r.code);
        });
    }

    @Test void needApproveVerify() {
        run("need_approve_verify", in -> {
            K3.NeedVerdict r = K3.verifyNeedApproval(in.get("need_request"), in.get("grant"), in.get("approved"), in.get("sig"), Boolean.TRUE.equals(in.get("step_up_ok")));
            return r.ok ? obj("ok", true, "authority_digest", K3.authorityDigest(r.authority)) : obj("ok", false, "code", r.code);
        });
    }

    /** Hostile shapes never throw and are never accepted. */
    @Test void hostileInputsAreRefused() {
        for (String text : List.of("null", "1", "\"x\"", "[]", "{}", "{\"v\":1e999}", "[null]", "{\"sig\":null,\"signer\":null}")) {
            Object v = Json.parseLenient(text);
            assertTrue(!K3.verifyFreshAt(v, "k") && !K3.verifyLogHead(v, "k") && !K3.verifyListReceipt(v, "k", null), text);
            assertTrue(!K3.verifyRecordInclusion(v, v, v, "k"), text);
            assertEquals("deny", K3.checkFreshAt(v, null, "k", "s", 0L, null).decision, text);
            assertEquals(false, K3.verifyBundle(v, List.of("k"), v, "0.5.0", null, null).ok, text);
            assertEquals(false, K3.verifyBatch(v, 0L, "", "k").ok, text);
            assertEquals(false, K3.verifyListCursor(v, "k", null).ok, text);
            assertEquals(false, K3.verifyAmendment(v, v, true).ok, text);
            assertEquals(false, K3.verifyRevokeSignature(v, v, v).ok, text);
            assertEquals(false, K3.verifyNeedApproval(v, v, v, v, true).ok, text);
            assertEquals("incomparable", K3.compareAuthority(v, v), text);
        }
    }
}
