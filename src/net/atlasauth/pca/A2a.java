package net.atlasauth.pca;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The A2A binding (verification side): typed needs ({@code pca_need}), per-hop chain extension, the pure gate of AUTH_REQUIRED
 * resumption, push-token binding and signed task-update receipts. Total. Per-hop PCActn verification is the ordinary verifier's job;
 * this is what surrounds it. Replays packages/pca/conformance/a2a-vectors.json.
 */
public final class A2a {
    private A2a() {}

    public static final String RECEIPT_DOMAIN = "atlas-pca/a2a-receipt/v1\u0000";
    private static final Set<String> NEED_MEMBERS = Set.of("v", "kind", "verb", "resource", "scopes", "grant_ref", "limits", "discharges", "tier", "policy_digest");
    private static final Set<String> TERMINAL = Set.of("TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED");
    private static final Set<String> STATES = Set.of("TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED",
        "TASK_STATE_SUBMITTED", "TASK_STATE_WORKING", "TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED");

    private static boolean str(Object o, int max) { return o instanceof String && !((String) o).isEmpty() && ((String) o).length() <= max; }
    private static Double dbl(Object o) {
        try {
            if (o instanceof Json.Num) { double d = Double.parseDouble(((Json.Num) o).raw); return Double.isFinite(d) ? d : null; }
        } catch (NumberFormatException e) { return null; }
        return null;
    }
    private static boolean nat(Object o) { return Json.isSafeInt(o) && Json.asLong(o) >= 0; }

    /** null when valid, else the refusal code. */
    @SuppressWarnings("unchecked")
    public static String needError(Object v) {
        if (!(v instanceof Map)) return "bad_shape";
        Map<String, Object> x = (Map<String, Object>) v;
        for (String k : x.keySet()) if (!NEED_MEMBERS.contains(k)) return "unknown_member";
        Double ver = dbl(x.get("v"));
        if (ver == null || ver != 1.0) return "bad_version";
        Object kind = x.get("kind");
        if (!"scope".equals(kind) && !"grant".equals(kind) && !"discharge".equals(kind) && !"escalate".equals(kind)) return "bad_kind";
        if (!str(x.get("verb"), 128) || !str(x.get("resource"), 512)) return "bad_field";
        if (x.containsKey("scopes")) {
            Object sc = x.get("scopes");
            if (!(sc instanceof List) || ((List<Object>) sc).size() > 16) return "bad_field";
            for (Object s : (List<Object>) sc) if (!str(s, 128) || ((String) s).codePoints().anyMatch(Character::isWhitespace)) return "bad_field";
        }
        for (String k : new String[] {"grant_ref", "policy_digest"}) if (x.containsKey(k) && !str(x.get(k), 128)) return "bad_field";
        if (x.containsKey("tier")) {
            Double t = dbl(x.get("tier"));
            if (t == null || (t != 2.0 && t != 3.0) || !"escalate".equals(kind)) return "bad_field";
        }
        if (x.containsKey("limits")) {
            Object l = x.get("limits");
            if (!(l instanceof Map) || ((Map<String, Object>) l).size() > 16) return "bad_field";
            for (Map.Entry<String, Object> e : ((Map<String, Object>) l).entrySet()) {
                Double n = dbl(e.getValue());
                if (!str(e.getKey(), 64) || n == null || n < 0) return "bad_field";
            }
        }
        if (x.containsKey("discharges")) {
            Object d = x.get("discharges");
            if (!(d instanceof List) || ((List<Object>) d).size() > 16) return "bad_field";
            for (Object e : (List<Object>) d) {
                if (!(e instanceof Map)) return "bad_field";
                Map<String, Object> m = (Map<String, Object>) e;
                for (String k : m.keySet()) if (!k.equals("issuer") && !k.equals("claim")) return "bad_field";
                if (!str(m.get("issuer"), 512) || !str(m.get("claim"), 256)) return "bad_field";
            }
        }
        if ("escalate".equals(kind) && !x.containsKey("tier")) return "bad_field";
        return null;
    }

    /** The decoded need (a Map) or null; {@code code} of the result carries the refusal. */
    public static final class Decoded {
        public final Map<String, Object> need;
        public final String code;
        Decoded(Map<String, Object> need, String code) { this.need = need; this.code = code; }
    }

    @SuppressWarnings("unchecked")
    public static Decoded decodeNeed(Object value) {
        if (!(value instanceof String) || ((String) value).isEmpty()) return new Decoded(null, "bad_base64");
        String s = (String) value;
        if (s.length() > 2048) return new Decoded(null, "too_long");
        byte[] raw = Pca.decodeB64uStrict(s, -1);
        if (raw == null) return new Decoded(null, "bad_base64");
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString();
        } catch (CharacterCodingException e) { return new Decoded(null, "bad_utf8"); }
        Object parsed;
        try { parsed = Json.parse(text); } catch (RuntimeException e) { return new Decoded(null, "bad_json"); }
        String code = needError(parsed);
        return code == null ? new Decoded((Map<String, Object>) parsed, null) : new Decoded(null, code);
    }

    public static String needDigest(Map<String, Object> need) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", "atlas-pca/need/v1");
        m.put("need", need);
        return Pca.hashCanonical(m);
    }

    /** Null when ok, else {@code {failedHop, reason}}. */
    public static Object[] checkChainExtension(List<List<String>> chains) {
        for (int i = 0; i < chains.size(); i++) {
            List<String> ids = chains.get(i);
            if (ids.isEmpty()) return new Object[] {i, "no_chain"};
            if (i > 0) {
                List<String> prev = chains.get(i - 1);
                if (ids.size() < prev.size() || !ids.subList(0, prev.size()).equals(prev)) return new Object[] {i, "chain_does_not_extend_previous_hop"};
            }
        }
        return null;
    }

    /** null when the full verifier may now be asked, else the refusal code. {@code proofVerb} null means no proof. */
    public static String resumeGate(String state, Object needEncoded, Object answerDigest, String proofVerb, String proofResource) {
        if (!"TASK_STATE_AUTH_REQUIRED".equals(state) && !"auth-required".equals(state)) return "task_not_auth_required";
        Map<String, Object> need = needEncoded == null ? null : decodeNeed(needEncoded).need;
        if (need == null) return "no_valid_need";
        if (!needDigest(need).equals(answerDigest)) return "answer_not_bound_to_need";
        if (proofVerb == null || proofResource == null) return "no_proof";
        if (!proofVerb.equals(need.get("verb")) || !proofResource.equals(need.get("resource"))) return "action_mismatch";
        return null;
    }

    /** null where the reference throws (a salt shorter than 16 characters). */
    public static String pushToken(String taskId, List<String> chainIds, Object salt) {
        if (!(salt instanceof String) || ((String) salt).length() < 16) return null;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", "atlas-pca/a2a-push/v1");
        m.put("task_id", taskId);
        m.put("chain", PcaGrant.chainDigest(chainIds));
        m.put("salt", salt);
        return Pca.hashCanonical(m);
    }

    /** null when ok, else the reason. */
    @SuppressWarnings("unchecked")
    public static String checkPush(String taskId, List<String> chainIds, String salt, Object token, Object payload) {
        if (!(token instanceof String) || ((String) token).isEmpty()) return "no_token";
        String want = pushToken(taskId, chainIds, salt);
        if (want == null || !want.equals(token)) return "token_mismatch";
        if (payload instanceof Map) {
            String[][] keys = {{"task", "id"}, {"statusUpdate", "taskId"}, {"artifactUpdate", "taskId"}};
            for (String[] kf : keys) {
                Object c = ((Map<String, Object>) payload).get(kf[0]);
                Object v = c instanceof Map ? ((Map<String, Object>) c).get(kf[1]) : null;
                if (v != null) return taskId.equals(v) ? null : "task_mismatch";
            }
        }
        return "task_mismatch";
    }

    public static String receiptDigest(Object r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", "atlas-pca/a2a-receipt-ref/v1");
        m.put("r", r);
        return Pca.hashCanonical(m);
    }

    @SuppressWarnings("unchecked")
    public static boolean verifyReceipt(Object v, String signer) {
        if (!(v instanceof Map)) return false;
        Map<String, Object> r = (Map<String, Object>) v;
        Double ver = dbl(r.get("v"));
        if (ver == null || ver != 1.0 || !signer.equals(r.get("signer"))) return false;
        if (!str(r.get("task_id"), 4096) || !(r.get("state") instanceof String) || !STATES.contains(r.get("state"))) return false;
        if (!nat(r.get("seq")) || !nat(r.get("issued_at"))) return false;
        if (Pca.decodeB64uStrict(r.get("chain"), 32) == null) return false;
        Object prev = r.get("prev");
        if (prev != null && Pca.decodeB64uStrict(prev, 32) == null) return false;
        if ((Json.asLong(r.get("seq")) == 0) != (prev == null)) return false;
        Map<String, Object> body = new LinkedHashMap<>();
        for (String k : new String[] {"v", "task_id", "state", "seq", "prev", "chain", "issued_at", "signer"}) body.put(k, r.get(k));
        return K3.verifyBody(RECEIPT_DOMAIN, body, signer, r.get("sig"));
    }

    /** {@code code} null means ok. */
    public static final class ReceiptChain {
        public final String code, lastState;
        public final int at;
        public final boolean terminal;
        ReceiptChain(String code, int at, boolean terminal, String lastState) { this.code = code; this.at = at; this.terminal = terminal; this.lastState = lastState; }
    }

    @SuppressWarnings("unchecked")
    public static ReceiptChain checkReceiptChain(List<Object> receipts, String signer, String taskId, List<String> chainIds) {
        if (receipts.isEmpty()) return new ReceiptChain("empty", -1, false, null);
        String chain = PcaGrant.chainDigest(chainIds);
        Map<String, Object> prev = null;
        for (int i = 0; i < receipts.size(); i++) {
            if (!verifyReceipt(receipts.get(i), signer)) return new ReceiptChain("bad_receipt", i, false, null);
            Map<String, Object> r = (Map<String, Object>) receipts.get(i);
            if (!taskId.equals(r.get("task_id"))) return new ReceiptChain("wrong_task", i, false, null);
            if (!chain.equals(r.get("chain"))) return new ReceiptChain("wrong_chain", i, false, null);
            long seq = Json.asLong(r.get("seq"));
            if (prev == null) {
                if (seq != 0) return new ReceiptChain("bad_start", i, false, null);
            } else {
                if (TERMINAL.contains(prev.get("state"))) return new ReceiptChain("after_terminal", i, false, null);
                if (seq != Json.asLong(prev.get("seq")) + 1 || !receiptDigest(prev).equals(r.get("prev"))) return new ReceiptChain("broken_link", i, false, null);
            }
            prev = r;
        }
        String last = (String) prev.get("state");
        return new ReceiptChain(null, -1, TERMINAL.contains(last), last);
    }

    public static boolean mayTriggerNext(List<Object> receipts, String signer, String taskId, List<String> chainIds) {
        ReceiptChain r = checkReceiptChain(receipts, signer, taskId, chainIds);
        return r.code == null && "TASK_STATE_COMPLETED".equals(r.lastState);
    }
}
