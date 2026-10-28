package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Escalation on the wire (port of the TypeScript {@code escalation.ts}). A decision of {@code escalate} is admitted only by
 * a principal-signed answer bound to (policy digest, action digest, history head), spent by the replay counter, never
 * upgrading a deny. The answer is signed like every Intent Layer artifact: under the VERIFIER-pinned key of the principal,
 * in every suite this SDK verifies (Ed25519; the post-quantum and hybrid suites only under a pinned {@code pq_pk}).
 */
public final class Escalation {
    private Escalation() {}

    /** The signature domain of an escalation answer. */
    public static final String ANSWER_DOMAIN = "atlas-pca/escalation-answer/v1\0";
    public static final String POLICY_DOMAIN = "atlas-pca/escalation-policy/v1";
    public static final String ACTION_DOMAIN = "atlas-pca/escalation-action/v1";
    public static final String HISTORY_DOMAIN = "atlas-pca/escalation-history/v1";
    /** An answer lives at most 24 hours. */
    public static final long MAX_LIFETIME_MS = 86_400_000L;
    private static final long MAX_SAFE = 9007199254740991L;

    private static final List<String> REQUIRED = List.of("v", "kind", "principal", "policy_digest", "action_digest", "history_head",
        "decision", "iat", "expires_at", "nonce", "sig");
    private static final List<String> OPTIONAL = List.of("alg", "pq_pk", "pq_sig", "render_digest");

    private static String hashOf(String domain, String slot, Object value) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", domain);
        m.put(slot, value);
        return Pca.hashCanonical(m);
    }

    /** The digest of the policy in force: the stored grant. */
    public static String policyDigest(Map<String, Object> grant) { return hashOf(POLICY_DOMAIN, "grant", grant); }

    /** The digest of the exact PCActn (counter and signature included): one answer, one action. */
    public static String actionDigest(Map<String, Object> pcactn) { return hashOf(ACTION_DOMAIN, "pcactn", pcactn); }

    /** The head of the holder's history: its highest admitted counter ({@code null}: none yet). */
    public static String historyHead(Long lastCounter) {
        return hashOf(HISTORY_DOMAIN, "last_counter", lastCounter == null ? null : IntentJs.ofLong(lastCounter));
    }

    /** The request a refused escalate carries for the principal (valid one hour from {@code now}). */
    public static Map<String, Object> buildRequest(String aud, Map<String, Object> grant, Map<String, Object> pcactn, Long lastCounter,
                                                   List<String> reasons, long now) {
        return buildRequest(aud, grant, pcactn, lastCounter, reasons, now, null);
    }

    /** {@link #buildRequest(String, Map, Map, Long, List, long)} carrying the verifier's recomputed render digest (K7; {@code null}: none). */
    public static Map<String, Object> buildRequest(String aud, Map<String, Object> grant, Map<String, Object> pcactn, Long lastCounter,
                                                   List<String> reasons, long now, String renderDigest) {
        Object act = pcactn.get("action");
        Map<?, ?> action = act instanceof Map ? (Map<?, ?>) act : Map.of();
        List<Object> rs = new ArrayList<>();
        for (String r : reasons) {
            if (rs.size() >= 16) break;
            rs.add(r.length() > 512 ? r.substring(0, 512) : r);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("v", IntentJs.ofLong(1));
        out.put("kind", "pca-escalation-request");
        out.put("aud", aud == null ? "" : aud);
        out.put("policy_digest", policyDigest(grant));
        out.put("action_digest", actionDigest(pcactn));
        out.put("history_head", historyHead(lastCounter));
        out.put("verb", IntentRevocation.jsText(action.get("verb"), action.containsKey("verb")));
        out.put("resource", IntentRevocation.jsText(action.get("resource"), action.containsKey("resource")));
        out.put("reasons", rs);
        out.put("expires_at", IntentJs.ofLong(now + 3_600_000L));
        if (renderDigest != null) out.put("render_digest", renderDigest);
        return out;
    }

    /**
     * {@code JSON.stringify(request.reasons)}: quote, backslash and controls escaped, a lone surrogate written as
     * {@code \\udXXX}, everything else (non-ASCII included) raw. A cut in {@link #buildRequest} keeps a lone high surrogate.
     */
    public static String reasonsWire(Map<String, Object> request) {
        StringBuilder b = new StringBuilder("[");
        boolean first = true;
        for (Object o : (List<?>) request.get("reasons")) {
            if (!first) b.append(',');
            first = false;
            String s = (String) o;
            b.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { b.append(c).append(s.charAt(++i)); continue; }
                switch (c) {
                    case '"': b.append("\\\""); break;
                    case '\\': b.append("\\\\"); break;
                    case '\b': b.append("\\b"); break;
                    case '\f': b.append("\\f"); break;
                    case '\n': b.append("\\n"); break;
                    case '\r': b.append("\\r"); break;
                    case '\t': b.append("\\t"); break;
                    default:
                        if (c < 0x20 || Character.isSurrogate(c)) b.append(String.format("\\u%04x", (int) c)); else b.append(c);
                }
            }
            b.append('"');
        }
        return b.append(']').toString();
    }

    /** Null = well-formed (closed members, canonical digests, safe-integer times, sane lifetime, suite capability). */
    public static String answerShapeError(Object answer) {
        if (!(answer instanceof Map)) return "not an object";
        @SuppressWarnings("unchecked") Map<String, Object> a = (Map<String, Object>) answer;
        String e = IntentArtifacts.closedMembers(a, REQUIRED, OPTIONAL, "answer");
        if (e != null) return e;
        if (!(IntentJs.isInt(a.get("v")) && IntentJs.num(a.get("v")) == 1.0) || !"pca-escalation-answer".equals(a.get("kind")))
            return "not a pca-escalation-answer v1";
        if (!IntentArtifacts.isBoundedString(a.get("principal"), 64) || Pca.decodeB64uStrict(a.get("principal"), 32) == null)
            return "principal must be canonical base64url (32 bytes)";
        for (String k : new String[] {"policy_digest", "action_digest", "history_head"})
            if (!IntentArtifacts.isDigest(a.get(k))) return k + " must be canonical base64url (32 bytes)";
        if (!"allow".equals(a.get("decision")) && !"deny".equals(a.get("decision"))) return "decision must be 'allow' or 'deny'";
        if (!IntentJs.isNonNeg(a.get("iat")) || !IntentJs.isNonNeg(a.get("expires_at")))
            return "iat and expires_at must be non-negative safe integers";
        long iat = IntentJs.lng(a.get("iat")), exp = IntentJs.lng(a.get("expires_at"));
        if (!(exp > iat)) return "expires_at must be greater than iat";
        if (exp - iat > MAX_LIFETIME_MS) return "an answer lives at most " + MAX_LIFETIME_MS + " ms";
        byte[] nb = a.get("nonce") instanceof String ? Pca.decodeB64uStrict(a.get("nonce"), -1) : null;
        if (nb == null || nb.length < 16) return "nonce must be canonical base64url of at least 16 bytes";
        if (!(a.get("sig") instanceof String)) return "sig must be a string";
        if (a.containsKey("render_digest") && !IntentArtifacts.isDigest(a.get("render_digest"))) return "render_digest must be canonical base64url (32 bytes)";
        return IntentArtifacts.artifactSuiteError(a);
    }

    /** What an answer must be bound to. */
    public static final class Binding {
        public final String policyDigest;
        public final String actionDigest;
        public final String historyHead;
        /** K7: the H(R) the verifier recomputed; {@code null}: none, and an answer that carries a {@code render_digest} is refused. */
        public final String renderDigest;

        public Binding(String policyDigest, String actionDigest, String historyHead) { this(policyDigest, actionDigest, historyHead, null); }

        public Binding(String policyDigest, String actionDigest, String historyHead, String renderDigest) {
            this.policyDigest = policyDigest;
            this.actionDigest = actionDigest;
            this.historyHead = historyHead;
            this.renderDigest = renderDigest;
        }
    }

    /** The result of {@link #verify}: {@code ok} with the answering principal and its decision, or the refusal reason. */
    public static final class Result {
        public final boolean ok;
        public final String principal;
        public final String decision;
        public final String reason;

        private Result(boolean ok, String principal, String decision, String reason) {
            this.ok = ok;
            this.principal = principal;
            this.decision = decision;
            this.reason = reason;
        }

        static Result no(String reason) { return new Result(false, null, null, reason); }

        @Override public String toString() { return ok ? "Result{ok, " + principal + ", " + decision + "}" : "Result{" + reason + "}"; }
    }

    /**
     * Verify an answer against the verifier's pinned principals and the binding of THIS decision. {@code principals} entries
     * are a base64url Ed25519 key, or a pin object {@code {pk, pq_pk?}}. Total. A valid {@code deny} answer is
     * {@code ok} with decision {@code "deny"}: the caller must not admit it.
     */
    public static Result verify(Object answer, List<?> principals, Binding bind, long now) {
        try {
            if (now > MAX_SAFE || now < -MAX_SAFE) return Result.no("the verifier clock is not a safe integer (fail closed)");
            String e = answerShapeError(answer);
            if (e != null) return Result.no("malformed escalation answer: " + e);
            @SuppressWarnings("unchecked") Map<String, Object> a = new LinkedHashMap<>((Map<String, Object>) answer);
            // v / iat / expires_at spelled 1.0 or 1e3 are the integers they are (the signed canonical form has no floats)
            for (String k : new String[] {"v", "iat", "expires_at"}) a.put(k, IntentJs.ofLong(IntentJs.lng(a.get(k))));
            if (principals == null || principals.isEmpty()) return Result.no("no principal is pinned for escalation answers");
            String principal = (String) a.get("principal");
            Object pinPk = null, pinPq = null;
            boolean pinned = false;
            for (Object p : principals) {
                if (p instanceof String) {
                    if (p.equals(principal)) { pinned = true; pinPk = p; break; }
                } else if (p instanceof Map && principal.equals(((Map<?, ?>) p).get("pk"))) {
                    pinned = true;
                    pinPk = ((Map<?, ?>) p).get("pk");
                    pinPq = ((Map<?, ?>) p).get("pq_pk");
                    break;
                }
            }
            if (!pinned) return Result.no("the answering principal is not pinned by this verifier");
            if (!IntentArtifacts.verifyArtifactSig(ANSWER_DOMAIN, a, pinPk, pinPq)) return Result.no("escalation answer signature invalid");
            if (!bind.policyDigest.equals(a.get("policy_digest"))) return Result.no("the answer is bound to another policy");
            if (!bind.actionDigest.equals(a.get("action_digest"))) return Result.no("the answer is bound to another action");
            if (!bind.historyHead.equals(a.get("history_head"))) return Result.no("the answer is bound to another state of the history");
            if (bind.renderDigest != null) {
                if (!a.containsKey("render_digest")) return Result.no("the answer is not bound to the canonical approval render");
                if (!bind.renderDigest.equals(a.get("render_digest"))) return Result.no("the answer was given for another approval render");
            } else if (a.containsKey("render_digest")) return Result.no("the answer carries an approval render this verifier did not recompute");
            if (now < IntentJs.lng(a.get("iat"))) return Result.no("the answer is from the future");
            if (now > IntentJs.lng(a.get("expires_at"))) return Result.no("the answer has expired");
            return new Result(true, principal, (String) a.get("decision"), null);
        } catch (RuntimeException | StackOverflowError ex) {
            return Result.no("escalation answer error (fail closed): " + ex.getClass().getSimpleName());
        }
    }
}
