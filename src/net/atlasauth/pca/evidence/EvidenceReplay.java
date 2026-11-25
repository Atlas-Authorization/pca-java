package net.atlasauth.pca.evidence;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.EvidenceBridge;
import net.atlasauth.pca.IntentBridge;
import net.atlasauth.pca.IntentAcc;
import net.atlasauth.pca.IntentRevocation;
import net.atlasauth.pca.IntentSession;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.ActionSchema;
import net.atlasauth.pca.IntentClassifier;
import net.atlasauth.pca.IntentV2;
import net.atlasauth.pca.Ledger;
import net.atlasauth.pca.OracleFacts;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.PcaCore;
import net.atlasauth.pca.intent.IntentJit;
import net.atlasauth.pca.intent.IntentMapKit;
import net.atlasauth.pca.intent.IntentStatement;
import net.atlasauth.pca.revoke.JsVal;
import net.atlasauth.pca.wallet.Wallet;
import net.atlasauth.pca.webauthn.Webauthn;

/**
 * {@code verifyEvidenceBundle}: deterministic replay of a dispute evidence bundle. Every finding is recomputed from the signed
 * artifacts; the output is a findings report whose text comes from fixed templates, so two readers of the same bundle with the same
 * trust inputs get byte-identical reports ({@code report_digest}). Statuses: {@code pass}, {@code fail}, {@code unverified} (never
 * reported as a pass). A {@code trust.verifiers.<name>} port overrides the core default for the artifacts that have one.
 */
public final class EvidenceReplay {
    private EvidenceReplay() {}

    /** A verifier for one artifact: {@code {ok: true}} or {@code {ok: false, reason}}. For artifacts with a core verifier it overrides the default. */
    @FunctionalInterface
    public interface Port {
        Map<String, Object> verify(Object artifact, Map<String, Object> bundle) throws Exception;
    }

    private interface Core { Map<String, Object> get() throws Exception; }

    private static final Map<String, String> TEMPLATES = new LinkedHashMap<>();
    static {
        String[][] t = {
            {"shape", "The bundle is well formed (pca-intent-evidence v1, closed members)"},
            {"principal.pinned", "Every session-root key that signs in this bundle is a principal key pinned by the reader (attribution)"},
            {"trust.principals", "The pinned principal keys (trust.principals) are well formed"},
            {"statement.commit", "The session root commits to the intent statement the bundle names"},
            {"statement.opening", "The opened statement is signed by a principal and hashes to the committed ref"},
            {"session_root.signature", "The session root is signed by one of its principal keys"},
            {"schema.signature", "The action schema is signed by a site key"},
            {"schema.digest", "The session root binds this action schema"},
            {"schema.anchor", "The action schema is anchored in a transparency log"},
            {"map.replay", "The task map replays to its committed digest"},
            {"root_grant", "The root intent grant G_0 is principal-signed and bound to the session"},
            {"delta.signature", "The delta grant is a root capability signed by a principal of the session"},
            {"delta.chain", "The delta grant chains to the session (session, seq, prev, root)"},
            {"delta.backed", "Every delta grant is backed by a principal \"yes\" answer"},
            {"answer.signature", "The answer is signed by a principal of the session, for this session"},
            {"answer.map", "The answer refers to a map version in the bundle"},
            {"answer.tier", "The answer meets the site minimum friction tier for the verb"},
            {"answer.typed", "The typed-tier value re-derives the signed typed digest"},
            {"answer.device", "The device-tier WebAuthn assertion verifies with user verification"},
            {"canaries.summary", "The canary summary equals the one recomputed from the signed canary answers"},
            {"pcactn.verify", "The PCActn verifies (signature, chain, audience, validity at its issue time)"},
            {"pcactn.root", "The PCActn's root capability is G_0 or a bundled delta grant"},
            {"pcactn.session", "The PCActn's signed intent_session member matches the session, its root grant and the accumulator events"},
            {"subject.present", "The subject PCActn is in the bundle"},
            {"jit.consent", "The irreversible subject action carries a principal JIT consent bound to its exact action digest"},
            {"accumulator.declared", "The accumulator is declared in the session root"},
            {"accumulator.arithmetic", "The accumulator posts are the running values of the counted events"},
            {"accumulator.cap", "Every accumulator post is within the admitting grant's cap"},
            {"accumulator.receipts", "The sequencer reservation receipt verifies and is consistent"},
            {"acc.keysets.equivocation", "No two different sequencer key sets share one root and version"},
            {"acc.keysets", "The sequencer key set is signed by the session's pinned sequencer root and its version never rolls back"},
            {"trust.acc", "The verifier freshness configuration (trust.acc) is well formed"},
            {"effect.binding", "The effect record is bound to the PCActn's signed params"},
            {"effect.charged", "The charged amount is within the confirmed value"},
            {"effect.frame", "No monitored state outside the write set changed"},
            {"effect.signature", "The effect record is signed by the site"},
            {"verdict.signature", "The site verdict record verifies"},
            {"fact.signature", "The oracle fact verifies under a pinned oracle key"},
            {"classifier.signature", "The classifier verdict verifies under a pinned judge key"},
            {"offer_set.signature", "The offer set is signed by a site key, for this session"},
            {"labels.signature", "The label receipt is signed by a pinned site key, for this session"},
            {"settlement.signature", "The settlement record verifies"},
            {"revocation.history", "The bundled revocation epoch extends its predecessor (one append-only chain by the session revocation authority)"},
            {"revocation.epoch", "A fresh revocation epoch shows the session, its maps and its deltas unrevoked at the action time"},
            {"anchor.inclusion", "The anchored artifact is included under a guardian-signed head of the intent log"},
        };
        for (String[] e : t) TEMPLATES.put(e[0], e[1]);
    }

    private static final Map<String, String> STATUS_TEXT = new LinkedHashMap<>();
    static {
        STATUS_TEXT.put("pass", "verified");
        STATUS_TEXT.put("fail", "REFUTED");
        STATUS_TEXT.put("unverified", "not verified here");
    }

    private static final String[] NOT_PROVEN = {
        "That the principal understood the question: the bundle proves only that a deterministic card with the recorded digest was shown and answered at the recorded friction tier.",
        "That the site's signed schema describes what its endpoints really do (SCH).",
        "That the site's effect records and any oracle facts are true (EFF, ORC).",
        "Acceptance of this bundle by any card network, court or regulator.",
    };

    // ---- small JSON helpers -------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }
    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return o instanceof List ? (List<Object>) o : new ArrayList<>(); }
    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }
    private static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }
    private static String s(Object o) { return o instanceof String ? (String) o : null; }
    private static Double num(Object o) { return IntentBridge.num(o); }
    private static boolean isNum(Object o) { Double d = num(o); return d != null && !d.isNaN() && !d.isInfinite(); }
    private static boolean numEq(Object a, Object b) { Double x = num(a), y = num(b); return x != null && y != null && x.doubleValue() == y.doubleValue(); }
    private static long lng(Object o) { return (long) (double) num(o); }
    private static boolean str(Object o, String v) { return java.util.Objects.equals(o, v); }
    private static Json.Num n(long v) { return new Json.Num(Long.toString(v)); }
    private static String js(double d) { return JsVal.numOf(d == 0.0 ? 0.0 : d).raw; }
    private static int cmp(String a, String b) { return Integer.signum(a.compareTo(b)); }
    private static String id(Object o) { return JsVal.str(o); }

    private static Map<String, Object> vd(boolean ok, String reason) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("ok", ok);
        if (!ok) v.put("reason", reason);
        return v;
    }
    private static Map<String, Object> nul(String e) { return vd(e == null, e); }
    private static boolean ok(Map<String, Object> v) { return Boolean.TRUE.equals(v.get("ok")); }

    // ---- findings -----------------------------------------------------------------------------------------------------

    private static final class Findings {
        final List<Map<String, Object>> list = new ArrayList<>();

        void add(String code, String status, List<String> refs, String detail) {
            String text = TEMPLATES.get(code) + ": " + STATUS_TEXT.get(status) + (detail != null && !detail.isEmpty() ? " (" + detail + ")" : "") + ".";
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("code", code);
            f.put("status", status);
            f.put("text", text);
            f.put("refs", new ArrayList<Object>(refs));
            list.add(f);
        }
        void add(String code, String status) { add(code, status, List.of(), null); }
        void add(String code, String status, List<String> refs) { add(code, status, refs, null); }
        void add(String code, boolean pass, List<String> refs) { add(code, pass ? "pass" : "fail", refs, null); }

        void verdict(String code, Map<String, Object> v, List<String> refs) {
            if (ok(v)) add(code, "pass", refs, null);
            else add(code, "fail", refs, (String) v.get("reason"));
        }

        /** Run {@code port} if supplied, else the core default; with neither (or a null core verdict) the artifact stays unverified. */
        void check(String code, Port port, Core core, Object artifact, Map<String, Object> bundle, List<String> refs, String what) {
            Map<String, Object> v;
            try {
                v = port != null ? port.verify(artifact, bundle) : core != null ? core.get() : null;
            } catch (Exception e) {
                v = vd(false, "verifier threw: " + e.getMessage());
            }
            if (v == null) add(code, "unverified", refs, "no verifier for " + what);
            else verdict(code, v, refs);
        }
    }

    private static List<Object> one(Object x) { List<Object> c = new ArrayList<>(); c.add(x); return c; }

    private static List<String> refs(String... r) { return new ArrayList<>(Arrays.asList(r)); }

    private static boolean pass(Findings f, String code) {
        boolean any = false;
        for (Map<String, Object> x : f.list) {
            if (!code.equals(x.get("code"))) continue;
            if ("fail".equals(x.get("status"))) return false;
            if ("pass".equals(x.get("status"))) any = true;
        }
        return any;
    }

    // ---- entry ----------------------------------------------------------------------------------------------------------

    static Map<String, Object> emptySummary() {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("admitted_under", null);
        s.put("principal_keys", new ArrayList<Object>());
        Map<String, Object> a = new LinkedHashMap<>();
        for (String k : new String[] {"total", "yes", "no", "partial", "canaries"}) a.put(k, n(0));
        s.put("answers", a);
        s.put("refusals", new ArrayList<Object>());
        s.put("consent", null);
        s.put("charged", null);
        Map<String, Object> ca = new LinkedHashMap<>();
        ca.put("correct", n(0));
        ca.put("asked", n(0));
        s.put("canary_accuracy", ca);
        Map<String, Object> at = new LinkedHashMap<>();
        at.put("pinned", false);
        at.put("keys_to_check", new ArrayList<Object>());
        s.put("attribution", at);
        s.put("proven", new ArrayList<Object>());
        s.put("not_proven", new ArrayList<Object>(Arrays.asList((Object[]) NOT_PROVEN)));
        return s;
    }

    private static Map<String, Object> finish(Findings f, String digest, Map<String, Object> summary) {
        List<Map<String, Object>> findings = new ArrayList<>(f.list);
        findings.sort((a, b) -> {
            int c = cmp((String) a.get("code"), (String) b.get("code"));
            if (c != 0) return c;
            c = cmp(JsVal.join(l(a.get("refs")), ","), JsVal.join(l(b.get("refs")), ","));
            if (c != 0) return c;
            c = cmp((String) a.get("status"), (String) b.get("status"));
            return c != 0 ? c : cmp((String) a.get("text"), (String) b.get("text"));
        });
        boolean anyFail = false, anyUnverified = false, pinPass = false, pinOther = false;
        for (Map<String, Object> x : findings) {
            String st = (String) x.get("status");
            if ("fail".equals(st)) anyFail = true;
            if ("unverified".equals(st)) anyUnverified = true;
            if ("principal.pinned".equals(x.get("code"))) { if ("pass".equals(st)) pinPass = true; else pinOther = true; }
        }
        boolean consistent = !findings.isEmpty() && !anyFail;
        boolean attributed = pinPass && !pinOther;
        boolean ok = consistent && attributed;
        boolean complete = !anyUnverified;
        List<Object> notProven = l(summary.get("not_proven"));
        List<Object> toCheck = l(get(summary.get("attribution"), "keys_to_check"));
        if (consistent && !attributed && !toCheck.isEmpty()) {
            notProven.add(0, "The bundle is internally consistent but NOT attributed to any known principal: verify these session-root keys out of band: " + JsVal.join(toCheck, ", ") + ".");
        }
        java.util.TreeSet<String> codes = new java.util.TreeSet<>();
        for (Map<String, Object> x : findings) if ("unverified".equals(x.get("status"))) codes.add((String) x.get("code"));
        if (!codes.isEmpty()) notProven.add("Checked only through a supplied verifier, or not at all: " + String.join(", ", codes) + ".");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("ok", ok);
        body.put("consistent", consistent);
        body.put("attributed", attributed);
        body.put("complete", complete);
        body.put("digest", digest);
        body.put("findings", new ArrayList<Object>(findings));
        body.put("summary", summary);
        Map<String, Object> w = new LinkedHashMap<>();
        w.put("d", EvidenceVerify.EVIDENCE_REPORT_DOMAIN);
        w.put("r", body);
        Map<String, Object> out = new LinkedHashMap<>(body);
        out.put("report_digest", Pca.hashCanonical(w));
        return out;
    }

    public static Map<String, Object> verify(Object input, Map<String, Object> trustIn, Map<String, Port> ports) {
        Map<String, Object> trust = trustIn == null ? new LinkedHashMap<>() : trustIn;
        Findings f = new Findings();
        Map<String, Object> summary = emptySummary();
        if (trust.containsKey("acc")) {
            String te = EvidenceVerify.accTrustError(trust.get("acc"));
            if (te != null) { f.add("trust.acc", "fail", List.of(), te); return finish(f, null, summary); }
        }
        if (trust.containsKey("principals")) {
            String pe = EvidenceVerify.principalsTrustError(trust.get("principals"));
            if (pe != null) { f.add("trust.principals", "fail", List.of(), pe); return finish(f, null, summary); }
        }
        String bad = EvidenceBundle.bundleShapeError(input);
        if (bad != null) { f.add("shape", "fail", List.of(), bad); return finish(f, null, summary); }
        Map<String, Object> b;
        String digest;
        try {
            b = EvidenceBundle.normalizeBundle(input);
            digest = EvidenceBundle.evidenceDigest(b);
        } catch (RuntimeException e) {
            f.add("shape", "fail", List.of(), "not canonicalizable: " + e.getMessage());
            return finish(f, null, summary);
        }
        f.add("shape", "pass");
        try {
            replay(b, digest, trust, ports == null ? Collections.<String, Port>emptyMap() : ports, f, summary);
        } catch (RuntimeException e) {
            f.add("shape", "fail", List.of(), "replay aborted: " + e.getMessage());
        }
        return finish(f, digest, summary);
    }

    // ---- the replay -------------------------------------------------------------------------------------------------------

    private static final class Grant {
        final Map<String, Object> cap;
        final int seq;
        Grant(Map<String, Object> cap, int seq) { this.cap = cap; this.seq = seq; }
    }

    private static final class KeySetsAt {
        List<Object> sets;
        Double minV;
        Map<String, Object> tracked;
    }

    @SuppressWarnings("unchecked")
    private static void replay(Map<String, Object> b, String digest, Map<String, Object> trust, Map<String, Port> ports, Findings f, Map<String, Object> summary) {
        Map<String, Object> S = m(b.get("session_root"));
        Map<String, Object> subjectM = m(b.get("subject"));
        String session = (String) subjectM.get("session");
        String subjectAud = (String) subjectM.get("aud");
        List<String> principals = new ArrayList<>();
        for (Object p : l(S.get("principals"))) principals.add((String) get(p, "key"));
        Collections.sort(principals);
        summary.put("principal_keys", new ArrayList<Object>(principals));
        String sRef = trust.get("sessionRootDigest") instanceof String ? (String) trust.get("sessionRootDigest") : IntentSession.rootDigest(S);
        Map<String, Object> pqPins = new LinkedHashMap<>();
        if (trust.get("principals") instanceof List) for (Object p : (List<?>) trust.get("principals")) if (get(p, "pq_pk") instanceof String) pqPins.put((String) get(p, "key"), get(p, "pq_pk"));
        List<Object> siteKeys = trust.get("siteKeys") instanceof List ? (List<Object>) trust.get("siteKeys") : null;
        Map<String, Object> schemaM = m(b.get("schema"));
        Map<String, Object> schemaDoc = m(schemaM.get("doc"));

        // -- session root
        if (!str(S.get("session"), session)) f.add("session_root.signature", "fail", refs("session_root"), "session root is for another session");
        else f.check("session_root.signature", ports.get("sessionRoot"), () -> nul(IntentSession.verifyRoot(S, pqPins)), S, b, refs("session_root"), "the session root");

        // -- statement
        Map<String, Object> stmt = m(b.get("statement"));
        f.add("statement.commit", str(S.get("intent_ref"), (String) stmt.get("commit")), refs("statement"));
        Object opening = stmt.get("opening");
        boolean hasOpening = stmt.containsKey("opening");
        if (!hasOpening) f.add("statement.opening", "unverified", refs("statement"), "the statement was not opened (it stays a commitment)");
        else {
            Map<String, Object> v = IntentStatement.verifyIntent(opening);
            if (!ok(v)) f.add("statement.opening", "fail", refs("statement"), (String) v.get("reason"));
            else if (!IntentStatement.intentRef(opening).equals(stmt.get("commit"))) f.add("statement.opening", "fail", refs("statement"), "the opening does not hash to the commitment");
            else if (!principals.contains(get(opening, "principal"))) f.add("statement.opening", "fail", refs("statement"), "signed by a key that is not a principal of the session");
            else f.add("statement.opening", "pass", refs("statement"));
        }

        // -- schema
        f.check("schema.signature", ports.get("schema"), siteKeys != null ? () -> nul(ActionSchema.verify(schemaDoc, siteKeys)) : null, schemaDoc, b, refs("schema"), "the action schema (no site keys supplied)");
        String schemaDigest = ActionSchema.digest(schemaDoc);
        f.add("schema.digest", str(get(S.get("schema"), "digest"), schemaDigest) && str(get(S.get("schema"), "aud"), subjectAud), refs("schema"));

        // -- maps
        Set<Object> mapCommits = new HashSet<>();
        for (Object mo : l(b.get("maps"))) mapCommits.add(get(mo, "commit"));
        for (Object mo : l(b.get("maps"))) {
            List<String> ref = refs("map:" + id(get(mo, "seq")));
            if (!JsVal.truthy(get(mo, "map"))) { f.add("map.replay", "unverified", ref, "committed map not revealed"); continue; }
            Map<String, Object> r = IntentMapKit.verifyIntentMap(get(mo, "map"));
            if (!Boolean.TRUE.equals(r.get("ok"))) {
                List<Object> pr = l(r.get("problems"));
                f.add("map.replay", "fail", ref, JsVal.join(pr.subList(0, Math.min(3, pr.size())), "; "));
            } else if (!IntentMapKit.intentMapDigest(get(mo, "map")).equals(get(mo, "commit"))) f.add("map.replay", "fail", ref, "the revealed map does not hash to its commit");
            else f.add("map.replay", "pass", ref);
        }

        // -- grants: G_0 and the delta chain
        Map<String, Grant> grants = new LinkedHashMap<>();
        Map<String, Object> g0 = m(b.get("root_grant"));
        {
            Map<String, Object> cv = EvidenceBridge.grantSessionCaveat(g0);
            String chain = Pca.verifyChain(one(g0), (String) g0.get("issuer"), true, null, pqPins, null);
            if (!chain.isEmpty()) f.add("root_grant", "fail", refs("G_0"), chain);
            else if (!principals.contains(g0.get("issuer"))) f.add("root_grant", "fail", refs("G_0"), "not signed by a principal of the session");
            else if (cv == null || IntentSession.caveatError(cv) != null) f.add("root_grant", "fail", refs("G_0"), cv != null ? IntentSession.caveatError(cv) : "no intent_session caveat");
            else if (!str(cv.get("session"), session) || !numEq(cv.get("seq"), n(0)) || !str(cv.get("root"), sRef)) f.add("root_grant", "fail", refs("G_0"), "intent_session caveat does not bind seq 0 of this session root");
            else {
                f.add("root_grant", "pass", refs("G_0"));
                grants.put((String) g0.get("id"), new Grant(g0, 0));
            }
        }
        String prevId = (String) g0.get("id");
        List<Object> deltas = l(b.get("deltas"));
        for (int i = 0; i < deltas.size(); i++) {
            Map<String, Object> d = m(deltas.get(i));
            int want = i + 1;
            List<String> ref = refs("D_" + want);
            String chain = Pca.verifyChain(one(d), (String) d.get("issuer"), true, null, pqPins, null);
            if (!chain.isEmpty() || !principals.contains(d.get("issuer")) || d.containsKey("parent")) {
                f.add("delta.signature", "fail", ref, !chain.isEmpty() ? chain : "not a principal-signed root capability");
                continue;
            }
            f.add("delta.signature", "pass", ref);
            Map<String, Object> cv = EvidenceBridge.grantSessionCaveat(d);
            int nCv = 0;
            for (Object k : l(d.get("caveats"))) if (str(get(k, "type"), "intent_session")) nCv++;
            String why = null;
            if (cv == null || nCv != 1) why = "no single intent_session caveat";
            else if (IntentSession.caveatError(cv) != null) why = IntentSession.caveatError(cv);
            else if (!str(cv.get("session"), session)) why = "bound to another session";
            else if (!str(cv.get("root"), sRef)) why = "bound to another session root";
            else if (!numEq(cv.get("seq"), n(want))) why = "seq " + id(cv.get("seq")) + " where " + want + " was expected (gap, duplicate or reorder)";
            else if (!str(cv.get("prev"), prevId)) why = "prev does not name the previous grant";
            if (why != null) f.add("delta.chain", "fail", ref, why);
            else {
                f.add("delta.chain", "pass", ref);
                grants.put((String) d.get("id"), new Grant(d, want));
            }
            prevId = (String) d.get("id");
        }

        // -- answers
        List<Map<String, Object>> verified = new ArrayList<>();
        for (Object ao : l(b.get("answers"))) {
            Map<String, Object> a = m(ao);
            List<String> ref = refs("answer:" + id(a.get("question_id")));
            Map<String, Object> v = Wallet.verifyIntentAnswer(a, principals);
            if (!ok(v)) { f.add("answer.signature", "fail", ref, (String) v.get("reason")); continue; }
            if (!str(a.get("session"), session)) { f.add("answer.signature", "fail", ref, "answer for another session"); continue; }
            f.add("answer.signature", "pass", ref);
            verified.add(a);
            f.add("answer.map", mapCommits.contains(a.get("map_digest")), ref);
            Map<String, Object> ux = m(a.get("ux"));
            if (JsVal.truthy(ux.get("canary")) || !numEq(a.get("y"), n(1))) continue;
            Object min = get(trust.get("minTier"), (String) a.get("verb"));
            if (min != null) f.add("answer.tier", Wallet.frictionRank(ux.get("tier")) >= Wallet.frictionRank(min) ? "pass" : "fail", ref, id(ux.get("tier")) + " vs minimum " + id(min));
            if (str(ux.get("tier"), "typed")) {
                Object tv = get(trust.get("typedValues"), (String) a.get("question_id"));
                if (tv == null) f.add("answer.typed", "unverified", ref, "the typed value is not known to this verifier");
                else f.add("answer.typed", Wallet.typedDigest((String) a.get("question_id"), (String) tv).equals(ux.get("typed_digest")), ref);
            }
            if (str(ux.get("tier"), "device")) {
                Object wa = ux.get("webauthn");
                Object cred = wa instanceof Map ? get(trust.get("credentials"), (String) get(wa, "credential_id")) : null;
                if (!(wa instanceof Map) || cred == null) f.add("answer.device", "unverified", ref, "unknown authenticator");
                else {
                    Map<String, Object> assertion = new LinkedHashMap<>();
                    assertion.put("authenticatorData", Keys.unb64u((String) get(wa, "authenticator_data")));
                    assertion.put("clientDataJSON", Keys.unb64u((String) get(wa, "client_data_json")));
                    assertion.put("signature", Keys.unb64u((String) get(wa, "signature")));
                    assertion.put("publicKey", get(cred, "publicKey"));
                    Map<String, Object> expect = new LinkedHashMap<>();
                    expect.put("expectedChallenge", Wallet.deviceChallenge((String) a.get("question_id"), (String) ux.get("rendered_digest"), lng(a.get("y")),
                        ux.containsKey("action_digest") ? (String) ux.get("action_digest") : null));
                    expect.put("rpId", get(cred, "rpId"));
                    expect.put("origins", get(cred, "origins"));
                    expect.put("requireUV", true);
                    expect.put("storedSignCount", has(cred, "signCount") && get(cred, "signCount") != null ? get(cred, "signCount") : n(0));
                    Map<String, Object> r = Webauthn.verifyAssertion(assertion, expect);
                    f.add("answer.device", Boolean.TRUE.equals(r.get("ok")) ? "pass" : "fail", ref, Boolean.TRUE.equals(r.get("ok")) ? null : (String) r.get("reason"));
                }
            }
        }
        List<Map<String, Object>> real = new ArrayList<>(), canaries = new ArrayList<>();
        for (Map<String, Object> a : verified) (JsVal.truthy(get(a.get("ux"), "canary")) ? canaries : real).add(a);
        long yes = 0, no = 0, partial = 0, yesAny = 0;
        List<Object> refusals = new ArrayList<>();
        for (Map<String, Object> a : real) {
            if (numEq(a.get("y"), n(1)) && !a.containsKey("partial")) yes++;
            if (numEq(a.get("y"), n(0))) { no++; refusals.add(a.get("question_id")); }
            if (a.containsKey("partial")) partial++;
            if (numEq(a.get("y"), n(1))) yesAny++;
        }
        Map<String, Object> ans = m(summary.get("answers"));
        ans.put("total", n(real.size()));
        ans.put("yes", n(yes));
        ans.put("no", n(no));
        ans.put("partial", n(partial));
        ans.put("canaries", n(canaries.size()));
        refusals.sort((x, y) -> cmp((String) x, (String) y));
        summary.put("refusals", refusals);
        f.add("delta.backed", yesAny >= deltas.size() ? "pass" : "fail", List.of(), deltas.size() + " delta(s), " + yesAny + " principal yes answer(s)");

        // -- canaries
        {
            Map<String, Object> labels = new LinkedHashMap<>();
            for (Object c : l(b.get("canary_labels"))) labels.put((String) get(c, "question_id"), get(c, "label"));
            long falseYes = 0, falseNo = 0, missing = 0;
            for (Map<String, Object> a : canaries) {
                String qid = (String) a.get("question_id");
                Object label = get(trust.get("canaryLabels"), qid);
                if (label == null) label = labels.get(qid);
                if (label == null) missing++;
                else if (numEq(label, n(0)) && numEq(a.get("y"), n(1))) falseYes++;
                else if (numEq(label, n(1)) && numEq(a.get("y"), n(0))) falseNo++;
            }
            Map<String, Object> ca = m(summary.get("canary_accuracy"));
            ca.put("correct", n(canaries.size() - missing - falseYes - falseNo));
            ca.put("asked", n(canaries.size()));
            Map<String, Object> c = m(b.get("canaries"));
            if (missing > 0) f.add("canaries.summary", "fail", List.of(), missing + " canary answer(s) without a known label");
            else if (!numEq(c.get("asked"), n(canaries.size())) || !numEq(c.get("false_yes"), n(falseYes)) || !numEq(c.get("false_no"), n(falseNo))) {
                f.add("canaries.summary", "fail", List.of(), "claimed " + id(c.get("asked")) + "/" + id(c.get("false_yes")) + "/" + id(c.get("false_no")) + ", recomputed " + canaries.size() + "/" + falseYes + "/" + falseNo);
            } else f.add("canaries.summary", "pass", List.of(), canaries.size() + " asked, " + falseYes + " false yes, " + falseNo + " false no");
        }

        // -- sequencer key sets (rule 15)
        Map<String, Object> acc = m(b.get("accumulator"));
        Map<String, Map<String, Object>> rootHolders = new LinkedHashMap<>();
        for (Object ao : l(S.get("accumulators"))) {
            Object h = get(ao, "holder");
            if (str(get(h, "kind"), "sequenced")) rootHolders.put((String) get(h, "root"), m(h));
        }
        List<Map<String, Object>> acceptedKeySets = new ArrayList<>();
        List<Map<String, Object>> verifiedKeySets = new ArrayList<>();
        Set<String> equivocatedSlots = new HashSet<>();
        {
            List<Object> sets = new ArrayList<>(acc.get("sequencer_keys") instanceof List ? (List<?>) acc.get("sequencer_keys") : List.of());
            sets.sort((x, y) -> {
                int c = Double.compare(orZero(get(x, "issued_at")), orZero(get(y, "issued_at")));
                if (c != 0) return c;
                c = Double.compare(orZero(get(x, "version")), orZero(get(y, "version")));
                return c != 0 ? c : cmp(Pca.hashCanonical(x), Pca.hashCanonical(y));
            });
            Map<String, Double> tracked = new LinkedHashMap<>();
            Map<String, String[]> byVersion = new LinkedHashMap<>();
            for (int i = 0; i < sets.size(); i++) {
                Object ko = sets.get(i);
                String ref = "keyset#" + i + ":" + (ko instanceof Map ? id(get(ko, "version")) : "?");
                Map<String, Object> holder = ko instanceof Map && get(ko, "sequencer") instanceof String ? rootHolders.get(get(ko, "sequencer")) : null;
                if (holder == null) { f.add("acc.keysets", "fail", refs(ref), "not signed by a sequencer root the session root pins"); continue; }
                String root = (String) holder.get("root");
                if (!EvidenceBridge.verifySequencerKeySet(ko, root, holder.get("root_pq_pk"), holder.containsKey("root_pq_pk"))) {
                    f.add("acc.keysets", "fail", refs(ref), "the key set does not verify under its pinned root");
                    continue;
                }
                Map<String, Object> k = m(ko);
                double ver = num(k.get("version"));
                Double prev = tracked.get(root);
                if (prev != null && ver < prev) { f.add("acc.keysets", "fail", refs(ref), "version " + id(k.get("version")) + " rolls back the tracked version " + js(prev)); continue; }
                String slot = root + "#" + id(k.get("version"));
                String dg = IntentAcc.keySetDigest(k);
                String[] seen = byVersion.get(slot);
                if (seen != null && !seen[0].equals(dg)) {
                    equivocatedSlots.add(slot);
                    verifiedKeySets.add(k);
                    f.add("acc.keysets.equivocation", "fail", refs(seen[1], ref), "two different key sets under version " + id(k.get("version")) + " of one sequencer root");
                    continue;
                }
                if (seen == null) byVersion.put(slot, new String[] {dg, ref});
                verifiedKeySets.add(k);
                tracked.put(root, Math.max(prev == null ? 0 : prev, ver));
                acceptedKeySets.add(k);
                f.add("acc.keysets", "pass", refs(ref));
            }
            for (int i = acceptedKeySets.size() - 1; i >= 0; i--) {
                Map<String, Object> k = acceptedKeySets.get(i);
                if (equivocatedSlots.contains(k.get("sequencer") + "#" + id(k.get("version")))) acceptedKeySets.remove(i);
            }
        }
        java.util.function.BiFunction<String, Double, KeySetsAt> keySetsAt = (root, t) -> {
            KeySetsAt r = new KeySetsAt();
            Map<String, Object> newest = null;
            for (Map<String, Object> k : verifiedKeySets) {
                if (!root.equals(k.get("sequencer")) || !(num(k.get("issued_at")) <= t)) continue;
                if (newest == null || num(k.get("version")) > num(newest.get("version"))) newest = k;
            }
            boolean poisoned = newest != null && equivocatedSlots.contains(root + "#" + id(newest.get("version")));
            r.sets = new ArrayList<>();
            double floor = newest == null ? 0 : num(newest.get("version"));
            for (Map<String, Object> k : acceptedKeySets) {
                if (root.equals(k.get("sequencer")) && num(k.get("issued_at")) <= t + IntentAcc.RECEIPT_SKEW_MS && num(k.get("version")) >= floor) r.sets.add(k);
            }
            r.minV = newest == null ? null : num(newest.get("version"));
            if (newest != null && !poisoned) {
                r.tracked = new LinkedHashMap<>();
                r.tracked.put("version", newest.get("version"));
                r.tracked.put("digest", IntentAcc.keySetDigest(newest));
            }
            return r;
        };

        // -- PCActns
        Map<String, Map<String, Object>> byDigest = new LinkedHashMap<>();
        Map<String, Integer> rootSeq = new LinkedHashMap<>();
        List<Object> effects = l(b.get("effects"));
        java.util.function.Function<String, Map<String, Object>> effectOf = d -> {
            for (Object e : effects) if (d.equals(get(e, "pcactn_digest"))) return m(e);
            return null;
        };
        java.util.function.Function<Map<String, Object>, String> digestOf = p -> {
            try { return Pca.hashCanonical(p); } catch (RuntimeException e) { return null; }
        };
        List<Map<String, Object>> grantsBySeq = new ArrayList<>();
        {
            List<Grant> gs = new ArrayList<>(grants.values());
            gs.sort((x, y) -> Integer.compare(x.seq, y.seq));
            for (Grant g : gs) grantsBySeq.add(g.cap);
        }
        List<Object> epochs = l(b.get("revocation_epochs"));
        java.util.function.ToIntFunction<Double> epochIdxAt = t -> {
            int idx = -1;
            for (int i = 0; i < epochs.size(); i++) if (num(get(get(epochs.get(i), "epoch"), "issued_at")) <= t) idx = i;
            return idx;
        };
        List<Object> pcactns = l(b.get("pcactns"));
        List<Object> events = l(acc.get("events"));
        List<Object> history = new ArrayList<>();
        for (Object evo : events) {
            String pd = (String) get(evo, "pcactn_digest");
            boolean dup = false;
            for (Object h : history) if (pd.equals(get(h, "id"))) { dup = true; break; }
            if (dup) continue;
            Map<String, Object> p = null;
            for (Object x : pcactns) { if (pd.equals(digestOf.apply(m(x)))) { p = m(x); break; } }
            Map<String, Object> eff = effectOf.apply(pd);
            Object params = eff == null ? null : eff.get("params");
            if (p != null && params != null) {
                Map<String, Object> h = new LinkedHashMap<>();
                h.put("id", pd);
                h.put("verb", get(p.get("action"), "verb"));
                h.put("resource", get(p.get("action"), "resource"));
                h.put("params", params);
                h.put("t", p.get("iat"));
                h.put("status", has(evo, "status") && get(evo, "status") != null ? get(evo, "status") : "committed");
                history.add(h);
            }
        }
        Object schemaVerbsOnly = verbsOnly(schemaDoc);
        List<Object> receiptsAll = acc.get("receipts") instanceof List ? l(acc.get("receipts")) : new ArrayList<>();
        Map<String, Object> trustAcc = trust.get("acc") instanceof Map ? m(trust.get("acc")) : null;
        java.util.function.Function<Object[], Map<String, Object>> v2Context = a -> {
            Map<String, Object> p = m(a[0]);
            String d = (String) a[1];
            Integer seq = (Integer) a[2];
            Map<String, Object> eff = effectOf.apply(d);
            Object params = eff == null ? null : eff.get("params");
            if (!(params instanceof Map) || seq == null) return null;
            int idx = -1;
            for (int i = 0; i < history.size(); i++) if (d.equals(get(history.get(i), "id"))) { idx = i; break; }
            List<Object> before = new ArrayList<>();
            if (idx >= 0) before.addAll(history.subList(0, idx));
            else for (Object h : history) if (num(get(h, "t")) <= num(p.get("iat"))) before.add(h);
            Map<String, Object> accCtx = EvidenceBridge.accContextFor(S, before, m(params), p.get("iat"), schemaVerbsOnly);
            int ri = epochIdxAt.applyAsInt(num(p.get("iat")));
            Object rev = ri >= 0 ? epochs.get(ri) : null;
            Object revLast = ri > 0 ? epochs.get(ri - 1) : null;
            Map<String, Object> ctx = new LinkedHashMap<>();
            ctx.put("params", params);
            Map<String, Object> sch = new LinkedHashMap<>();
            sch.put("docs", new ArrayList<Object>(List.of(schemaDoc)));
            sch.put("keys", siteKeys != null ? siteKeys : new ArrayList<Object>());
            ctx.put("schema", sch);
            Map<String, Object> sess = new LinkedHashMap<>();
            sess.put("root", S);
            sess.put("grants", new ArrayList<Object>(grantsBySeq.subList(0, Math.min(seq, grantsBySeq.size()))));
            sess.put("pq_pins", pqPins);
            if (rev != null) sess.put("revocation", rev);
            if (revLast != null) sess.put("revocation_last", revLast);
            ctx.put("session", sess);
            Map<String, Object> accOut = new LinkedHashMap<>(accCtx);
            accOut.put("receipts", receiptsAll);
            List<Object> keys = new ArrayList<>();
            Map<String, Object> versions = new LinkedHashMap<>();
            for (String root : rootHolders.keySet()) {
                KeySetsAt ks = keySetsAt.apply(root, num(p.get("iat")));
                keys.addAll(ks.sets);
                if (ks.tracked != null) versions.put(root, ks.tracked);
            }
            accOut.put("sequencer_keys", keys);
            accOut.put("keyset_versions", versions);
            ctx.put("acc", accOut);
            if (trustAcc != null) {
                Map<String, Object> pol = new LinkedHashMap<>();
                pol.put("acc", trustAcc);
                ctx.put("policy", pol);
            }
            return ctx;
        };
        Set<String> v2Checks = new HashSet<>(Arrays.asList("schema", "intent_session", "accumulators"));
        for (Object po : pcactns) {
            Map<String, Object> p = m(po);
            String d = digestOf.apply(p);
            if (d == null) { f.add("pcactn.verify", "fail", refs("pcactn:?"), "not canonicalizable"); continue; }
            byDigest.put(d, p);
            List<String> ref = refs("pcactn:" + d);
            Object capChain = p.get("cap_chain");
            Object root = capChain instanceof List && !((List<?>) capChain).isEmpty() ? ((List<?>) capChain).get(0) : null;
            if (!JsVal.truthy(root)) { f.add("pcactn.verify", "fail", ref, "empty capability chain"); continue; }
            Grant g = grants.get(get(root, "id"));
            boolean sameRoot = g != null && Pca.hashCanonical(g.cap).equals(Pca.hashCanonical(root));
            boolean hasIs = p.containsKey("intent_session");
            Map<String, Object> is = hasIs ? m(p.get("intent_session")) : null;
            Map<String, Object> ctx = hasIs && sameRoot ? v2Context.apply(new Object[] {p, d, g.seq}) : null;
            PcaCore.Options opts = new PcaCore.Options(m(root));
            opts.planRoots = Pca.PlanRoots.SKIP;
            opts.grantFromArtifact = true;
            opts.pqPins = pqPins;
            opts.nowEpoch = lng(p.get("iat"));
            opts.audience(subjectAud);
            if (ctx != null) opts.intentV2 = IntentV2.Context.fromJson(ctx);
            PcaCore.Result r = PcaCore.verify(p, opts);
            List<String> failed = new ArrayList<>();
            for (Map.Entry<String, String> e : r.checks.entrySet()) if (PcaCore.FAIL.equals(e.getValue())) failed.add(e.getKey());
            Collections.sort(failed);
            List<String> v1f = new ArrayList<>(), v2f = new ArrayList<>();
            for (String k : failed) (v2Checks.contains(k) ? v2f : v1f).add(k);
            f.add("pcactn.verify", v1f.isEmpty() ? "pass" : "fail", ref, v1f.isEmpty() ? null : String.join(", ", v1f) + ": " + (r.reason == null ? "" : r.reason));
            if (sameRoot) {
                f.add("pcactn.root", "pass", ref, g.seq == 0 ? "G_0" : "D_" + g.seq);
                rootSeq.put(d, g.seq);
            } else f.add("pcactn.root", "fail", ref, "rooted at a grant that is not G_0 or a verified delta of this session");
            if (hasIs) {
                String why = null;
                if (!str(get(is, "session"), session)) why = "another session";
                else if (!str(get(is, "root"), sRef)) why = "another session root";
                else if (!str(get(is, "schema"), schemaDigest)) why = "another schema";
                else if (g != null && !numEq(get(is, "seq"), n(g.seq))) why = "seq " + id(get(is, "seq")) + " but rooted at seq " + g.seq;
                else {
                    Object isAcc = get(is, "acc");
                    for (Object c : isAcc instanceof List ? (List<?>) isAcc : List.of()) {
                        Object found = null;
                        for (Object e : events) if (d.equals(get(e, "pcactn_digest")) && java.util.Objects.equals(get(e, "acc"), get(c, "id"))) { found = e; break; }
                        if (found == null || !numEq(get(found, "post"), get(c, "post"))) why = "the signed claim " + id(get(c, "id")) + ".post = " + id(get(c, "post")) + " has no matching accumulator event";
                    }
                }
                if (why == null && !v2f.isEmpty()) why = "core v2 checks failed: " + String.join(", ", v2f);
                if (why != null) f.add("pcactn.session", "fail", ref, why);
                else if (ctx == null) f.add("pcactn.session", "unverified", ref, "the core v2 checks need the plaintext params of the effect record");
                else f.add("pcactn.session", "pass", ref);
            }
        }
        Map<String, Object> subject = byDigest.get(subjectM.get("pcactn_digest"));
        f.add("subject.present", subject != null, refs("pcactn:" + subjectM.get("pcactn_digest")));
        Integer sSeq = rootSeq.get(subjectM.get("pcactn_digest"));
        summary.put("admitted_under", sSeq == null ? null : sSeq == 0 ? "G_0" : "D_" + sSeq);

        // -- effects
        for (Object eo : effects) {
            Map<String, Object> e = m(eo);
            List<String> ref = refs("effect:" + e.get("pcactn_digest"));
            Map<String, Object> p = byDigest.get(e.get("pcactn_digest"));
            if (p == null) { f.add("effect.binding", "fail", ref, "no such PCActn in the bundle"); continue; }
            if (!e.containsKey("params")) f.add("effect.binding", "unverified", ref, "no raw params to bind");
            else f.add("effect.binding", Pca.paramsDigest(e.get("params")).equals(get(p.get("action"), "params_digest")), ref);
            if (JsVal.truthy(e.get("charged"))) {
                Map<String, Object> ch = m(e.get("charged"));
                String chRef = (String) ch.get("ref");
                String name = chRef.startsWith("action.params.") ? chRef.substring("action.params.".length()) : null;
                Object bound = name != null && JsVal.truthy(e.get("params")) ? get(e.get("params"), name) : null;
                if (!isNum(bound) || !isNum(ch.get("amount"))) f.add("effect.charged", "unverified", ref, "no numeric " + chRef + " to compare");
                else {
                    f.add("effect.charged", num(ch.get("amount")) <= num(bound) ? "pass" : "fail", ref, id(ch.get("amount")) + " vs " + id(bound));
                    if (e.get("pcactn_digest").equals(subjectM.get("pcactn_digest"))) {
                        Map<String, Object> cs = new LinkedHashMap<>();
                        cs.put("amount", ch.get("amount"));
                        cs.put("bound", bound);
                        summary.put("charged", cs);
                    }
                }
            }
            if (e.containsKey("frame_violations")) {
                List<Object> fv = l(e.get("frame_violations"));
                List<String> sorted = new ArrayList<>();
                for (Object x : fv) sorted.add((String) x);
                Collections.sort(sorted);
                f.add("effect.frame", fv.isEmpty() ? "pass" : "fail", ref, fv.isEmpty() ? null : String.join(", ", sorted));
            }
            f.check("effect.signature", ports.get("effect"), null, e, b, ref, "effect records (no core format yet)");
        }

        // -- JIT consent for an irreversible subject action
        if (subject != null && str(get(subject.get("action"), "reversibility_class"), "irreversible")) {
            List<String> ref = refs("pcactn:" + subjectM.get("pcactn_digest"));
            String ad = IntentJit.intentActionDigest(subject.get("action"));
            Object needO = trust.get("jitTier");
            Object need = needO == null ? "typed" : needO;
            Map<String, Object> c = null;
            for (Map<String, Object> a : real) {
                Map<String, Object> ux = m(a.get("ux"));
                if (numEq(a.get("y"), n(1)) && Boolean.TRUE.equals(ux.get("consent_for_action")) && ad.equals(ux.get("action_digest")) && Wallet.frictionRank(ux.get("tier")) >= Wallet.frictionRank(need)) { c = a; break; }
            }
            if (c != null) {
                f.add("jit.consent", "pass", ref, "question " + id(c.get("question_id")) + ", " + id(get(c.get("ux"), "tier")) + " tier");
                Map<String, Object> cs = new LinkedHashMap<>();
                cs.put("question_id", c.get("question_id"));
                cs.put("tier", get(c.get("ux"), "tier"));
                cs.put("signer", c.get("signer"));
                summary.put("consent", cs);
            } else f.add("jit.consent", "fail", ref, "no principal yes at " + id(need) + " tier or above bound to this action digest");
        }

        // -- accumulators
        Map<String, Map<String, Object>> decls = new LinkedHashMap<>();
        for (Object ao : l(S.get("accumulators"))) decls.put((String) get(ao, "id"), m(ao));
        java.util.function.BiFunction<Map<String, Object>, String, Long> valueOf = (decl, d) -> {
            Map<String, Object> p = byDigest.get(d);
            Map<String, Object> eff = effectOf.apply(d);
            Object params = eff == null ? null : eff.get("params");
            if (p == null || !(params instanceof Map)) return null;
            return EvidenceBridge.accValue(decl, (String) get(p.get("action"), "verb"), m(params), schemaVerbsOnly);
        };
        Map<String, Double> running = new LinkedHashMap<>();
        for (int i = 0; i < events.size(); i++) {
            Map<String, Object> ev = m(events.get(i));
            List<String> ref = refs("acc:" + id(ev.get("acc")) + "#" + i);
            Map<String, Object> decl = decls.get(ev.get("acc"));
            if (decl == null) { f.add("accumulator.declared", "fail", ref); continue; }
            Map<String, Object> p = byDigest.get(ev.get("pcactn_digest"));
            boolean counted = !str(ev.get("status"), "released") && !str(ev.get("status"), "reverted");
            double prev = running.getOrDefault((String) ev.get("acc"), 0.0);
            Double expected = null;
            if (!counted) expected = prev;
            else if (str(decl.get("agg"), "count")) expected = prev + 1;
            else if (str(decl.get("agg"), "sum") || str(decl.get("agg"), "max")) {
                Long val = valueOf.apply(decl, (String) ev.get("pcactn_digest"));
                if (val != null) expected = str(decl.get("agg"), "sum") ? prev + val : Math.max(prev, val);
            }
            double post = num(ev.get("post"));
            if (p == null) f.add("accumulator.arithmetic", "fail", ref, "event names a PCActn that is not in the bundle");
            else if (expected == null) f.add("accumulator.arithmetic", post >= prev ? "unverified" : "fail", ref, post >= prev ? "contribution not recomputable" : "post decreased");
            else f.add("accumulator.arithmetic", post == expected ? "pass" : "fail", ref, post == expected ? null : "post " + id(ev.get("post")) + ", recomputed " + js(expected));
            running.put((String) ev.get("acc"), counted ? post : prev);
            if (!counted) continue;
            Integer seq = p != null ? rootSeq.get(ev.get("pcactn_digest")) : null;
            if (has(ev, "delta") && seq != null && !numEq(ev.get("delta"), n(seq))) { f.add("accumulator.cap", "fail", ref, "the event names a different admitting grant from the PCActn root"); continue; }
            Grant grant = null;
            for (Grant gg : grants.values()) {
                if (seq != null ? gg.seq == seq : (has(ev, "delta") && numEq(ev.get("delta"), n(gg.seq)))) { grant = gg; break; }
            }
            List<Double> caps = new ArrayList<>();
            Double c1 = grant != null && p != null ? EvidenceVerify.capOf(grant.cap, (String) ev.get("acc"), (String) get(p.get("action"), "verb")) : null;
            if (c1 != null) caps.add(c1);
            if (isNum(decl.get("domain_max"))) caps.add(num(decl.get("domain_max")));
            if (isNum(decl.get("cap"))) caps.add(num(decl.get("cap")));
            if (caps.isEmpty()) f.add("accumulator.cap", "unverified", ref, "no cap stated for this accumulator");
            else {
                double cap = Collections.min(caps);
                f.add("accumulator.cap", isNum(ev.get("post")) && post <= cap ? "pass" : "fail", ref, "post " + id(ev.get("post")) + ", cap " + js(cap));
            }
        }
        List<Object> receipts = receiptsAll;
        if (str(acc.get("holder"), "sequenced") && receipts.isEmpty()) f.add("accumulator.receipts", "fail", refs("accumulator"), "a sequenced accumulator without receipts");
        for (int i = 0; i < receipts.size(); i++) {
            Map<String, Object> r = m(receipts.get(i));
            Core core = () -> {
                Map<String, Object> decl = decls.get(r.get("acc"));
                if (decl == null || !str(get(decl.get("holder"), "kind"), "sequenced")) return vd(false, "the receipt names an accumulator that is not sequenced in the session root");
                Map<String, Object> holder = m(decl.get("holder"));
                if (!str(r.get("session"), session) || !str(r.get("aud"), subjectAud)) return vd(false, "receipt for another session or audience");
                String d = null;
                for (Map.Entry<String, Map<String, Object>> e : byDigest.entrySet()) {
                    if (IntentAcc.pcactnReservationDigest(e.getValue()).equals(r.get("pcactn_digest"))) { d = e.getKey(); break; }
                }
                if (d == null) return vd(false, "the receipt reserves for a PCActn that is not in the bundle");
                double admittedAt = num(byDigest.get(d).get("iat"));
                KeySetsAt ks = keySetsAt.apply((String) holder.get("root"), admittedAt);
                Double maxR = trustAcc != null && trustAcc.containsKey("max_receipt_age_s") ? num(trustAcc.get("max_receipt_age_s")) * 1000 : null;
                Double maxK = trustAcc != null && trustAcc.containsKey("max_keyset_age_s") ? num(trustAcc.get("max_keyset_age_s")) * 1000 : null;
                if (!EvidenceBridge.verifyReceiptAgainstHolder(r, holder, ks.sets, admittedAt, maxR, maxK, ks.tracked, ks.tracked == null ? ks.minV : null))
                    return vd(false, "not signed by a key the pinned sequencer root listed, or not fresh, at admission time");
                if (!(isNum(admittedAt) && isNum(r.get("expires_at")) && admittedAt <= num(r.get("expires_at")))) return vd(false, "the receipt had expired when the action was admitted");
                Long val = valueOf.apply(decl, d);
                if (val == null) return null;
                if (!EvidenceBridge.receiptArithmeticOk(decl.get("agg"), r, val)) return vd(false, "pre + delta does not give post for the reserved value");
                return vd(true, null);
            };
            f.check("accumulator.receipts", ports.get("receipt"), core, r, b, refs("receipt:" + id(r.get("acc")) + "#" + (r.containsKey("seq") ? id(r.get("seq")) : String.valueOf(i))), "the reserved contribution (the effect params were withheld)");
        }

        // -- W-B artifacts
        List<Object> facts = b.get("facts") instanceof List ? l(b.get("facts")) : new ArrayList<>();
        for (int i = 0; i < facts.size(); i++) {
            Object x = facts.get(i);
            Object pk = x instanceof Map && get(x, "oracle") instanceof String ? get(trust.get("oracleKeys"), (String) get(x, "oracle")) : null;
            Core core = pk == null ? null : () -> {
                String w = EvidenceBridge.validateFactWire(x);
                if (w != null) return vd(false, w);
                return EvidenceBridge.verifyArtifactSig(OracleFacts.FACT_DOMAIN, m(x), (String) pk) ? vd(true, null) : vd(false, "bad oracle signature");
            };
            f.check("fact.signature", ports.get("fact"), core, x, b, refs("fact:" + i), "this fact (oracle key not pinned)");
        }
        List<Object> classifier = b.get("classifier") instanceof List ? l(b.get("classifier")) : new ArrayList<>();
        for (int i = 0; i < classifier.size(); i++) {
            Object x = classifier.get(i);
            String judge = x instanceof Map && get(x, "judge") instanceof String ? (String) get(x, "judge") : null;
            Core core = judge == null || !(trust.get("judges") instanceof List ? (List<?>) trust.get("judges") : List.of()).contains(judge) ? null : () -> {
                String w = EvidenceBridge.validateClassifierVerdictWire(x);
                if (w != null) return vd(false, w);
                if (!str(get(x, "session"), session)) return vd(false, "verdict for another session");
                return EvidenceBridge.verifyArtifactSig(IntentClassifier.INTENT_CLASSIFIER_DOMAIN, m(x), judge) ? vd(true, null) : vd(false, "bad judge signature");
            };
            f.check("classifier.signature", ports.get("classifier"), core, x, b, refs("classifier:" + i), "this classifier verdict (judge not pinned)");
        }
        List<Object> offerSets = b.get("offer_sets") instanceof List ? l(b.get("offer_sets")) : new ArrayList<>();
        for (int i = 0; i < offerSets.size(); i++) {
            Object x = offerSets.get(i);
            Object key = null;
            if (siteKeys != null && x instanceof Map) for (Object k : siteKeys) if (get(k, "kid") != null && get(k, "kid").equals(get(x, "kid")) && str(get(k, "alg"), "ed25519")) { key = k; break; }
            final Object fkey = key;
            Core core = key == null ? null : () -> {
                String w = EvidenceBridge.validateOfferSetWire(x);
                if (w != null) return vd(false, w);
                if (!str(get(x, "session"), session)) return vd(false, "offer set for another session");
                return EvidenceBridge.verifyArtifactSig(OracleFacts.OFFER_SET_DOMAIN, m(x), (String) get(fkey, "pk")) ? vd(true, null) : vd(false, "bad site signature");
            };
            f.check("offer_set.signature", ports.get("offerSet"), core, x, b, refs("offer_set:" + i), "this offer set (site key not pinned)");
        }
        List<Object> labelKeys = new ArrayList<>();
        if (trust.get("labelKeys") instanceof List) labelKeys.addAll((List<?>) trust.get("labelKeys"));
        else if (siteKeys != null) {
            for (Object k : siteKeys) {
                if (!str(get(k, "alg"), "ed25519")) continue;
                Map<String, Object> lk = new LinkedHashMap<>();
                lk.put("site", schemaDoc.get("site"));
                lk.put("kid", get(k, "kid"));
                lk.put("pk", get(k, "pk"));
                labelKeys.add(lk);
            }
        }
        List<Object> labels = b.get("labels") instanceof List ? l(b.get("labels")) : new ArrayList<>();
        for (int i = 0; i < labels.size(); i++) {
            Object x = labels.get(i);
            Core core = labelKeys.isEmpty() ? null : () -> {
                String e = EvidenceBridge.verifyLabels(x, labelKeys);
                if (e == null && !str(get(x, "session"), session)) return vd(false, "label receipt for another session");
                return nul(e);
            };
            f.check("labels.signature", ports.get("labels"), core, x, b, refs("labels:" + i), "this label receipt (no site keys)");
        }

        // -- ported artifacts with no core format
        for (Object v : l(b.get("verdicts"))) f.check("verdict.signature", ports.get("verdict"), null, v, b, refs("verdict:" + id(get(v, "pcactn_digest"))), "site verdicts (no core format yet)");
        List<Object> settlements = b.get("settlements") instanceof List ? l(b.get("settlements")) : new ArrayList<>();
        for (int i = 0; i < settlements.size(); i++) f.check("settlement.signature", ports.get("settlement"), null, settlements.get(i), b, refs("settlement:" + i), "settlement records (no core format yet)");

        // -- revocation
        if (epochs.isEmpty()) f.add("revocation.epoch", "unverified", List.of(), "no revocation epoch in the bundle");
        else if (!JsVal.truthy(S.get("revocation"))) f.add("revocation.epoch", "fail", List.of(), "the session root names no revocation authority");
        else {
            Object revO = S.get("revocation");
            String authority = (String) get(revO, "key");
            double maxAgeMs = (has(revO, "max_age_s") && get(revO, "max_age_s") != null ? num(get(revO, "max_age_s")) : 300) * 1000;
            Map<String, Object> pin = null;
            if (get(revO, "pq_pk") != null) { pin = new LinkedHashMap<>(); pin.put(authority, get(revO, "pq_pk")); }
            boolean historyOk = true;
            for (int i = 0; i < epochs.size(); i++) {
                Object ev = epochs.get(i);
                Object last = i > 0 ? epochs.get(i - 1) : null;
                String e = IntentRevocation.checkSessionRevocation(ev, session, authority, new ArrayList<Object>(), num(get(get(ev, "epoch"), "issued_at")), maxAgeMs, null, pin, last != null, last);
                if (e != null) historyOk = false;
                f.verdict("revocation.history", nul(e), refs("epoch#" + i + ":" + id(get(get(ev, "epoch"), "epoch"))));
            }
            if (subject == null) f.add("revocation.epoch", "unverified", List.of(), "no subject action time");
            else {
                List<Object> ids = new ArrayList<>();
                ids.add(IntentRevocation.sessionRevocationId(session));
                for (Object mo : l(b.get("maps"))) ids.add(IntentRevocation.mapRevocationId((String) get(mo, "commit")));
                for (Object d : deltas) ids.add(IntentRevocation.deltaRevocationId((String) get(d, "id")));
                int idx = epochIdxAt.applyAsInt(num(subject.get("iat")));
                Object ev = idx >= 0 ? epochs.get(idx) : null;
                if (ev == null) f.add("revocation.epoch", "fail", List.of(), "every epoch was issued after the action");
                else if (!historyOk) f.add("revocation.epoch", "fail", refs("epoch:" + id(get(get(ev, "epoch"), "epoch"))), "the bundled epochs are not one append-only chain");
                else {
                    Object last = idx > 0 ? epochs.get(idx - 1) : null;
                    f.verdict("revocation.epoch", nul(IntentRevocation.checkSessionRevocation(ev, session, authority, ids, num(subject.get("iat")), maxAgeMs, null, pin, last != null, last)), refs("epoch:" + id(get(get(ev, "epoch"), "epoch"))));
                }
            }
        }

        // -- anchors
        if (JsVal.truthy(schemaM.get("anchor"))) f.add("schema.anchor", "unverified", refs("schema"), "the anchor names a log position without an inclusion proof");
        List<Object> anchors = l(b.get("anchors"));
        boolean anyEvidenceAnchor = false;
        for (Object a : anchors) if (str(get(a, "kind"), "evidence")) anyEvidenceAnchor = true;
        if (!anyEvidenceAnchor) f.add("anchor.inclusion", "unverified", refs("anchor:evidence"), "the bundle is not anchored");
        for (Object ao : anchors) {
            String kind = (String) get(ao, "kind");
            String dg = (String) get(ao, "digest");
            List<String> ref = refs("anchor:" + kind + ":" + id(get(ao, "index")));
            boolean anchorable;
            if (kind.equals("evidence")) anchorable = dg.equals(digest);
            else if (kind.equals("statement")) anchorable = dg.equals(stmt.get("commit"));
            else if (kind.equals("map")) anchorable = mapCommits.contains(dg);
            else if (kind.equals("schema")) anchorable = dg.equals(schemaDigest);
            else if (kind.equals("observation")) { anchorable = false; for (Map<String, Object> a : verified) if (Wallet.answerRef(a).equals(dg)) { anchorable = true; break; } }
            else anchorable = false;
            if (!anchorable) { f.add("anchor.inclusion", "fail", ref, "the anchor names an artifact that is not this one"); continue; }
            Object g = trust.get("anchorGuardian");
            if (!JsVal.truthy(g)) { f.add("anchor.inclusion", "unverified", ref, "no anchor-log guardian key supplied"); continue; }
            Object h = get(ao, "signed_tree_head");
            Object proof = get(ao, "proof");
            boolean okA = str(get(h, "principal"), EvidenceVerify.INTENT_ANCHOR_LOG)
                && str(get(h, "instance_id"), (String) get(g, "instance"))
                && Ledger.verifyTreeHead(h, (String) get(g, "public"), null)
                && numEq(get(proof, "index"), get(ao, "index"))
                && numEq(get(proof, "size"), get(h, "size"))
                && Ledger.verifyLedgerInclusion((String) get(h, "root"), proof, EvidenceVerify.anchorCommit(kind, dg));
            f.add("anchor.inclusion", okA, ref);
        }

        // -- attribution
        Set<String> signing = new java.util.LinkedHashSet<>();
        signing.add((String) S.get("signer"));
        signing.add((String) g0.get("issuer"));
        for (Object d : deltas) signing.add((String) get(d, "issuer"));
        for (Object a : l(b.get("answers"))) signing.add((String) get(a, "signer"));
        if (hasOpening) signing.add((String) get(opening, "principal"));
        signing.remove(null);
        List<String> keys = new ArrayList<>(signing);
        Collections.sort(keys);
        m(summary.get("attribution")).put("keys_to_check", new ArrayList<Object>(keys));
        if (!trust.containsKey("principals")) f.add("principal.pinned", "unverified", keys, "no pinned principal keys: the bundle names its own principals; verify these keys out of band");
        else {
            Map<String, Object> pins = new LinkedHashMap<>();
            for (Object p : l(trust.get("principals"))) pins.put((String) get(p, "key"), p);
            List<String> unpinned = new ArrayList<>(), pqMismatch = new ArrayList<>();
            for (String k : keys) if (!pins.containsKey(k)) unpinned.add(k);
            for (String k : keys) {
                Object pin = pins.get(k);
                Object sp = null;
                for (Object x : l(S.get("principals"))) if (k.equals(get(x, "key"))) { sp = x; break; }
                if (pin != null && !java.util.Objects.equals(get(pin, "pq_pk"), get(sp, "pq_pk"))) pqMismatch.add(k);
            }
            if (!unpinned.isEmpty()) f.add("principal.pinned", "fail", unpinned, "signing keys that are not pinned principals");
            else if (!pqMismatch.isEmpty()) f.add("principal.pinned", "fail", pqMismatch, "the session root binds a different PQ key than the pin");
            else {
                f.add("principal.pinned", "pass", keys);
                m(summary.get("attribution")).put("pinned", true);
            }
        }

        // -- plain-language facts (only what passed)
        List<Object> proven = new ArrayList<>();
        boolean pinned = Boolean.TRUE.equals(get(summary.get("attribution"), "pinned"));
        Object adm = summary.get("admitted_under");
        if (adm != null && pass(f, "pcactn.verify")) proven.add("The subject action was signed by the agent under " + adm + ", a grant signed by the session principal" + (pinned ? " (pinned)" : " (NOT pinned)") + ".");
        Map<String, Object> consent = m(summary.get("consent"));
        if (consent != null) {
            String sg = (String) consent.get("signer");
            String who = pinned ? "Pinned principal key " + sg : "Session-root key " + sg + " (NOT pinned: not attributed to a known principal)";
            proven.add(who + " signed a " + consent.get("tier") + "-tier \"yes\" bound to this exact action (question " + id(consent.get("question_id")) + ").");
        }
        Map<String, Object> ch = m(summary.get("charged"));
        if (ch != null && num(ch.get("amount")) <= num(ch.get("bound"))) proven.add("The charged amount " + id(ch.get("amount")) + " is within the confirmed value " + id(ch.get("bound")) + ".");
        if (!refusals.isEmpty()) proven.add("The principal refused " + refusals.size() + " question(s): " + JsVal.join(refusals, ", ") + ".");
        long asked = lng(get(summary.get("canary_accuracy"), "asked"));
        if (asked != 0) proven.add("Canary accuracy " + id(get(summary.get("canary_accuracy"), "correct")) + "/" + asked + ".");
        if (pass(f, "accumulator.cap")) proven.add("Every accumulator post is within the cap of the grant that admitted it.");
        if (pass(f, "effect.frame")) proven.add("The site reports no change to monitored state outside the write set.");
        summary.put("proven", proven);
    }

    private static double orZero(Object o) {
        Double d = num(o);
        return d == null || d.isNaN() ? 0 : d;
    }

    /** {@code {verbs: doc.verbs}}: the schema view the accumulator value rule reads. */
    private static Object verbsOnly(Map<String, Object> doc) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("verbs", doc.get("verbs"));
        return v;
    }
}
