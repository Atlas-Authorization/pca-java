package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.gnap.Gnap;
import net.atlasauth.pca.gnap.Interaction;
import net.atlasauth.pca.gnap.InteractionError;
import org.junit.jupiter.api.Test;

/** Replays the TypeScript-reference oracle of the GNAP bridge (access rights, grant requests, chains, jwsd proofs, step-up, interaction). */
class GnapDiffTest {
    private static final String MOD = "ref-gnap";

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }

    @SuppressWarnings("unchecked")
    private static List<Object> l(Object o) { return (List<Object>) o; }

    /** An InteractionError seen as the oracle's coded refusal. */
    private static final class CodedEx extends RuntimeException implements OracleCases.Coded {
        private static final long serialVersionUID = 1L;
        private final String code;
        CodedEx(InteractionError e) { super(e.getMessage(), e); this.code = e.code(); }
        @Override public String code() { return code; }
    }

    private static OracleCases.Fn coded(OracleCases.Fn f) {
        return a -> {
            try { return f.apply(a); } catch (InteractionError e) { throw new CodedEx(e); }
        };
    }

    private static Object unbytes(Object x) {
        if (x instanceof Map && m(x).size() == 1 && m(x).get("$bytes") instanceof String) return Keys.unb64u((String) m(x).get("$bytes"));
        return x;
    }

    private static Map<String, Object> opt(List<?> a, int i) { return a.size() > i ? m(a.get(i)) : null; }

    // ---- access rights ----

    @Test void constants() throws Exception {
        OracleCases.each(MOD, "constants", a -> {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("GNAP_GRANT_CAVEAT", Gnap.GNAP_GRANT_CAVEAT);
            o.put("GNAP_ACCESS_CAVEAT", Gnap.GNAP_ACCESS_CAVEAT);
            o.put("MAX_DETACHED_JWS_CHARS", Gnap.MAX_DETACHED_JWS_CHARS);
            o.put("START_MODES", new ArrayList<Object>(Interaction.START_MODES));
            o.put("FINISH_METHODS", new ArrayList<Object>(Interaction.FINISH_METHODS));
            o.put("HASH_METHODS", new ArrayList<Object>(Interaction.HASH_METHODS.keySet()));
            return o;
        });
    }

    @Test void agentGnapProfile() throws Exception { OracleCases.each(MOD, "AGENT_GNAP_PROFILE", a -> Gnap.agentGnapProfile()); }

    @Test void gnapActionResource() throws Exception { OracleCases.each(MOD, "gnapActionResource", a -> Gnap.gnapActionResource((String) a.get(0), (String) a.get(1))); }

    @Test void normalizeAccess() throws Exception { OracleCases.each(MOD, "normalizeAccess", a -> Gnap.normalizeAccess(a.get(0))); }

    @Test void accessToPredicates() throws Exception { OracleCases.each(MOD, "accessToPredicates", a -> Gnap.accessToPredicates(m(a.get(0)))); }

    @Test void accessContains() throws Exception { OracleCases.each(MOD, "accessContains", a -> Gnap.accessContains(m(a.get(0)), m(a.get(1)))); }

    @Test void accessWithin() throws Exception { OracleCases.each(MOD, "accessWithin", a -> Gnap.accessWithin(l(a.get(0)), m(a.get(1)))); }

    @Test void clampAccess() throws Exception { OracleCases.each(MOD, "clampAccess", a -> Gnap.clampAccess(l(a.get(0)), l(a.get(1)))); }

    @Test void grantedAccessOf() throws Exception { OracleCases.each(MOD, "grantedAccessOf", a -> Gnap.grantedAccessOf(a.get(0))); }

    @Test void resolveHolder() throws Exception { OracleCases.each(MOD, "resolveHolder", a -> Gnap.resolveHolder(a.get(0), a.size() > 1 ? a.get(1) : Gnap.ABSENT)); }

    @Test void holderJwk() throws Exception { OracleCases.each(MOD, "holderJwk", a -> Gnap.holderJwk((String) a.get(0))); }

    // ---- grant request -> capability, authorization, tokens ----

    @Test void grantRequestToCapability() throws Exception { OracleCases.each(MOD, "grantRequestToCapability", a -> Gnap.grantRequestToCapability(a.get(0), m(a.get(1)))); }

    @Test void authorizeGnapAction() throws Exception { OracleCases.each(MOD, "authorizeGnapAction", a -> Gnap.authorizeGnapAction(a.get(0), m(a.get(1)), opt(a, 2))); }

    @Test void encodeBoundToken() throws Exception { OracleCases.each(MOD, "encodeBoundToken", a -> Gnap.encodeBoundToken(a.get(0))); }

    @Test void capabilityToGrantResponse() throws Exception { OracleCases.each(MOD, "capabilityToGrantResponse", a -> Gnap.capabilityToGrantResponse(a.get(0), opt(a, 1))); }

    @Test void verifyGnapToken() throws Exception { OracleCases.each(MOD, "verifyGnapToken", a -> Gnap.verifyGnapToken(a.get(0), opt(a, 1))); }

    // ---- jwsd ----

    @Test void gnapContentDigest() throws Exception { OracleCases.each(MOD, "gnapContentDigest", a -> Gnap.gnapContentDigest(unbytes(a.get(0)))); }

    @Test void gnapContentDigestAbsent() throws Exception { OracleCases.each(MOD, "gnapContentDigestAbsent", a -> Gnap.gnapContentDigest(Gnap.ABSENT)); }

    @Test void signGnapRequest() throws Exception {
        OracleCases.each(MOD, "signGnapRequest", a -> {
            Map<String, Object> args = new LinkedHashMap<>(m(a.get(0)));
            if (args.containsKey("body")) args.put("body", unbytes(args.get("body")));
            return Gnap.signGnapRequest(args);
        });
    }

    @Test void verifyGnapRequest() throws Exception {
        OracleCases.each(MOD, "verifyGnapRequest", a -> {
            Map<String, Object> args = new LinkedHashMap<>(m(a.get(0)));
            Object mode = args.remove("seenProofMode");
            if (args.containsKey("body")) args.put("body", unbytes(args.get("body")));
            List<Object> seen = new ArrayList<>();
            if (mode != null) {
                args.put("seenProof", (Gnap.SeenProof) (id, exp) -> {
                    List<Object> pair = new ArrayList<>();
                    pair.add(id);
                    pair.add(exp);
                    seen.add(pair);
                    switch ((String) mode) {
                        case "fresh": return Boolean.FALSE;
                        case "replayed": return Boolean.TRUE;
                        case "throws": throw new IllegalStateException("store down");
                        default: return null; // returns nothing: replayed
                    }
                });
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("result", Gnap.verifyGnapRequest(args));
            out.put("seen", seen);
            return out;
        });
    }

    // ---- step-up ----

    @Test void gnapRequestRequiresStepUp() throws Exception { OracleCases.each(MOD, "gnapRequestRequiresStepUp", a -> Gnap.gnapRequestRequiresStepUp(a.get(0), opt(a, 1))); }

    @Test void beginGnapContinuation() throws Exception { OracleCases.each(MOD, "beginGnapContinuation", a -> Gnap.beginGnapContinuation(m(a.get(0)))); }

    @Test void gnapStepUpShare() throws Exception {
        OracleCases.each(MOD, "gnapStepUpShare", a -> Gnap.gnapStepUpShare(m(a.get(0)), (String) a.get(1), a.get(2), a.get(3), a.get(4)));
    }

    @Test void completeGnapContinuation() throws Exception { OracleCases.each(MOD, "completeGnapContinuation", a -> Gnap.completeGnapContinuation(m(a.get(0)))); }

    // ---- interaction ----

    @Test void callbackUriOk() throws Exception { OracleCases.each(MOD, "callbackUriOk", coded(a -> Interaction.callbackUriOk(a.get(0)))); }

    @Test void validateInteractRequest() throws Exception { OracleCases.each(MOD, "validateInteractRequest", coded(a -> Interaction.validateInteractRequest(a.get(0)))); }

    @Test void interactionHash() throws Exception { OracleCases.each(MOD, "interactionHash", coded(a -> Interaction.interactionHash(m(a.get(0))))); }

    @Test void verifyInteractionHash() throws Exception { OracleCases.each(MOD, "verifyInteractionHash", coded(a -> Interaction.verifyInteractionHash(a.get(0), m(a.get(1))))); }

    @Test void acceptFinish() throws Exception { OracleCases.each(MOD, "acceptFinish", coded(a -> Interaction.acceptFinish(m(a.get(0)), m(a.get(1))))); }

    @Test void accessToNeeds() throws Exception { OracleCases.each(MOD, "accessToNeeds", coded(a -> Interaction.accessToNeeds(l(a.get(0))))); }

    @Test void newUserCodeRefusals() throws Exception { OracleCases.each(MOD, "newUserCode", coded(a -> Interaction.newUserCode((int) (double) IntentJs.num(a.get(0))))); }

    @Test void newUserCodeShape() {
        Pattern p = Pattern.compile("[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}");
        for (int i = 0; i < 200; i++) assertTrue(p.matcher(Interaction.newUserCode()).matches());
        for (int n = 6; n <= 12; n++) assertEquals(n, Interaction.newUserCode(n).length());
        assertThrows(IllegalArgumentException.class, () -> Interaction.newUserCode(5));
        assertThrows(IllegalArgumentException.class, () -> Interaction.newUserCode(13));
    }

    // ---- the AS state machine as scripted scenarios (random values replaced by tokens) ----

    private static Object redact(Object v, List<String[]> map) {
        if (v instanceof String) {
            String s = (String) v;
            for (String[] kt : map) if (kt[0] != null && !kt[0].isEmpty()) s = s.replace(kt[0], kt[1]);
            return s;
        }
        if (v instanceof List) { List<Object> out = new ArrayList<>(); for (Object x : (List<?>) v) out.add(redact(x, map)); return out; }
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : m(v).entrySet()) out.put(e.getKey(), redact(e.getValue(), map));
            return out;
        }
        return v;
    }

    private static Object stateMap(Interaction.State s) { return s == null ? null : s.toMap(); }

    private static Object scenario(Map<String, Object> s) {
        long[] clock = {1000};
        Map<String, Object> opts = m(s.get("opts"));
        String ge = opts.containsKey("grantEndpoint") ? (String) opts.get("grantEndpoint") : "https://as.example/tx";
        List<String> supports = new ArrayList<>();
        for (Object x : l(opts.get("supports"))) supports.add((String) x);
        Function<String, String> app = Boolean.TRUE.equals(opts.get("app")) ? id -> "app://as/" + id : null;
        Long ttl = opts.containsKey("ttlSec") ? Long.valueOf((long) (double) IntentJs.num(opts.get("ttlSec"))) : null;
        Interaction.Server srv = new Interaction.Server(ge, supports, id -> "https://as.example/i/" + id, app, (String) opts.get("userCodeUri"), ttl, () -> clock[0]);
        Map<String, String> v = new HashMap<>();
        List<String[]> started = new ArrayList<>(); // {id, code, asnonce} of every start, in order
        Map<String, Object>[] lastReq = new Map[1];
        List<Object> trace = new ArrayList<>();
        Function<Object, Object> sub = x -> {
            if (!(x instanceof String) || !((String) x).startsWith("$")) return x;
            String k = ((String) x).substring(1);
            String code = v.getOrDefault("code", "");
            if (k.equals("code:lower")) return code.toLowerCase(java.util.Locale.ROOT);
            if (k.equals("code:spaced")) return code.substring(0, Math.min(4, code.length())) + " - " + code.substring(Math.min(4, code.length()));
            return v.getOrDefault(k, (String) x);
        };
        for (Object so : l(s.get("steps"))) {
            Map<String, Object> st = m(so);
            String op = (String) st.get("op");
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("op", op);
            try {
                Object value = null;
                switch (op) {
                    case "start": {
                        lastReq[0] = m(st.get("req"));
                        Map<String, Object> r = srv.start(lastReq[0]);
                        Interaction.State it = (Interaction.State) r.get("interaction");
                        v.put("id", it.id);
                        v.put("code", it.userCode != null ? it.userCode : "");
                        v.put("asnonce", it.finish != null ? (String) it.finish.get("asNonce") : "");
                        started.add(new String[] {v.get("id"), v.get("code"), v.get("asnonce")});
                        Map<String, Object> o = new LinkedHashMap<>();
                        o.put("interaction", it.toMap());
                        o.put("response", r.get("response"));
                        value = o;
                        break;
                    }
                    case "lookup": value = stateMap(srv.lookupUserCode((String) sub.apply(st.get("code")))); break;
                    case "approve": {
                        Map<String, Object> r = srv.approve((String) sub.apply(st.get("id")));
                        v.put("ref", (String) r.get("interactRef"));
                        Interaction.State it = srv.get(v.get("id"));
                        String h = null;
                        Map<String, Object> fin = r.get("finish") == null ? null : m(r.get("finish"));
                        if (fin != null && "push".equals(fin.get("method"))) h = (String) m(fin.get("body")).get("hash");
                        else if (fin != null && fin.get("url") != null) { Matcher mt = Pattern.compile("[?&]hash=([^&]+)").matcher((String) fin.get("url")); if (mt.find()) h = mt.group(1); }
                        v.put("hash", h != null ? h : "");
                        String expected = null;
                        if (it != null && it.finish != null) {
                            Map<String, Object> ha = new LinkedHashMap<>();
                            ha.put("clientNonce", it.finish.get("clientNonce"));
                            ha.put("asNonce", it.finish.get("asNonce"));
                            ha.put("interactRef", r.get("interactRef"));
                            ha.put("grantEndpoint", it.grantEndpoint);
                            ha.put("hashMethod", it.finish.get("hashMethod"));
                            expected = Interaction.interactionHash(ha);
                        }
                        Map<String, Object> o = new LinkedHashMap<>();
                        o.put("result", r);
                        o.put("hashOk", Objects.equals(h, expected));
                        value = o;
                        break;
                    }
                    case "consume": value = stateMap(srv.consume((String) sub.apply(st.get("ref")))); break;
                    case "finalize": srv.finalizeInteraction((String) sub.apply(st.get("id"))); break;
                    case "get": value = stateMap(srv.get((String) sub.apply(st.get("id")))); break;
                    case "advance": clock[0] += (long) (double) IntentJs.num(st.get("sec")); value = clock[0]; break;
                    case "accept": {
                        Map<String, Object> fin = m(lastReq[0].get("finish"));
                        Map<String, Object> ctx = new LinkedHashMap<>();
                        ctx.put("clientNonce", fin.get("nonce"));
                        ctx.put("asNonce", v.get("asnonce"));
                        ctx.put("grantEndpoint", ge);
                        if (fin.get("hash_method") != null) ctx.put("hashMethod", fin.get("hash_method"));
                        Map<String, Object> cb = new LinkedHashMap<>();
                        cb.put("hash", sub.apply(st.get("hash")));
                        cb.put("interact_ref", sub.apply(st.get("ref")));
                        value = Interaction.acceptFinish(cb, ctx);
                        break;
                    }
                    default: throw new IllegalStateException("unknown step " + op);
                }
                List<String[]> tokens = new ArrayList<>(List.of(new String[] {v.get("ref"), "<REF>"}, new String[] {v.get("hash"), "<HASH>"}, new String[] {v.get("asnonce"), "<ASNONCE>"},
                    new String[] {v.get("id"), "<ID>"}, new String[] {v.get("code"), "<CODE>"}));
                // an earlier interaction (start number n from 0) is redacted as <ID:n> / <CODE:n> / <ASNONCE:n>, the latest keeps the bare tokens
                for (int n = 0; n < started.size() - 1; n++) {
                    tokens.add(new String[] {started.get(n)[0], "<ID:" + n + ">"});
                    tokens.add(new String[] {started.get(n)[1], "<CODE:" + n + ">"});
                    tokens.add(new String[] {started.get(n)[2], "<ASNONCE:" + n + ">"});
                }
                entry.put("ok", true);
                entry.put("value", redact(OracleCases.toJson(value), tokens));
            } catch (InteractionError e) {
                entry.put("ok", false);
                entry.put("code", e.code());
            } catch (RuntimeException e) {
                entry.put("ok", false);
                entry.put("code", "other");
            }
            trace.add(entry);
        }
        return trace;
    }

    @Test void interactionScenario() throws Exception { OracleCases.each(MOD, "interactionScenario", a -> scenario(m(a.get(0)))); }
}
