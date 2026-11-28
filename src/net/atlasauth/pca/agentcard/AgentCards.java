package net.atlasauth.pca.agentcard;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.a2a.A2aCard;
import net.atlasauth.pca.a2a.A2aJws;
import net.atlasauth.pca.a2a.A2aPca;
import net.atlasauth.pca.jose.Jose;
import net.atlasauth.pca.oauth.JsVal;
import net.atlasauth.pca.oauth.WhatwgUrl;

/**
 * Signed Agent Card plus AgentFacts attestor for PCA. The card signing surface is the A2A one ({@link A2aPca}: same canonical bytes, same
 * detached JWS, same {@code pca_passport} commitment), so a card issued here verifies there and the reverse. This class adds the card
 * builder, the AgentFacts document (self-asserted claims split from third-party attestations, each a detached JWS over a canonical statement),
 * the well-known hosting handlers and the registry entry. Values are parsed JSON (Map, List, String, Boolean, {@link Json.Num}, null);
 * keys are JWK maps. Everything fails closed.
 *
 * <p>Shortcuts: attestation windows parse ISO 8601 only (a string the reference engine would accept through its legacy date fallback is
 * refused here), a date-time with no offset is read in the JVM's zone as the reference engine reads it in its own, and
 * {@link #toRegistryEntry} derives the card URL for http(s) / ws(s) / ftp service URLs without credentials only.
 */
public final class AgentCards {
    private AgentCards() {}

    public static final String DEFAULT_ALG = "EdDSA";
    public static final String PCA_ATTESTOR_ID = "did:atlas:pca-attestor";
    public static final String WELL_KNOWN_AGENT_CARD_PATH = "/.well-known/agent-card.json";
    public static final String WELL_KNOWN_AGENT_FACTS_PATH = "/.well-known/agent-facts.json";
    /** The {@code @context} of a PCA AgentFacts document (a PCA profile, not NANDA-conformant). */
    public static final List<String> AGENT_FACTS_CONTEXT = List.of("https://www.w3.org/ns/did/v1", "https://nanda.ai/agentfacts/v1");
    private static final String STATEMENT_DOMAIN = "atlas-pca/agentfacts/attestation/v1";
    private static final Object UNDEF = new Object();

    /** RFC 8785 canonical bytes (see {@link A2aCard#jcsBytes}). */
    public static byte[] jcsBytes(Object value) { return A2aCard.jcsBytes(value); }

    /** The A2A 1.0 {@code AgentCard} problems (see {@link A2aCard#validateAgentCard1}). */
    public static List<String> validateAgentCard1(Object card) { return A2aCard.validateAgentCard1(card); }

    // ---- helpers -----------------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    private static boolean isObj(Object o) { return o instanceof Map; }

    /** {@code o[k]} as a member read: null for an absent member or a non-object; a null o throws, as a property read on null does. */
    private static Object get(Object o, String k) {
        if (o == null) throw new IllegalStateException("TypeError: cannot read properties of null (reading '" + k + "')");
        return o instanceof Map ? ((Map<?, ?>) o).get(k) : null;
    }

    private static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    /** JavaScript {@code String(v)} for parsed JSON values. */
    static String jsStr(Object v) {
        if (v == null) return "null";
        if (v instanceof String) return (String) v;
        if (v instanceof Boolean) return v.toString();
        Double d = JsVal.num(v);
        if (d != null) return AttestCommon.jsNumString(d);
        if (v instanceof List) {
            StringBuilder sb = new StringBuilder();
            boolean first = true;
            for (Object x : (List<?>) v) { if (!first) sb.append(','); first = false; if (x != null) sb.append(jsStr(x)); }
            return sb.toString();
        }
        return "[object Object]";
    }

    // ---- 1. signed Agent Card ----------------------------------------------------------------------------------------

    /** {@code undefined} is an absent key; an explicit JSON null is a value (the reference tests {@code !== undefined}). */
    private static Map<String, Object> passportRefFrom(Object p, boolean hasUri, Object uri) {
        if (p instanceof List) p = new LinkedHashMap<String, Object>(); // an array is an object without these members
        if (!(p instanceof Map)) throw new IllegalStateException("TypeError: cannot use 'in' operator on a non-object");
        Map<String, Object> m = map(p), out = new LinkedHashMap<>();
        if (m.containsKey("id")) out.put("id", m.get("id"));
        if (m.containsKey("model_id")) { if (hasUri) out.put("uri", uri); }
        else if (m.containsKey("uri")) out.put("uri", m.get("uri"));
        else if (hasUri) out.put("uri", uri);
        return out;
    }

    /**
     * Build an (unsigned) Agent Card from a PCA passport (an AgentPassport, or a bare {@code {id, uri?}}). {@code opts}: {@code name},
     * {@code skills}, {@code url}, {@code description}, {@code version}, {@code passportUri}, {@code pcaProofRef}.
     */
    public static Map<String, Object> buildAgentCard(Object passport, Map<String, Object> opts) {
        Map<String, Object> card = new LinkedHashMap<>();
        if (opts.containsKey("name")) card.put("name", opts.get("name"));
        for (String k : new String[] {"description", "url", "version", "skills"}) if (opts.containsKey(k)) card.put(k, opts.get(k));
        card.put("pcaPassport", passportRefFrom(passport, opts.containsKey("passportUri"), opts.get("passportUri")));
        if (opts.containsKey("pcaProofRef")) card.put("pcaProof", opts.get("pcaProofRef"));
        return card;
    }

    /** Sign an Agent Card (wire-identical to {@link A2aPca#issueSignedAgentCard}). */
    public static Map<String, Object> issueSignedAgentCard(Object card, Map<String, Object> signingKey, A2aPca.IssueOptions opts) {
        return A2aPca.issueSignedAgentCard(card, signingKey, opts);
    }

    /**
     * Validate an Agent Card against its signatures (fail-closed): {@code {ok, reason?, passportRef?, passport?, pcaProof?}}. Wording after the first
     * colon of a library failure is this port's own.
     */
    public static Map<String, Object> verifyAgentCard(Object card, A2aPca.VerifyCardOptions opts) { return A2aPca.verifyCard(card, opts, true); }

    // ---- 2. AgentFacts -----------------------------------------------------------------------------------------------

    private static byte[] statementBytes(Object issuer, Object subject, Object attests, Object validFrom, Object validUntil) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", STATEMENT_DOMAIN);
        m.put("issuer", issuer);
        m.put("subject", subject);
        m.put("attests", attests);
        m.put("validFrom", validFrom);
        m.put("validUntil", validUntil);
        return Json.canonicalizeStrict(m).getBytes(StandardCharsets.UTF_8);
    }

    private static Map<String, Object> signAttestation(Object issuer, Object subject, Object attests, Object validFrom, Object validUntil, Object keyO, Object alg, Object kid) {
        if (subject == UNDEF || attests == UNDEF) throw new IllegalArgumentException("canonicalize: unsupported type undefined");
        byte[] payload = statementBytes(issuer, subject, attests, validFrom, validUntil == UNDEF ? null : validUntil);
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("attestor", issuer);
        Map<String, Object> sig = A2aJws.signDetached(payload, map(keyO), alg != null ? (String) alg : DEFAULT_ALG, kid == null ? null : (String) kid, false, header);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("issuer", issuer);
        out.put("subject", subject);
        out.put("attests", attests);
        out.put("validFrom", validFrom);
        if (validUntil != UNDEF) out.put("validUntil", validUntil);
        out.put("signature", sig);
        return out;
    }

    private static Object validFromOf(Map<String, Object> opts) {
        return opts.get("validFrom") != null ? opts.get("validFrom") : A2aPca.toIsoString(opts.get("now") != null ? opts.get("now") : (Object) Long.valueOf(System.currentTimeMillis()));
    }

    /**
     * Issue an AgentFacts document for a passport with PCA as the third-party attestor. {@code opts}: {@code attestorKey} (a private JWK),
     * {@code attests}, {@code selfAsserted}, {@code attestorId}, {@code agentId}, {@code alg}, {@code kid}, {@code validFrom}, {@code validUntil}, {@code now},
     * {@code context}. The self-asserted claims are echoed verbatim and never signed.
     */
    public static Map<String, Object> issueAgentFacts(Object passport, Map<String, Object> opts) {
        Object agentId = opts.get("agentId") != null ? opts.get("agentId") : (has(passport, "id") ? get(passport, "id") : idOrUndef(passport));
        Object validFrom = validFromOf(opts);
        Object issuer = opts.get("attestorId") != null ? opts.get("attestorId") : PCA_ATTESTOR_ID;
        Map<String, Object> att = signAttestation(issuer, agentId, opts.containsKey("attests") ? opts.get("attests") : UNDEF, validFrom,
            opts.containsKey("validUntil") ? opts.get("validUntil") : UNDEF, opts.get("attestorKey"), opts.get("alg"), opts.get("kid"));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("@context", opts.get("context") != null ? opts.get("context") : new ArrayList<Object>(AGENT_FACTS_CONTEXT));
        out.put("id", agentId);
        out.put("type", "AgentFacts");
        out.put("selfAsserted", opts.get("selfAsserted") != null ? opts.get("selfAsserted") : new LinkedHashMap<String, Object>());
        out.put("attestations", new ArrayList<Object>(List.of(att)));
        return out;
    }

    /** {@code passport.id} when it is absent: a null passport throws (property read on null), anything else reads undefined. */
    private static Object idOrUndef(Object passport) {
        get(passport, "id");
        return UNDEF;
    }

    /** Append another third-party attestation to an AgentFacts document (a copy; the input is not mutated). {@code opts} as {@link #issueAgentFacts}. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> addAttestation(Object facts, Map<String, Object> opts) {
        Object validFrom = validFromOf(opts);
        Object issuer = opts.get("attestorId") != null ? opts.get("attestorId") : PCA_ATTESTOR_ID;
        Object subject = has(facts, "id") ? get(facts, "id") : UNDEF;
        Map<String, Object> att = signAttestation(issuer, subject, opts.containsKey("attests") ? opts.get("attests") : UNDEF, validFrom,
            opts.containsKey("validUntil") ? opts.get("validUntil") : UNDEF, opts.get("attestorKey"), opts.get("alg"), opts.get("kid"));
        Map<String, Object> out = A2aPca.spread(facts);
        Object existing = get(facts, "attestations");
        List<Object> l = new ArrayList<>();
        if (existing instanceof List) l.addAll((List<Object>) existing);
        else if (existing instanceof String) ((String) existing).codePoints().forEach(c -> l.add(new String(Character.toChars(c))));
        else throw new IllegalStateException("TypeError: facts.attestations is not iterable");
        l.add(att);
        out.put("attestations", l);
        return out;
    }

    private static Map<String, Object> check(Object issuer, boolean ok, String reason) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("issuer", issuer);
        c.put("ok", ok);
        if (reason != null) c.put("reason", reason);
        return c;
    }

    private static Object issuerOf(Object a) { return a instanceof Map && map(a).get("issuer") instanceof String ? map(a).get("issuer") : "<unknown>"; }

    private static final Pattern ISO = Pattern.compile("^([+-]\\d{6}|\\d{4})(?:-(\\d{2})(?:-(\\d{2}))?)?(?:T(\\d{2}):(\\d{2})(?::(\\d{2})(?:\\.(\\d+))?)?(Z|[+-]\\d{2}:\\d{2})?)?$");

    /** {@code Date.parse}: epoch ms, or NaN. ISO 8601 only (see the class note). */
    static double parseDate(Object sO) {
        if (!(sO instanceof String)) return Double.NaN;
        Matcher m = ISO.matcher((String) sO);
        if (!m.matches()) return Double.NaN;
        try {
            String ys = m.group(1);
            if (ys.equals("-000000")) return Double.NaN;
            int y = Integer.parseInt(ys.startsWith("+") ? ys.substring(1) : ys);
            int mo = m.group(2) == null ? 1 : Integer.parseInt(m.group(2)), d = m.group(3) == null ? 1 : Integer.parseInt(m.group(3));
            boolean timed = m.group(4) != null;
            int hh = timed ? Integer.parseInt(m.group(4)) : 0, mi = timed ? Integer.parseInt(m.group(5)) : 0, ss = m.group(6) == null ? 0 : Integer.parseInt(m.group(6));
            int ms = m.group(7) == null ? 0 : Integer.parseInt((m.group(7) + "00").substring(0, 3));
            if (mo < 1 || mo > 12 || d < 1 || d > 31 || mi > 59 || ss > 59 || hh > 24 || (hh == 24 && (mi != 0 || ss != 0 || ms != 0))) return Double.NaN;
            // a day past the month's end rolls into the next month, as the reference engine reads it (2026-02-30 is March 2)
            LocalDateTime base = LocalDateTime.of(y, mo, 1, 0, 0, 0).plusDays(d - 1).plusHours(hh).plusMinutes(mi).plusSeconds(ss);
            String z = m.group(8);
            long epoch;
            if (z != null && z.equals("Z")) epoch = base.toEpochSecond(ZoneOffset.UTC);
            else if (z != null) {
                int sign = z.charAt(0) == '-' ? -1 : 1;
                int oh = Integer.parseInt(z.substring(1, 3)), om = Integer.parseInt(z.substring(4, 6));
                if (oh > 23 || om > 59) return Double.NaN;
                epoch = base.toEpochSecond(ZoneOffset.ofTotalSeconds(sign * (oh * 3600 + om * 60)));
            } else if (!timed) epoch = base.toEpochSecond(ZoneOffset.UTC); // date-only forms are UTC
            else epoch = base.atZone(ZoneId.systemDefault()).toEpochSecond(); // date-time forms with no offset are local time
            double v = epoch * 1000.0 + ms;
            return Math.abs(v) > 8.64e15 ? Double.NaN : v;
        } catch (RuntimeException e) {
            return Double.NaN;
        }
    }

    private static Map<String, Object> verifyOne(Object a, Object docId, double now, A2aJws.Resolver resolver) {
        Object issuer = issuerOf(a);
        if (!JsVal.truthy(a) || !(get(a, "subject") instanceof String) || !isObj(get(a, "attests")) || !(get(a, "validFrom") instanceof String))
            return check(issuer, false, "attestation is malformed");
        String subject = (String) get(a, "subject");
        if (!(docId instanceof String) || !subject.equals(docId)) return check(issuer, false, "attestation subject '" + subject + "' does not match agent id '" + jsStr(docId) + "'");
        double from = parseDate(get(a, "validFrom"));
        if (Double.isNaN(from)) return check(issuer, false, "attestation validFrom is not a valid date");
        if (!(Double.isFinite(now) && now >= from)) return check(issuer, false, "attestation is not yet valid");
        if (has(a, "validUntil")) {
            double until = parseDate(get(a, "validUntil"));
            if (Double.isNaN(until)) return check(issuer, false, "attestation validUntil is not a valid date");
            if (!(Double.isFinite(now) && now <= until)) return check(issuer, false, "attestation has expired");
        }
        if (resolver == null) return check(issuer, false, "no verification key or JWKS supplied");
        // the statement bytes are computed outside the verify guard in the reference: no canonical form is an error, not a refusal
        byte[] payload = statementBytes(has(a, "issuer") ? get(a, "issuer") : UNDEF, subject, get(a, "attests"), get(a, "validFrom"), has(a, "validUntil") ? get(a, "validUntil") : null);
        if (get(a, "signature") == null) throw new IllegalStateException("TypeError: cannot read properties of undefined (reading 'protected')");
        A2aJws.Result r = A2aJws.verifyDetached(payload, get(a, "signature"), resolver);
        if (!r.ok) return check(issuer, false, "signature did not verify: " + r.reason);
        Map<String, Object> ok = check(issuer, true, null);
        ok.put("attests", get(a, "attests"));
        return ok;
    }

    /**
     * Verify an AgentFacts document, fail-closed: a wrong subject, a closed or malformed validity window, or a signature that does not verify refuses
     * that attestation, and any refused attestation refuses the document. {@code opts}: {@code jwks} / {@code key} / {@code alg} / {@code now}. The result
     * marks which claims are third-party attested and which merely self-asserted: {@code {ok, reason?, agentId, attestations[], attested, selfAsserted, claims}}.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyAgentFacts(Object facts, Map<String, Object> opts) {
        Object saO = get(facts, "selfAsserted");
        Map<String, Object> selfAsserted = isObj(saO) ? map(saO) : new LinkedHashMap<String, Object>();
        Object nowO = opts.get("now");
        double now = nowO != null ? (JsVal.num(nowO) == null ? Double.NaN : JsVal.num(nowO)) : (double) System.currentTimeMillis();
        Object listO = get(facts, "attestations");
        boolean hasId = has(facts, "id");
        Object id = get(facts, "id");
        if (!(listO instanceof List)) return result(false, "agent facts has no attestations array", hasId, id, new ArrayList<>(), new LinkedHashMap<>(), selfAsserted, new LinkedHashMap<>());
        List<Object> list = (List<Object>) listO;
        A2aJws.Resolver resolver = null;
        if (!list.isEmpty()) {
            A2aJws.Resolved res = A2aJws.resolveVerifyKey(opts.get("jwks"), opts.get("key"), (String) opts.get("alg"));
            if (res.error != null) {
                List<Object> missing = new ArrayList<>();
                for (Object a : list) missing.add(check(issuerOf(a), false, "no verification key or JWKS supplied"));
                return result(false, res.error, hasId, id, missing, new LinkedHashMap<>(), selfAsserted, new LinkedHashMap<>());
            }
            resolver = res.resolver;
        }
        List<Object> checks = new ArrayList<>();
        Map<String, Object> attested = new LinkedHashMap<>();
        boolean allOk = true;
        for (Object a : list) {
            Map<String, Object> c = verifyOne(a, id, now, resolver);
            checks.add(c);
            if (!Boolean.TRUE.equals(c.get("ok"))) { allOk = false; continue; }
            Object at = c.get("attests");
            if (isObj(at)) attested.putAll(map(at));
        }
        Map<String, Object> claims = new LinkedHashMap<>();
        for (String k : selfAsserted.keySet()) claims.put(k, "self-asserted");
        for (String k : attested.keySet()) claims.put(k, "attested"); // attested wins on overlap
        return result(allOk, allOk ? null : "one or more attestations did not verify", hasId, id, checks, attested, selfAsserted, claims);
    }

    private static Map<String, Object> result(boolean ok, String reason, boolean hasId, Object id, List<Object> checks,
                                              Map<String, Object> attested, Map<String, Object> self, Map<String, Object> claims) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", ok);
        if (reason != null) out.put("reason", reason);
        if (hasId) out.put("agentId", id);
        out.put("attestations", checks);
        out.put("attested", attested);
        out.put("selfAsserted", self);
        out.put("claims", claims);
        return out;
    }

    // ---- 3. well-known hosting ---------------------------------------------------------------------------------------

    /** A path handler: a request path in, the response {@code {status, headers, body}} out, or null when the path is not this handler's. */
    @FunctionalInterface
    public interface PathHandler extends Function<String, Map<String, Object>> {}

    private static Map<String, Object> jsonResponse(Object value) {
        Map<String, Object> headers = new LinkedHashMap<>();
        headers.put("content-type", "application/json");
        headers.put("cache-control", "no-store");
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("status", new Json.Num("200"));
        r.put("headers", headers);
        r.put("body", Jose.stringify(value));
        return r;
    }

    private static String normalizePath(String path) {
        int q = path.indexOf('?');
        String noQuery = q == -1 ? path : path.substring(0, q);
        return noQuery.length() > 1 && noQuery.endsWith("/") ? noQuery.substring(0, noQuery.length() - 1) : noQuery;
    }

    /** Serve a signed Agent Card at {@code path} (null: {@link #WELL_KNOWN_AGENT_CARD_PATH}); the handler returns null for any other path. */
    public static PathHandler agentCardHandler(Object card, String path) {
        final String target = normalizePath(path != null ? path : WELL_KNOWN_AGENT_CARD_PATH);
        final Map<String, Object> response = jsonResponse(card);
        return reqPath -> normalizePath(reqPath).equals(target) ? response : null;
    }

    /** Serve an AgentFacts document at {@code path} (null: {@link #WELL_KNOWN_AGENT_FACTS_PATH}); the handler returns null for any other path. */
    public static PathHandler agentFactsHandler(Object facts, String path) {
        final String target = normalizePath(path != null ? path : WELL_KNOWN_AGENT_FACTS_PATH);
        final Map<String, Object> response = jsonResponse(facts);
        return reqPath -> normalizePath(reqPath).equals(target) ? response : null;
    }

    // ---- 4. registry entry ---------------------------------------------------------------------------------------------

    private static String wellKnownUrlFrom(Object serviceUrl, String path) {
        if (!(serviceUrl instanceof String)) return null;
        try {
            WhatwgUrl u = WhatwgUrl.parse((String) serviceUrl);
            String p = u.protocol;
            if (!(p.equals("http:") || p.equals("https:") || p.equals("ws:") || p.equals("wss:") || p.equals("ftp:"))) return null;
            return p + "//" + u.host + (u.port.isEmpty() ? "" : ":" + u.port) + path;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /**
     * Shape a registry entry from a signed card and an AgentFacts document (purely structural: it does NOT re-verify). Derives which advertised claim
     * names a third party attests and which are only self-asserted.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> toRegistryEntry(Object card, Object facts) {
        Set<String> attestedSet = new LinkedHashSet<>();
        Object atts = get(facts, "attestations");
        if (atts != null) {
            if (!(atts instanceof List) && !(atts instanceof String)) throw new IllegalStateException("TypeError: not iterable");
            if (atts instanceof List) for (Object a : (List<Object>) atts) if (JsVal.truthy(a) && isObj(get(a, "attests"))) attestedSet.addAll(map(get(a, "attests")).keySet());
        }
        Object saO = get(facts, "selfAsserted");
        List<Object> selfOnly = new ArrayList<>();
        if (isObj(saO)) for (String k : map(saO).keySet()) if (!attestedSet.contains(k)) selfOnly.add(k);
        String cardUrl = wellKnownUrlFrom(get(card, "url"), WELL_KNOWN_AGENT_CARD_PATH);
        Map<String, Object> out = new LinkedHashMap<>();
        if (has(facts, "id")) out.put("id", get(facts, "id"));
        if (has(card, "name")) out.put("name", get(card, "name"));
        for (String k : new String[] {"url", "version", "skills"}) if (has(card, k)) out.put(k, get(card, k));
        if (JsVal.truthy(get(card, "pcaPassport"))) out.put("passport", get(card, "pcaPassport"));
        if (JsVal.truthy(get(card, "pcaProof"))) out.put("pcaProof", get(card, "pcaProof"));
        out.put("card", card);
        if (cardUrl != null) out.put("agentCardUrl", cardUrl);
        out.put("facts", facts);
        out.put("attestedClaims", new ArrayList<Object>(attestedSet));
        out.put("selfAssertedClaims", selfOnly);
        return out;
    }
}
