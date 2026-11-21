package net.atlasauth.pca.signals;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.function.Supplier;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.jose.Jose;
import net.atlasauth.pca.revoke.JsVal;

/**
 * Shared Signals Framework (SSF / CAEP) for Proof-Carrying Authority: the active revocation and mid-run kill-switch channel.
 * A transmitter emits a Security Event Token (SET, RFC 8417: a JWT with an events claim); subscribers fold those events into local
 * {@link RevocationState} they consult on every request, next to the core verifier. This builds and verifies SETs for CAEP
 * session-revoked / credential-change and the PCA event types (grant-revoked, kill-switch, intent-revoked), keeps the
 * subscriber-side state, and offers the fail-closed {@link #receiveSET} path. SETs are signed EdDSA; keys are JWK maps.
 */
public final class Signals {
    private Signals() {}

    /** RFC 8417 section 2.3: a SET carries typ "secevent+jwt" so it cannot be confused with an access or ID token. */
    public static final String SET_TYP = "secevent+jwt";
    /** The JWS algorithm SETs are signed and verified with. */
    public static final String SET_ALG = "EdDSA";

    public static final String SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
    public static final String CREDENTIAL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/credential-change";
    public static final String GRANT_REVOKED = "https://atlasauth.net/caep/grant-revoked";
    public static final String KILL_SWITCH = "https://atlasauth.net/caep/kill-switch";
    public static final String INTENT_REVOKED = "https://atlasauth.net/caep/intent-revoked";
    public static final String VERIFICATION = "https://schemas.openid.net/secevent/ssf/event-type/verification";
    public static final String RISK_LEVEL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";
    public static final String ASSURANCE_LEVEL_CHANGE = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";

    /** Event-type URIs by the reference's member names (sessionRevoked, credentialChange, grantRevoked, killSwitch, intentRevoked, verification, riskLevelChange, assuranceLevelChange). */
    public static final Map<String, String> EVENT_TYPES;
    static {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("sessionRevoked", SESSION_REVOKED);
        m.put("credentialChange", CREDENTIAL_CHANGE);
        m.put("grantRevoked", GRANT_REVOKED);
        m.put("killSwitch", KILL_SWITCH);
        m.put("intentRevoked", INTENT_REVOKED);
        m.put("verification", VERIFICATION);
        m.put("riskLevelChange", RISK_LEVEL_CHANGE);
        m.put("assuranceLevelChange", ASSURANCE_LEVEL_CHANGE);
        EVENT_TYPES = Collections.unmodifiableMap(m);
    }

    /** OpenID RISC 1.0 event types that end an account's standing: treated as revoking every grant of the mapped agent. */
    public static final Map<String, String> RISC_EVENT_TYPES;
    static {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("sessionsRevoked", "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked");
        m.put("accountDisabled", "https://schemas.openid.net/secevent/risc/event-type/account-disabled");
        m.put("accountPurged", "https://schemas.openid.net/secevent/risc/event-type/account-purged");
        m.put("credentialCompromise", "https://schemas.openid.net/secevent/risc/event-type/credential-compromise");
        RISC_EVENT_TYPES = Collections.unmodifiableMap(m);
    }

    /** Default capacity of {@link #createInMemorySetReplayStore}. */
    public static final int SET_INMEMORY_MAX_ENTRIES = 100_000;

    // ---- build / verify ----

    /**
     * Build a signed Security Event Token (RFC 8417): typ secevent+jwt, iss, iat, a random jti, aud, the events map and, when
     * given, sub plus a structured sub_id. args: {events, issuer, audience (string or list), subject?, key (a private Ed25519 JWK)}.
     */
    @SuppressWarnings("unchecked")
    public static String buildSET(Map<String, Object> args) {
        Object events = JsVal.member(args, "events");
        int keys = events instanceof Map ? ((Map<?, ?>) events).size() : events instanceof List ? ((List<?>) events).size() : 0;
        if (!(events instanceof Map || events instanceof List) || keys == 0) {
            throw new IllegalArgumentException("buildSET: at least one event is required in the `events` map (RFC 8417 §2.2)");
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("events", events);
        boolean hasSubject = JsVal.has(args, "subject");
        if (hasSubject) {
            Map<String, Object> sid = new LinkedHashMap<>();
            sid.put("format", "opaque");
            sid.put("id", args.get("subject"));
            payload.put("sub_id", sid);
        }
        if (JsVal.has(args, "issuer")) payload.put("iss", args.get("issuer")); // an absent one is undefined: omitted from the JSON
        payload.put("iat", new Json.Num(Long.toString(Math.floorDiv(System.currentTimeMillis(), 1000L))));
        payload.put("jti", UUID.randomUUID().toString());
        if (JsVal.has(args, "audience")) payload.put("aud", args.get("audience"));
        if (hasSubject) payload.put("sub", args.get("subject"));
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", SET_ALG);
        header.put("typ", SET_TYP);
        return Jose.signJwt(header, payload, (Map<String, Object>) args.get("key"));
    }

    /** The parsed result of a verified SET. */
    public static final class ParsedSet {
        public final Map<String, Object> events;
        public final String iss;
        /** The SET id (RFC 8417 requires it): de-dup replays on this. */
        public final String jti;
        /** The SET-level subject, or null. */
        public final String sub;
        /** The full verified JWT payload. */
        public final Map<String, Object> payload;

        ParsedSet(Map<String, Object> events, String iss, String jti, String sub, Map<String, Object> payload) {
            this.events = events;
            this.iss = iss;
            this.jti = jti;
            this.sub = sub;
            this.payload = payload;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("events", events);
            m.put("iss", iss);
            m.put("jti", jti);
            if (sub != null) m.put("sub", sub);
            m.put("payload", payload);
            return m;
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseEvents(Object raw) {
        if (!(raw instanceof Map)) throw new IllegalArgumentException("SET invalid: `events` claim is missing or not a JSON object (RFC 8417 §2.2)");
        Map<String, Object> m = (Map<String, Object>) raw;
        if (m.isEmpty()) throw new IllegalArgumentException("SET invalid: `events` claim is empty (RFC 8417 §2.2)");
        for (Map.Entry<String, Object> e : m.entrySet()) {
            if (!(e.getValue() instanceof Map)) throw new IllegalArgumentException("SET invalid: event payload for `" + e.getKey() + "` is not a JSON object (RFC 8417 §2.2)");
        }
        return m;
    }

    private static List<String> strings(Object o, String what) {
        List<String> out = new ArrayList<>();
        if (o instanceof String) out.add((String) o);
        else if (o instanceof List) {
            for (Object x : (List<?>) o) {
                if (!(x instanceof String)) throw new JsVal.TypeError(what + " must be a string or a list of strings");
                out.add((String) x);
            }
        } else throw new JsVal.TypeError(what + " must be a string or a list of strings");
        return out;
    }

    /**
     * Verify a SET's signature (EdDSA) and standard claims, then parse it. Throws on any invalid signature, wrong key, failed claim
     * check (iss / aud / typ / exp / nbf), or a malformed or empty events map. verifyKey is a public Ed25519 JWK. opts (may be
     * null): issuer and audience (string or list), clockTolerance (seconds), currentDate (epoch ms), typ, requireTyp (false skips
     * the typ check).
     */
    public static ParsedSet verifySET(Object set, Object verifyKey, Map<String, Object> opts) {
        Jose.assertCanonicalCompactJws(set); // canonical-spelling gate BEFORE the JOSE layer (one accepted string form)
        Jose.JwtOptions jo = new Jose.JwtOptions();
        jo.algorithms = List.of(SET_ALG);
        List<String> issuerList = null;
        if (JsVal.has(opts, "issuer")) {
            Object i = opts.get("issuer");
            if (i instanceof String) jo.issuer = (String) i;
            else issuerList = strings(i, "issuer");
        }
        if (JsVal.has(opts, "audience")) jo.audience = strings(opts.get("audience"), "audience");
        if (JsVal.has(opts, "clockTolerance")) {
            Object c = opts.get("clockTolerance");
            if (!JsVal.isNumber(c)) throw new JsVal.TypeError("clockTolerance must be a number");
            jo.clockTolerance = JsVal.num(c);
        }
        if (JsVal.has(opts, "currentDate")) {
            Object c = opts.get("currentDate");
            if (!JsVal.isFinite(c)) throw new JsVal.TypeError("currentDate must be a finite epoch time in ms");
            jo.currentDateMs = JsVal.num(c);
        }
        if (!Boolean.FALSE.equals(JsVal.opt(opts, "requireTyp"))) jo.typ = (String) JsVal.or(JsVal.opt(opts, "typ"), SET_TYP);
        Jose.VerifiedJwt v = Jose.jwtVerify((String) set, verifyKey, jo);
        Map<String, Object> payload = v.payload;
        if (issuerList != null) {
            if (!payload.containsKey("iss")) throw new Jose.JoseException("missing required \"iss\" claim");
            if (!issuerList.contains(payload.get("iss"))) throw new Jose.JoseException("unexpected \"iss\" claim value");
        }
        if (!(payload.get("iss") instanceof String)) throw new IllegalArgumentException("SET invalid: missing or non-string `iss`");
        if (!(payload.get("jti") instanceof String)) throw new IllegalArgumentException("SET invalid: missing or non-string `jti` (RFC 8417 section 2.2 requires it)");
        Map<String, Object> events = parseEvents(payload.get("events"));
        return new ParsedSet(events, (String) payload.get("iss"), (String) payload.get("jti"), payload.get("sub") instanceof String ? (String) payload.get("sub") : null, payload);
    }

    // ---- revocation state ----

    /** A fresh, empty revocation state. */
    public static RevocationState createRevocationState() { return new RevocationState(); }

    /** Object.entries over an events container: a null / absent one throws (as JavaScript does), a non-object has no entries. */
    private static List<Map.Entry<String, Object>> entries(Object events) {
        if (events == null) throw new JsVal.TypeError("Cannot convert undefined or null to object");
        List<Map.Entry<String, Object>> out = new ArrayList<>();
        if (events instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) events).entrySet()) out.add(new java.util.AbstractMap.SimpleEntry<>((String) e.getKey(), e.getValue()));
        }
        return out;
    }

    private static Object eventsOf(Object parsed) {
        return parsed instanceof ParsedSet ? ((ParsedSet) parsed).events : JsVal.member(parsed, "events");
    }

    private static Object payloadOf(Object parsed) {
        return parsed instanceof ParsedSet ? ((ParsedSet) parsed).payload : JsVal.member(parsed, "payload");
    }

    private static double tsOf(Object ev) {
        Object t = JsVal.member(ev, "event_timestamp");
        return JsVal.isNumber(t) ? JsVal.num(t) : 0;
    }

    /**
     * Fold one verified SET into the state. grant-revoked adds its grant_ref to the revoked set; kill-switch revokes every grant
     * of its agent (and any explicit grant_ref); intent-revoked records its pca-intent: ids. Each key keeps the MAX event_timestamp
     * seen, so a stale event never regresses the state and, revocation being monotone, never un-revokes. The two CAEP standard
     * events are folded but do not by themselves revoke a PCA grant. parsed is a {@link ParsedSet} or its JSON form. Returns state.
     */
    public static RevocationState applySET(RevocationState state, Object parsed) {
        for (Map.Entry<String, Object> en : entries(eventsOf(parsed))) {
            String type = en.getKey();
            Object ev = en.getValue();
            double ts = tsOf(ev);
            if (type.equals(GRANT_REVOKED)) {
                Object ref = JsVal.opt(ev, "grant_ref");
                if (JsVal.nonEmpty(ref)) RevocationState.recordMax(state.revokedGrants, (String) ref, ts);
            } else if (type.equals(KILL_SWITCH)) {
                Object agent = JsVal.opt(ev, "agent"), ref = JsVal.opt(ev, "grant_ref");
                if (JsVal.nonEmpty(agent)) RevocationState.recordMax(state.killedAgents, (String) agent, ts);
                if (JsVal.nonEmpty(ref)) RevocationState.recordMax(state.revokedGrants, (String) ref, ts);
            } else if (type.equals(INTENT_REVOKED)) {
                Object ids = JsVal.opt(ev, "ids");
                if (ids instanceof List) {
                    for (Object id : (List<?>) ids) {
                        if (id instanceof String && ((String) id).startsWith("pca-intent:")) {
                            if (state.revokedIntentIds == null) state.revokedIntentIds = new LinkedHashMap<>();
                            RevocationState.recordMax(state.revokedIntentIds, (String) id, ts);
                        }
                    }
                }
            }
        }
        return state;
    }

    /** Has a pushed intent-revoked event named this intent revocation id? (Best effort; the epoch pull bound decides.) */
    public static boolean isIntentRevoked(RevocationState state, Object id) { return state.revokedIntentIds != null && state.revokedIntentIds.containsKey(id); }

    /**
     * Is this grant revoked? True if the grant_ref was revoked directly, or (when agent is given) a kill-switch revoked that agent.
     * The check a resource server runs next to the core verifier: a revoked grant is denied even with a valid, in-budget PCActn.
     */
    public static boolean isRevoked(RevocationState state, Object grantRef, Object agent) {
        if (state.revokedGrants.containsKey(grantRef)) return true;
        return agent != null && state.killedAgents.containsKey(agent);
    }

    private static double setTimestamp(Object parsed) {
        Object events = eventsOf(parsed);
        if (events == null) throw new JsVal.TypeError("Cannot convert undefined or null to object");
        double min = Double.POSITIVE_INFINITY;
        List<Object> values = new ArrayList<>();
        if (events instanceof Map) values.addAll(((Map<?, ?>) events).values());
        else if (events instanceof List) values.addAll((List<?>) events);
        for (Object ev : values) {
            Object t = JsVal.member(ev, "event_timestamp");
            if (JsVal.isNumber(t) && JsVal.num(t) < min) min = JsVal.num(t);
        }
        return Double.isNaN(min) || Double.isInfinite(min) ? 0 : min;
    }

    /**
     * Fold a sequence of verified SETs into one state, applying them in event_timestamp order (ascending). applySET is itself
     * order-independent, so the order makes the fold deterministic whatever order a push stream delivers in. state may be null.
     */
    public static RevocationState streamProcessor(List<?> parsedSets, RevocationState state) {
        RevocationState s = state != null ? state : createRevocationState();
        List<Object> ordered = new ArrayList<>(parsedSets);
        Map<Object, Double> key = new java.util.IdentityHashMap<>();
        for (Object p : ordered) key.put(p, setTimestamp(p));
        ordered.sort((a, b) -> (int) Math.signum(key.get(a) - key.get(b)));
        for (Object p : ordered) applySET(s, p);
        return s;
    }

    // ---- replay store ----

    /**
     * Single-process store, explicitly bounded: state is lost on restart and not shared across processes. When maxEntries live
     * (unexpired) entries are held, a further new jti makes addIfAbsent THROW (receiveSET then refuses with replay_store_error)
     * instead of evicting a live entry, so a flood can never reopen a replay window. opts (may be null): maxEntries.
     */
    public static SetReplayStore createInMemorySetReplayStore(Map<String, Object> opts) {
        Object m = JsVal.or(JsVal.opt(opts, "maxEntries"), new Json.Num(Integer.toString(SET_INMEMORY_MAX_ENTRIES)));
        Double d = JsVal.num(m);
        if (d == null || Double.isNaN(d) || Double.isInfinite(d) || d != Math.rint(d) || d < 1) throw new SignalsError("misconfigured", "maxEntries must be a positive integer");
        final double max = d;
        final Map<String, Double> seen = new LinkedHashMap<>();
        return new SetReplayStore() {
            @Override public synchronized boolean addIfAbsent(String jti, double expiresAtSec, double nowSec) {
                if (!Double.isFinite(nowSec) || !Double.isFinite(expiresAtSec)) return false;
                Double held = seen.get(jti);
                if (held != null && !(nowSec >= held)) return false;
                if (held == null && seen.size() >= max) {
                    seen.values().removeIf(exp -> nowSec >= exp);
                    if (seen.size() >= max) throw new IllegalStateException("replay store is full");
                }
                seen.put(jti, expiresAtSec);
                return true;
            }
        };
    }

    /**
     * Conformance suite for a {@link SetReplayStore}. Returns the list of failed checks (empty = conformant). make returns a FRESH,
     * empty store on each call.
     */
    public static List<String> runSetReplayStoreConformance(Supplier<SetReplayStore> make) throws Exception {
        List<String> failures = new ArrayList<>();
        SetReplayStore s = make.get();
        if (!s.addIfAbsent("a", 200, 100)) failures.add("first sight of a jti returns true");
        if (s.addIfAbsent("a", 200, 101)) failures.add("second sight of the same jti returns false");
        if (!s.addIfAbsent("b", 200, 101)) failures.add("a different jti is independent");
        if (s.addIfAbsent("a", 200, 199)) failures.add("still seen one second before expiry");
        SetReplayStore t = make.get();
        t.addIfAbsent("c", 200, 100);
        if (!t.addIfAbsent("c", 400, 200)) failures.add("an expired entry may be added again (nowSec >= expiresAtSec)");
        SetReplayStore u = make.get();
        ExecutorService ex = Executors.newFixedThreadPool(16);
        int wins = 0;
        try {
            List<Future<Boolean>> fs = new ArrayList<>();
            for (int i = 0; i < 16; i++) { Callable<Boolean> c = () -> u.addIfAbsent("race", 200, 100); fs.add(ex.submit(c)); }
            for (Future<Boolean> f : fs) if (f.get()) wins++;
        } finally {
            ex.shutdown();
        }
        if (wins != 1) failures.add("16 concurrent adds of one jti: exactly one wins (got " + wins + ")");
        return failures;
    }

    // ---- receiver ----

    /** The outcome of {@link #receiveSET}: ok with the parsed SET, or a refusal code and reason. Every refusal is a value, never a throw. */
    public static final class ReceiveSetResult {
        public final boolean ok;
        public final ParsedSet parsed;
        /** misconfigured, oversize, malformed, verify_failed, iat_missing, iat_future, iat_stale, unmapped_subject, replay, replay_store_error. */
        public final String code;
        public final String reason;

        ReceiveSetResult(boolean ok, ParsedSet parsed, String code, String reason) { this.ok = ok; this.parsed = parsed; this.code = code; this.reason = reason; }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", ok);
            if (ok) m.put("parsed", parsed.toMap());
            else { m.put("code", code); m.put("reason", reason); }
            return m;
        }
    }

    private static ReceiveSetResult fails(String code, String reason) { return new ReceiveSetResult(false, null, code, reason); }

    private static String msg(RuntimeException e, String dflt) { return e.getMessage() != null ? e.getMessage() : dflt; }

    /**
     * The recommended receive path: size cap, canonical spelling, EdDSA signature, typ, required iss and aud, iat freshness window,
     * atomic jti replay guard, then fold into state. The jti is recorded only after every other check passed, so a forged token
     * cannot burn a real SET's id. Fails closed on every error, including a replay store that throws (the SET is NOT applied).
     * opts: issuer, audience, replayStore ({@link SetReplayStore}), state ({@link RevocationState}), maxAgeSec (all required),
     * clockSkewSec (default 60), nowSec, maxBytes (default 16384), standardRevocations (a map as for {@link #planStandardRevocations}).
     */
    public static ReceiveSetResult receiveSET(Object set, Object verifyKey, Map<String, Object> opts) {
        if (opts == null || !JsVal.has(opts, "issuer") || !JsVal.has(opts, "audience") || !(opts.get("replayStore") instanceof SetReplayStore)
            || !JsVal.truthy(opts.get("state")) || !JsVal.isFinite(opts.get("maxAgeSec")) || JsVal.num(opts.get("maxAgeSec")) <= 0) {
            return fails("misconfigured", "issuer, audience, replayStore, state and a positive maxAgeSec are all required");
        }
        double maxAge = JsVal.num(opts.get("maxAgeSec"));
        Object maxBytes = JsVal.or(opts.get("maxBytes"), new Json.Num("16384"));
        if (!(set instanceof String) || ((String) set).length() > JsVal.num(maxBytes)) return fails("oversize", "SET is not a string or exceeds maxBytes");
        try {
            Jose.assertCanonicalCompactJws(set);
        } catch (RuntimeException e) {
            return fails("malformed", msg(e, "not a canonical compact JWS"));
        }
        double nowSec = opts.get("nowSec") != null ? JsVal.num(opts.get("nowSec")) : Math.floor((double) System.currentTimeMillis() / 1000);
        ParsedSet parsed;
        try {
            Map<String, Object> vo = new LinkedHashMap<>();
            vo.put("issuer", opts.get("issuer"));
            vo.put("audience", opts.get("audience"));
            vo.put("currentDate", JsVal.numOf(nowSec * 1000));
            parsed = verifySET(set, verifyKey, vo);
        } catch (RuntimeException e) {
            return fails("verify_failed", msg(e, "verification failed"));
        }
        Object iatO = parsed.payload.get("iat");
        if (!JsVal.isFinite(iatO)) return fails("iat_missing", "SET has no numeric iat");
        double iat = JsVal.num(iatO);
        double skew = opts.get("clockSkewSec") != null ? JsVal.num(opts.get("clockSkewSec")) : 60;
        if (!(Double.isFinite(nowSec) && Double.isFinite(skew) && iat <= nowSec + skew)) return fails("iat_future", "SET iat is in the future");
        if (!(nowSec - iat <= maxAge)) return fails("iat_stale", "SET is older than " + JsVal.str(JsVal.numOf(maxAge)) + "s");
        StandardRevocationPlan plan = null;
        if (JsVal.has(opts, "standardRevocations")) {
            try {
                @SuppressWarnings("unchecked") Map<String, Object> so = (Map<String, Object>) opts.get("standardRevocations");
                plan = planStandardRevocations(parsed, so);
            } catch (RuntimeException e) {
                return fails("unmapped_subject", msg(e, "a revocation event could not be mapped to an agent"));
            }
        }
        boolean fresh;
        try {
            fresh = ((SetReplayStore) opts.get("replayStore")).addIfAbsent(parsed.jti, iat + maxAge + skew, nowSec);
        } catch (RuntimeException e) {
            return fails("replay_store_error", msg(e, "replay store failed"));
        }
        if (!fresh) return fails("replay", "jti '" + parsed.jti + "' has already been received");
        RevocationState state = (RevocationState) opts.get("state");
        applySET(state, parsed);
        if (plan != null) applyStandardPlan(state, plan);
        return new ReceiveSetResult(true, parsed, null, null);
    }

    // ---- standard (CAEP / RISC) revocation events ----

    /** What {@link #planStandardRevocations} decided; applying it is a separate, infallible step. */
    public static final class StandardRevocationPlan {
        /** [agent, event_timestamp] pairs to add to killedAgents. */
        public final List<Object[]> agents = new ArrayList<>();
        /** Event types that revoke but whose subject named no known agent (nothing was revoked for them). */
        public final List<String> unmapped = new ArrayList<>();

        public Map<String, Object> toMap() {
            List<Object> a = new ArrayList<>();
            for (Object[] p : agents) { List<Object> pair = new ArrayList<>(); pair.add(p[0]); pair.add(JsVal.numOf((Double) p[1])); a.add(pair); }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("agents", a);
            m.put("unmapped", new ArrayList<Object>(unmapped));
            return m;
        }
    }

    /** Maps an event's RFC 9493 subject to the agent id a PCActn's agentOf yields; returns a non-string / empty value when the subject names no agent. */
    public interface SubjectToAgent { Object apply(Map<String, Object> subject); }

    private static Object defaultSubjectToAgent(Map<String, Object> subject) {
        Object id = subject.get("id");
        return "opaque".equals(subject.get("format")) && JsVal.nonEmpty(id) ? id : null;
    }

    private static boolean isRevokingStandardEvent(String type, Object ev) {
        if (type.equals(SESSION_REVOKED)) return true;
        if (type.equals(CREDENTIAL_CHANGE)) return !"create".equals(JsVal.member(ev, "change_type")); // unknown or absent counts as a change (fail closed)
        return RISC_EVENT_TYPES.containsValue(type);
    }

    /**
     * Decide, without touching any state, which agents a verified SET's standard events revoke: CAEP session-revoked, CAEP
     * credential-change (every change_type except create; an absent or unknown one counts as a change) and the RISC types in
     * {@link #RISC_EVENT_TYPES}. The subject is the event's own subject, else the SET-level sub_id. A revoking event with no subject,
     * or one subjectToAgent cannot map, is listed in unmapped (or throws unmapped_subject under failOnUnmapped).
     * opts (may be null): subjectToAgent ({@link SubjectToAgent}), failOnUnmapped (true to throw).
     */
    @SuppressWarnings("unchecked")
    public static StandardRevocationPlan planStandardRevocations(Object parsed, Map<String, Object> opts) {
        SubjectToAgent toAgent = JsVal.opt(opts, "subjectToAgent") instanceof SubjectToAgent ? (SubjectToAgent) opts.get("subjectToAgent") : Signals::defaultSubjectToAgent;
        StandardRevocationPlan plan = new StandardRevocationPlan();
        Object sid = JsVal.member(payloadOf(parsed), "sub_id");
        Map<String, Object> setSubject = sid instanceof Map ? (Map<String, Object>) sid : null;
        for (Map.Entry<String, Object> en : entries(eventsOf(parsed))) {
            String type = en.getKey();
            Object ev = en.getValue();
            if (!isRevokingStandardEvent(type, ev)) continue;
            Object evSubject = JsVal.member(ev, "subject");
            Map<String, Object> own = evSubject instanceof Map ? (Map<String, Object>) evSubject : setSubject;
            Object agent = null;
            if (own != null && own.get("format") instanceof String) {
                try {
                    agent = toAgent.apply(own);
                } catch (RuntimeException e) {
                    agent = null;
                }
            }
            if (!JsVal.nonEmpty(agent)) {
                if (Boolean.TRUE.equals(JsVal.opt(opts, "failOnUnmapped"))) throw new SignalsError("unmapped_subject", "event '" + type + "' names no mappable agent");
                plan.unmapped.add(type);
                continue;
            }
            plan.agents.add(new Object[] {agent, tsOf(ev)});
        }
        return plan;
    }

    private static void applyStandardPlan(RevocationState state, StandardRevocationPlan plan) {
        for (Object[] p : plan.agents) RevocationState.recordMax(state.killedAgents, (String) p[0], (Double) p[1]);
    }

    private static void assertRevocationState(RevocationState state) {
        if (state == null) throw new SignalsError("misconfigured", "state must come from createRevocationState()");
    }

    /** {@link #planStandardRevocations} then apply: monotone, max-timestamp, like {@link #applySET}. Returns the plan that was applied. */
    public static StandardRevocationPlan applyStandardRevocations(RevocationState state, Object parsed, Map<String, Object> opts) {
        assertRevocationState(state);
        StandardRevocationPlan plan = planStandardRevocations(parsed, opts);
        applyStandardPlan(state, plan);
        return plan;
    }

    // ---- adapters for authorize() ----

    /** A revocation hook over a verification context {pcactn, grant}: returns {enforced: true, ok: true} or {enforced: true, ok: false, reason}. */
    public interface Hook { Map<String, Object> check(Map<String, Object> ctx); }

    private static Object leafHolderAgent(Map<String, Object> ctx) {
        Object chain = JsVal.member(JsVal.member(ctx, "pcactn"), "cap_chain");
        if (chain == null) throw new JsVal.TypeError("cap_chain is missing");
        if (!(chain instanceof List) || ((List<?>) chain).isEmpty()) return null;
        return JsVal.opt(((List<?>) chain).get(((List<?>) chain).size() - 1), "holder");
    }

    private static String revocationReason(RevocationState state, Object pcactn, Object grant, Function<Map<String, Object>, Object> agentOf) {
        try {
            Object ref = JsVal.member(pcactn, "grant_ref");
            if (!JsVal.nonEmpty(ref)) return "grant_ref is missing";
            if (state.revokedGrants.containsKey(ref)) return "grant revoked by signal";
            Object gid = JsVal.opt(grant, "id");
            if (gid instanceof String && state.revokedGrants.containsKey(gid)) return "grant revoked by signal";
            Map<String, Object> ctx = new LinkedHashMap<>();
            ctx.put("pcactn", pcactn);
            ctx.put("grant", grant);
            Object agent = agentOf.apply(ctx);
            if (!JsVal.nonEmpty(agent)) return "agent could not be determined";
            if (state.killedAgents.containsKey(agent)) return "agent killed by signal";
            return null;
        } catch (RuntimeException e) {
            return "revocation check error (fail closed)";
        }
    }

    /**
     * A revocation hook for the core verifier. It reads state LIVE on every call, so SETs folded in by {@link #receiveSET} take effect
     * on the next request. It always reports enforced: true; a revoked grant, a revoked or undeterminable agent, or any error denies.
     * agentOf (null = the PCActn's leaf holder key) names the agent a kill-switch targets.
     */
    public static Hook createRevocationHook(RevocationState state, Function<Map<String, Object>, Object> agentOf) {
        assertRevocationState(state);
        Function<Map<String, Object>, Object> f = agentOf != null ? agentOf : Signals::leafHolderAgent;
        return ctx -> {
            String reason = revocationReason(state, JsVal.opt(ctx, "pcactn"), JsVal.opt(ctx, "grant"), f);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("enforced", true);
            out.put("ok", reason == null);
            if (reason != null) out.put("reason", reason);
            return out;
        };
    }

    /** The same decision in the shape authorizeExecution takes as isRevoked(grant, pcactn): true when revoked or undeterminable (fail closed). */
    public static BiPredicate<Object, Object> createIsRevoked(RevocationState state, Function<Map<String, Object>, Object> agentOf) {
        assertRevocationState(state);
        Function<Map<String, Object>, Object> f = agentOf != null ? agentOf : Signals::leafHolderAgent;
        return (grant, pcactn) -> revocationReason(state, pcactn, grant, f) != null;
    }

    // ---- snapshot / restore ----

    /** Copy state into a plain JSON-safe snapshot {v: 1, grants, agents, intents} for you to persist. An empty state after a restart revokes nothing. */
    public static Map<String, Object> snapshotRevocationState(RevocationState state) {
        assertRevocationState(state);
        Map<String, Object> m = state.toMap();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("v", new Json.Num("1"));
        out.put("grants", m.get("grants"));
        out.put("agents", m.get("agents"));
        out.put("intents", m.get("intents") == null ? new ArrayList<Object>() : m.get("intents"));
        return out;
    }

    private static List<Object[]> pairs(Object v, String what) {
        if (!(v instanceof List)) throw new SignalsError("bad_snapshot", what + " is not an array");
        List<Object[]> out = new ArrayList<>();
        for (Object p : (List<?>) v) {
            if (!(p instanceof List) || ((List<?>) p).size() != 2 || !JsVal.nonEmpty(((List<?>) p).get(0)) || !JsVal.isFinite(((List<?>) p).get(1))) {
                throw new SignalsError("bad_snapshot", what + " holds an entry that is not [string, number]");
            }
            out.add(new Object[] {((List<?>) p).get(0), JsVal.num(((List<?>) p).get(1))});
        }
        return out;
    }

    /**
     * Merge a snapshot into a fresh state. Strict: any shape error throws bad_snapshot. Merging is monotone (max timestamp), so
     * restoring never un-revokes anything.
     */
    public static RevocationState restoreRevocationState(Object snapshot) { return restoreRevocationState(snapshot, createRevocationState()); }

    /** {@link #restoreRevocationState(Object)} into an existing state; when a shape error throws, into is not touched. */
    public static RevocationState restoreRevocationState(Object snapshot, RevocationState into) {
        assertRevocationState(into);
        if (!(snapshot instanceof Map) || !JsVal.isNumber(((Map<?, ?>) snapshot).get("v")) || JsVal.num(((Map<?, ?>) snapshot).get("v")) != 1.0) {
            throw new SignalsError("bad_snapshot", "snapshot is not a version 1 object");
        }
        Map<?, ?> s = (Map<?, ?>) snapshot;
        for (Object k : s.keySet()) {
            if (!List.of("v", "grants", "agents", "intents").contains(k)) throw new SignalsError("bad_snapshot", "snapshot has unknown member '" + k + "'");
        }
        List<Object[]> grants = pairs(s.get("grants"), "grants"), agents = pairs(s.get("agents"), "agents"), intents = pairs(s.get("intents"), "intents");
        for (Object[] p : grants) RevocationState.recordMax(into.revokedGrants, (String) p[0], (Double) p[1]);
        for (Object[] p : agents) RevocationState.recordMax(into.killedAgents, (String) p[0], (Double) p[1]);
        for (Object[] p : intents) {
            if (into.revokedIntentIds == null) into.revokedIntentIds = new LinkedHashMap<>();
            RevocationState.recordMax(into.revokedIntentIds, (String) p[0], (Double) p[1]);
        }
        return into;
    }
}
