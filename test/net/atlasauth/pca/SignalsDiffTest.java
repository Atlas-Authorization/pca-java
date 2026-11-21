package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import net.atlasauth.pca.jose.Jose;
import net.atlasauth.pca.revoke.JsVal;
import net.atlasauth.pca.signals.RevocationState;
import net.atlasauth.pca.signals.SetReplayStore;
import net.atlasauth.pca.signals.Signals;
import net.atlasauth.pca.signals.SignalsError;
import net.atlasauth.pca.signals.SsfManage;
import net.atlasauth.pca.signals.SsfStream;
import org.junit.jupiter.api.Test;

class SignalsDiffTest {
    private static final String M = "ref-signals";
    /** The frozen clock the corpus generator ran under (its header's clockMs). */
    private static final double CLOCK_MS = BaseOracle.clockMs(M);
    private static final Keys.EdKey TX = Keys.edFromSeed(sha("atlas-pca-conformance/ref-signals/tx"));
    private static final Map<String, Object> TX_PUB = jwk(false);
    private static final Map<String, Object> TX_PRIV = jwk(true);
    private static final Pattern UUID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");

    private static byte[] sha(String s) {
        try { return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)); } catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    private static Map<String, Object> jwk(boolean priv) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kty", "OKP");
        m.put("crv", "Ed25519");
        m.put("x", TX.id());
        if (priv) m.put("d", Keys.b64u(TX.seed));
        return m;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object o) { return (Map<String, Object>) o; }

    private static Map<String, Object> err(RuntimeException e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("$err", true);
        if (e instanceof SignalsError) m.put("code", ((SignalsError) e).code);
        return m;
    }

    private static Map<String, Object> plainErr() { Map<String, Object> m = new LinkedHashMap<>(); m.put("$err", true); return m; }

    private static double num(Object o) { return JsVal.num(o); }

    // ---- decode + normalise (a SET built with a random jti and the wall-clock iat) ----

    private static Object parseSeg(String seg) { return Json.parseLenient(new String(Base64.getUrlDecoder().decode(seg), StandardCharsets.UTF_8)); }

    private static Map<String, Object> shape(String set) {
        String[] p = set.split("\\.", -1);
        Map<String, Object> header = map(parseSeg(p[0])), payload = map(parseSeg(p[1]));
        Double iat = JsVal.num(payload.get("iat"));
        if (iat != null && (Math.abs(iat * 1000 - System.currentTimeMillis()) < 120_000 || Math.abs(iat * 1000 - CLOCK_MS) < 120_000)) payload.put("iat", "<now>");
        if (payload.get("jti") instanceof String && UUID.matcher((String) payload.get("jti")).matches()) payload.put("jti", "<uuid>");
        boolean ok;
        try { Jose.compactVerify(set, TX_PUB, List.of("EdDSA")); ok = true; } catch (RuntimeException e) { ok = false; }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("header", header);
        out.put("payload", payload);
        out.put("sigOk", ok);
        return out;
    }

    // ---- named function options ----

    private static Signals.SubjectToAgent mapper(String name) {
        switch (name) {
            case "email": return s -> "email".equals(s.get("format")) && s.get("email") instanceof String ? s.get("email") : null;
            case "throws": return s -> { throw new IllegalStateException("x"); };
            case "empty": return s -> "";
            case "num": return s -> new Json.Num("5");
            case "id": return s -> s.get("id") instanceof String ? s.get("id") : null;
            case "prefixed": return s -> s.get("id") instanceof String ? "agent:" + s.get("id") : null;
            default: throw new IllegalArgumentException(name);
        }
    }

    private static Map<String, Object> stdOpts(Object spec) {
        if (spec == null) return null;
        Map<String, Object> sp = map(spec), out = new LinkedHashMap<>();
        Object mp = sp.get("mapper");
        if (mp != null && !"default".equals(mp)) out.put("subjectToAgent", mapper((String) mp));
        if (sp.containsKey("fail")) out.put("failOnUnmapped", sp.get("fail"));
        return out;
    }

    private static Function<Map<String, Object>, Object> agentOf(Object name) {
        if (name == null || "leaf".equals(name)) return null;
        String n = (String) name;
        if (n.startsWith("const:")) { String c = n.substring(6); return ctx -> c; }
        switch (n) {
            case "throws": return ctx -> { throw new IllegalStateException("x"); };
            case "empty": return ctx -> "";
            case "num": return ctx -> new Json.Num("5");
            case "grantId": return ctx -> JsVal.opt(ctx.get("grant"), "id");
            default: throw new IllegalArgumentException(n);
        }
    }

    // ---- tests ----

    @Test void constants() throws Exception {
        OracleCases.each(M, "constants", a -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("SET_TYP", Signals.SET_TYP);
            m.put("SET_ALG", Signals.SET_ALG);
            m.put("EVENT_TYPES", new LinkedHashMap<String, Object>(Signals.EVENT_TYPES));
            m.put("RISC_EVENT_TYPES", new LinkedHashMap<String, Object>(Signals.RISC_EVENT_TYPES));
            m.put("SET_INMEMORY_MAX_ENTRIES", Signals.SET_INMEMORY_MAX_ENTRIES);
            m.put("DELIVERY_PUSH", SsfStream.DELIVERY_PUSH);
            m.put("DELIVERY_POLL", SsfStream.DELIVERY_POLL);
            m.put("STREAM_STATUSES", new ArrayList<Object>(SsfStream.STREAM_STATUSES));
            return m;
        });
    }

    @Test void verifySET() throws Exception {
        OracleCases.each(M, "verifySET", a -> {
            if (a.get(2) == null) { // an explicit null options value (not an absent one) is dereferenced right after the canonical-spelling gate
                Jose.assertCanonicalCompactJws(a.get(0));
                throw new JsVal.TypeError("Cannot read properties of null (reading 'issuer')");
            }
            return Signals.verifySET(a.get(0), a.get(1), a.get(2) instanceof Map ? map(a.get(2)) : null).toMap();
        });
    }

    @Test void buildSETShape() throws Exception {
        OracleCases.each(M, "buildSETShape", a -> {
            Map<String, Object> args = new LinkedHashMap<>(map(a.get(0)));
            args.put("key", args.remove("keyJwk"));
            return shape(Signals.buildSET(args));
        });
    }

    @Test void stateScenario() throws Exception {
        OracleCases.each(M, "stateScenario", a -> {
            RevocationState st = Signals.createRevocationState();
            List<Object> out = new ArrayList<>();
            for (Object so : (List<?>) map(a.get(0)).get("ops")) {
                Map<String, Object> s = map(so);
                try {
                    RevocationState target = Boolean.TRUE.equals(s.get("badState")) ? null : st;
                    Object r;
                    switch ((String) s.get("op")) {
                        case "apply": Signals.applySET(st, s.get("parsed")); r = st.toMap(); break;
                        case "applyStd": {
                            Map<String, Object> m = new LinkedHashMap<>();
                            m.put("plan", Signals.applyStandardRevocations(target, s.get("parsed"), stdOpts(s.get("std"))).toMap());
                            m.put("state", st.toMap());
                            r = m;
                            break;
                        }
                        case "plan": r = Signals.planStandardRevocations(s.get("parsed"), stdOpts(s.get("std"))).toMap(); break;
                        case "isRevoked": r = Signals.isRevoked(st, s.get("grant"), s.get("agent")); break;
                        case "isIntentRevoked": r = Signals.isIntentRevoked(st, s.get("id")); break;
                        case "stream": r = Signals.streamProcessor((List<?>) s.get("sets"), Boolean.TRUE.equals(s.get("useState")) ? st : null).toMap(); break;
                        case "snapshot": r = Signals.snapshotRevocationState(target); break;
                        case "restore": {
                            RevocationState res = Boolean.TRUE.equals(s.get("fresh")) ? Signals.restoreRevocationState(s.get("snapshot"))
                                : Boolean.TRUE.equals(s.get("nullInto")) ? Signals.restoreRevocationState(s.get("snapshot"), null) : Signals.restoreRevocationState(s.get("snapshot"), target);
                            r = res.toMap();
                            break;
                        }
                        default: throw new IllegalArgumentException("bad op");
                    }
                    out.add(r);
                } catch (RuntimeException e) {
                    out.add(err(e));
                }
            }
            out.add(st.toMap());
            return out;
        });
    }

    @Test void replayScenario() throws Exception {
        OracleCases.each(M, "replayScenario", a -> {
            Map<String, Object> spec = map(a.get(0));
            SetReplayStore store;
            try { store = Signals.createInMemorySetReplayStore(spec.get("opts") instanceof Map ? map(spec.get("opts")) : null); } catch (RuntimeException e) { List<Object> o = new ArrayList<>(); o.add(err(e)); return o; }
            List<Object> out = new ArrayList<>();
            for (Object opO : (List<?>) spec.get("ops")) {
                List<?> op = (List<?>) opO;
                try { out.add(store.addIfAbsent((String) op.get(0), num(op.get(1)), num(op.get(2)))); } catch (RuntimeException e) { out.add(plainErr()); }
            }
            return out;
        });
    }

    @Test void replayConformance() throws Exception {
        OracleCases.each(M, "replayConformance", a -> {
            Map<String, Object> spec = map(a.get(0));
            String kind = (String) spec.get("store");
            Supplier<SetReplayStore> mk;
            switch (kind) {
                case "alwaysTrue": mk = () -> (j, e, n) -> true; break;
                case "alwaysFalse": mk = () -> (j, e, n) -> false; break;
                case "noExpiry": mk = () -> { java.util.Set<String> seen = new java.util.HashSet<>(); return (j, e, n) -> seen.add(j); }; break;
                default: mk = () -> Signals.createInMemorySetReplayStore(spec.get("opts") instanceof Map ? map(spec.get("opts")) : null);
            }
            return new ArrayList<Object>(Signals.runSetReplayStoreConformance(mk));
        });
    }

    @Test void receiveScenario() throws Exception {
        OracleCases.each(M, "receiveScenario", a -> {
            Map<String, Object> spec = map(a.get(0));
            RevocationState st = Signals.createRevocationState();
            String kind = (String) spec.get("store");
            SetReplayStore store;
            if ("throws".equals(kind)) store = (j, e, n) -> { throw new IllegalStateException("boom"); };
            else if ("false".equals(kind)) store = (j, e, n) -> false;
            else if ("mem1".equals(kind)) { Map<String, Object> o = new LinkedHashMap<>(); o.put("maxEntries", new Json.Num("1")); store = Signals.createInMemorySetReplayStore(o); }
            else store = Signals.createInMemorySetReplayStore(null);
            List<Object> out = new ArrayList<>();
            for (Object dO : (List<?>) spec.get("deliveries")) {
                Map<String, Object> d = map(dO);
                Map<String, Object> op = new LinkedHashMap<>(map(d.get("opts")));
                if (!Boolean.TRUE.equals(d.get("noStore"))) op.put("replayStore", store);
                if (!Boolean.TRUE.equals(d.get("noState"))) op.put("state", st);
                if (d.get("std") != null) op.put("standardRevocations", stdOpts(d.get("std")));
                Object key = d.containsKey("key") ? d.get("key") : TX_PUB;
                try {
                    Map<String, Object> r = Signals.receiveSET(d.get("set"), key, Boolean.TRUE.equals(d.get("noOpts")) ? null : op).toMap();
                    if ("verify_failed".equals(r.get("code")) && !String.valueOf(r.get("reason")).startsWith("SET invalid:")) r.put("reason", "<jose>");
                    out.add(r);
                } catch (RuntimeException e) {
                    out.add(plainErr());
                }
            }
            out.add(st.toMap());
            return out;
        });
    }

    @Test void adapterScenario() throws Exception {
        OracleCases.each(M, "adapterScenario", a -> {
            Map<String, Object> spec = map(a.get(0));
            Signals.Hook hook;
            java.util.function.BiPredicate<Object, Object> isRev;
            try {
                RevocationState st = null;
                if (spec.get("badState") == null) {
                    Map<String, Object> snap = new LinkedHashMap<>();
                    snap.put("v", new Json.Num("1"));
                    snap.put("grants", spec.get("grants") != null ? spec.get("grants") : new ArrayList<Object>());
                    snap.put("agents", spec.get("agents") != null ? spec.get("agents") : new ArrayList<Object>());
                    snap.put("intents", new ArrayList<Object>());
                    st = Signals.restoreRevocationState(snap);
                }
                hook = Signals.createRevocationHook(st, agentOf(spec.get("agentOf")));
                isRev = Signals.createIsRevoked(st, agentOf(spec.get("agentOf")));
            } catch (RuntimeException e) {
                List<Object> o = new ArrayList<>();
                o.add(err(e));
                return o;
            }
            List<Object> out = new ArrayList<>();
            for (Object cO : (List<?>) spec.get("calls")) {
                Map<String, Object> c = map(cO);
                Map<String, Object> r = new LinkedHashMap<>();
                try {
                    Map<String, Object> ctx = new LinkedHashMap<>();
                    ctx.put("pcactn", c.get("pcactn"));
                    ctx.put("grant", c.get("grant"));
                    r.put("hook", hook.check(ctx));
                } catch (RuntimeException e) { r.put("hook", plainErr()); }
                try { r.put("isRevoked", isRev.test(c.get("grant"), c.get("pcactn"))); } catch (RuntimeException e) { r.put("isRevoked", plainErr()); }
                out.add(r);
            }
            return out;
        });
    }

    @Test void validateStreamConfig() throws Exception {
        OracleCases.each(M, "validateStreamConfig", a -> new ArrayList<Object>(SsfStream.validateStreamConfig(a.get(0))));
    }

    private static Map<String, Object> defaultStreamConfig() {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("stream_id", "s1");
        c.put("iss", "https://tx.example");
        c.put("aud", "rx");
        c.put("min_verification_interval", new Json.Num("30"));
        return c;
    }

    @Test void healthScenario() throws Exception {
        OracleCases.each(M, "healthScenario", a -> {
            Map<String, Object> spec = map(a.get(0));
            SsfStream.StreamHealth h = new SsfStream.StreamHealth(spec.get("config") != null ? map(spec.get("config")) : defaultStreamConfig(), spec.get("opts") != null ? map(spec.get("opts")) : null);
            List<String> issued = new ArrayList<>();
            List<Object> out = new ArrayList<>();
            for (Object so : (List<?>) spec.get("ops")) {
                Map<String, Object> s = map(so);
                try {
                    Object r;
                    switch ((String) s.get("op")) {
                        case "status": h.setStatus(s.get("v")); r = null; break;
                        case "event": h.recordEvent(num(s.get("now"))); r = null; break;
                        case "request": {
                            String st = h.requestVerification(num(s.get("now")));
                            if (st != null) { issued.add(st); r = "<state:" + (issued.size() - 1) + ">"; } else r = null;
                            break;
                        }
                        case "ack": {
                            Object state = s.containsKey("ref") ? (int) num(s.get("ref")) < issued.size() ? issued.get((int) num(s.get("ref"))) : null : s.get("state");
                            r = h.ackVerification(state, num(s.get("now")));
                            break;
                        }
                        case "report": r = h.report(num(s.get("now"))); break;
                        case "fresh": r = h.revocationFreshWithin(num(s.get("max")), num(s.get("now"))); break;
                        default: throw new IllegalArgumentException("bad op");
                    }
                    out.add(r);
                } catch (RuntimeException e) { out.add(plainErr()); }
            }
            return out;
        });
    }

    @Test void verificationScenario() throws Exception {
        OracleCases.each(M, "verificationScenario", a -> {
            Map<String, Object> spec = map(a.get(0));
            Map<String, Map<String, Object>> streams = new LinkedHashMap<>();
            if (spec.get("streams") != null) for (Map.Entry<String, Object> e : map(spec.get("streams")).entrySet()) streams.put(e.getKey(), map(e.getValue()));
            List<Object> out = new ArrayList<>();
            for (Object so : (List<?>) spec.get("ops")) {
                Map<String, Object> s = map(so);
                try {
                    SsfStream.VerificationOutcome r = SsfStream.handleVerificationRequest(streams, s.get("req"), num(s.get("now")), Boolean.TRUE.equals(s.get("noKey")) ? null : TX_PRIV);
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("status", new Json.Num(Integer.toString(r.status)));
                    if (r.status == 204) m.put("set", shape(r.set)); else m.put("error", r.error);
                    out.add(m);
                } catch (RuntimeException e) { out.add(plainErr()); }
            }
            Map<String, Object> last = new LinkedHashMap<>();
            for (Map.Entry<String, Map<String, Object>> e : streams.entrySet()) last.put(e.getKey(), e.getValue().get("lastVerification"));
            out.add(last);
            return out;
        });
    }

    @Test void pollScenario() throws Exception {
        OracleCases.each(M, "pollScenario", a -> {
            SsfStream.PollQueue q = new SsfStream.PollQueue();
            List<Object> out = new ArrayList<>();
            for (Object so : (List<?>) map(a.get(0)).get("ops")) {
                Map<String, Object> s = map(so);
                try {
                    Object r;
                    if (s.get("enqueue") != null) { List<?> e = (List<?>) s.get("enqueue"); q.enqueue((String) e.get(0), (String) e.get(1)); r = null; }
                    else if (s.get("depth") != null) r = q.depth();
                    else r = q.poll(s.get("poll"));
                    out.add(r);
                } catch (RuntimeException e) { out.add(plainErr()); }
            }
            Map<String, Object> fin = new LinkedHashMap<>();
            fin.put("depth", q.depth());
            fin.put("errors", new ArrayList<Object>(q.errors));
            out.add(fin);
            return out;
        });
    }

    @Test void pushResponse() throws Exception { OracleCases.each(M, "pushResponse", a -> SsfStream.pushResponse(a.get(0))); }

    @Test void caepSET() throws Exception {
        OracleCases.each(M, "caepSET", a -> {
            Map<String, Object> args = new LinkedHashMap<>(map(a.get(0)));
            args.put("key", args.remove("keyJwk"));
            String kind = (String) args.remove("kind");
            return shape("risk".equals(kind) ? SsfStream.riskLevelChangeSET(args) : SsfStream.assuranceLevelChangeSET(args));
        });
    }

    @Test void transmitterMetadata() throws Exception {
        OracleCases.each(M, "transmitterMetadata", a -> {
            Map<String, Object> o = map(a.get(0));
            List<String> dm = null;
            if (o.get("deliveryMethods") != null) { dm = new ArrayList<>(); for (Object x : (List<?>) o.get("deliveryMethods")) dm.add((String) x); }
            return SsfManage.transmitterMetadata((String) o.get("issuer"), dm, (String) a.get(1), (String) a.get(2));
        });
    }

    @SuppressWarnings("unchecked")
    private static Object copy(Object v) {
        if (v instanceof Map) { Map<String, Object> m = new LinkedHashMap<>(); for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) m.put(e.getKey(), copy(e.getValue())); return m; }
        if (v instanceof List) { List<Object> l = new ArrayList<>(); for (Object x : (List<Object>) v) l.add(copy(x)); return l; }
        return v;
    }

    @Test void manageScenario() throws Exception {
        OracleCases.each(M, "manageScenario", a -> {
            Map<String, Object> spec = map(a.get(0));
            SsfManage.MemoryStreamStore store = new SsfManage.MemoryStreamStore();
            List<Object> delivered = new ArrayList<>();
            int[] ids = {0};
            double[] now = {0};
            Object[] rcv = {null};
            SsfManage.Options o = new SsfManage.Options();
            o.store = store;
            o.issuer = "https://tx.example";
            List<String> supported = new ArrayList<>();
            if (spec.get("eventsSupported") != null) for (Object x : (List<?>) spec.get("eventsSupported")) supported.add((String) x);
            else { supported.add(Signals.GRANT_REVOKED); supported.add(Signals.KILL_SWITCH); supported.add(Signals.SESSION_REVOKED); }
            o.eventsSupported = supported;
            o.pollEndpoint = id -> "https://tx.example/poll/" + id;
            o.signingKey = TX_PRIV;
            o.deliver = (stream, set) -> {
                Map<String, Object> d = new LinkedHashMap<>();
                d.put("stream", copy(stream));
                d.put("set", shape(set));
                delivered.add(d);
            };
            o.now = () -> now[0];
            o.newId = () -> "s" + (++ids[0]);
            Map<String, Object> so = spec.get("options") != null ? map(spec.get("options")) : new LinkedHashMap<>();
            if (so.get("maxStreamsPerReceiver") != null) o.maxStreamsPerReceiver = num(so.get("maxStreamsPerReceiver"));
            if (so.get("maxSubjectsPerStream") != null) o.maxSubjectsPerStream = num(so.get("maxSubjectsPerStream"));
            if (so.get("deliveryMethods") != null) { o.deliveryMethods = new ArrayList<>(); for (Object x : (List<?>) so.get("deliveryMethods")) o.deliveryMethods.add((String) x); }
            SsfManage.Handler h = SsfManage.ssfManagementHandler(o, req -> {
                if ("throws".equals(rcv[0])) throw new IllegalStateException("auth");
                return rcv[0] == null ? null : map(rcv[0]);
            });
            List<Object> out = new ArrayList<>();
            for (Object stO : (List<?>) spec.get("steps")) {
                Map<String, Object> st = map(stO);
                now[0] = st.get("now") != null ? num(st.get("now")) : 1000;
                if (st.containsKey("rcv")) rcv[0] = st.get("rcv");
                else { Map<String, Object> r = new LinkedHashMap<>(); r.put("id", "rx1"); r.put("aud", "rx"); rcv[0] = r; }
                out.add(h.handle(st.get("req")));
            }
            Map<String, Object> dump = new LinkedHashMap<>();
            List<?> receivers = spec.get("receivers") != null ? (List<?>) spec.get("receivers") : List.of("rx1", "rx2");
            for (Object rid : receivers) {
                List<Object> list = new ArrayList<>();
                for (Map.Entry<String, Map<String, Object>> e : store.listByReceiver(rid)) { List<Object> pair = new ArrayList<>(); pair.add(e.getKey()); pair.add(e.getValue()); list.add(pair); }
                dump.put((String) rid, list);
            }
            Map<String, Object> fin = new LinkedHashMap<>();
            fin.put("delivered", delivered);
            fin.put("store", dump);
            out.add(fin);
            return out;
        });
    }

    // ---- what the oracle cannot pin: a SET built here verifies here, and the clock-driven paths ----

    @Test void builtSetRoundTrips() {
        Map<String, Object> ev = new LinkedHashMap<>();
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("grant_ref", "g1");
        payload.put("event_timestamp", new Json.Num("100"));
        ev.put(Signals.GRANT_REVOKED, payload);
        Map<String, Object> args = new LinkedHashMap<>();
        args.put("events", ev);
        args.put("issuer", "https://tx.example");
        args.put("audience", "rx");
        args.put("subject", "subj");
        args.put("key", TX_PRIV);
        String set = Signals.buildSET(args);
        Signals.ParsedSet p = Signals.verifySET(set, TX_PUB, null);
        assertEquals("https://tx.example", p.iss);
        assertEquals("subj", p.sub);
        assertNotNull(p.jti);
        RevocationState st = Signals.createRevocationState();
        Map<String, Object> opts = new LinkedHashMap<>();
        opts.put("issuer", "https://tx.example");
        opts.put("audience", "rx");
        opts.put("replayStore", Signals.createInMemorySetReplayStore(null));
        opts.put("state", st);
        opts.put("maxAgeSec", new Json.Num("300"));
        Signals.ReceiveSetResult r = Signals.receiveSET(set, TX_PUB, opts);
        assertTrue(r.ok, r.reason);
        assertTrue(Signals.isRevoked(st, "g1", null));
        assertFalse(Signals.receiveSET(set, TX_PUB, opts).ok);
    }
}
