package net.atlasauth.pca.signals;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.AbstractMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiConsumer;
import java.util.function.DoubleSupplier;
import java.util.function.Function;
import java.util.function.Supplier;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.jose.Jose;
import net.atlasauth.pca.revoke.JsVal;

/**
 * SSF stream management API (OpenID Shared Signals Framework 1.0, sections 8.1 and 7.1): create / read / update (PATCH) / replace
 * (PUT) / delete a stream, read / update its status, add / remove subjects, request a verification event, and the transmitter
 * configuration metadata. Framework-neutral: a request map {method, path, query?, body?} in, a response map {status, body?} out. The
 * HOST authenticates the receiver (SSF 8: "standard HTTP authentication") and passes {id, aud}; a stream belongs to exactly one
 * receiver and anyone else sees 404, never 403. Requests, responses and stream records are JSON objects (Map).
 */
public final class SsfManage {
    private SsfManage() {}

    /**
     * Storage of stream records {receiver, config, events_requested?, status, status_reason?, subjects: {canonical-JSON key: verified},
     * lastVerification?}. get returns a copy (null when absent); put stores a copy.
     */
    public interface StreamStore {
        Map<String, Object> get(String id);
        void put(String id, Map<String, Object> record);
        void delete(String id);
        List<Map.Entry<String, Map<String, Object>>> listByReceiver(Object receiver);
    }

    @SuppressWarnings("unchecked")
    static Object deepCopy(Object v) {
        if (v instanceof Map) {
            Map<String, Object> m = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) m.put(e.getKey(), deepCopy(e.getValue()));
            return m;
        }
        if (v instanceof List) {
            List<Object> l = new ArrayList<>();
            for (Object x : (List<Object>) v) l.add(deepCopy(x));
            return l;
        }
        return v;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> copy(Map<String, Object> m) { return (Map<String, Object>) deepCopy(m); }

    /** The in-memory {@link StreamStore} (structured clones in and out). */
    public static final class MemoryStreamStore implements StreamStore {
        private final Map<String, Map<String, Object>> m = new LinkedHashMap<>();
        @Override public synchronized Map<String, Object> get(String id) { Map<String, Object> r = m.get(id); return r == null ? null : copy(r); }
        @Override public synchronized void put(String id, Map<String, Object> r) { m.put(id, copy(r)); }
        @Override public synchronized void delete(String id) { m.remove(id); }
        @Override public synchronized List<Map.Entry<String, Map<String, Object>>> listByReceiver(Object receiver) {
            List<Map.Entry<String, Map<String, Object>>> out = new ArrayList<>();
            for (Map.Entry<String, Map<String, Object>> e : m.entrySet()) {
                if (Objects.equals(e.getValue().get("receiver"), receiver)) out.add(new AbstractMap.SimpleEntry<>(e.getKey(), copy(e.getValue())));
            }
            return out;
        }
    }

    /** What {@link #ssfManagementHandler} needs. Required: store, issuer, eventsSupported, pollEndpoint, signingKey (a private Ed25519 JWK), deliver, now. */
    public static final class Options {
        public StreamStore store;
        /** The transmitter's issuer URL: equals the iss of every SET (SSF 7.1 issuer). */
        public String issuer;
        /** Event type URIs the transmitter can emit. */
        public List<String> eventsSupported;
        /** Delivery methods offered; null means both. */
        public List<String> deliveryMethods;
        /** Poll endpoint the transmitter assigns to a stream (RFC 8936: transmitter-set). */
        public Function<String, String> pollEndpoint;
        /** Verification SETs are signed with this key (SSF 8.1.4). */
        public Map<String, Object> signingKey;
        /** Hand the verification SET to the stream's delivery (enqueue for poll, POST for push). */
        public BiConsumer<Map<String, Object>, String> deliver;
        /** 1 (default when null) = one stream per receiver: the second create is 409 (SSF 8.1.1.1). */
        public Double maxStreamsPerReceiver;
        public Double maxSubjectsPerStream;
        /** The clock, in epoch seconds. */
        public DoubleSupplier now;
        public Supplier<String> newId;
    }

    private static final List<String> ENDPOINTS = List.of("configuration", "status", "add_subject", "remove_subject", "verification");
    private static final List<String> RECEIVER_SUPPLIED = List.of("events_requested", "delivery", "description");
    private static final List<String> TRANSMITTER_SUPPLIED = List.of("stream_id", "iss", "aud", "events_supported", "events_delivered", "min_verification_interval");

    private static Map<String, Object> resp(int status, Object body, boolean hasBody) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("status", new Json.Num(Integer.toString(status)));
        if (hasBody) r.put("body", body);
        return r;
    }

    private static Map<String, Object> resp(int status, Object body) { return resp(status, body, true); }

    private static Map<String, Object> err(String error) { Map<String, Object> m = new LinkedHashMap<>(); m.put("error", error); return m; }

    private static Map<String, Object> err(String error, String description) { Map<String, Object> m = err(error); m.put("description", description); return m; }

    private static Map<String, Object> bad(String m) { return resp(400, err("invalid_request", m)); }

    private static Map<String, Object> notFound() { return resp(404, err("not_found")); }

    private static Map<String, Object> notAllowed() { return resp(405, err("method_not_allowed")); }

    private static boolean isRec(Object x) { return x instanceof Map; }

    /** Object.keys order of a key set: integer-like keys ascending first, then the rest in the given order. */
    private static List<String> jsKeyOrder(List<String> keys) {
        List<String> idx = new ArrayList<>(), rest = new ArrayList<>();
        for (String k : keys) {
            boolean index = !k.isEmpty() && k.length() <= 10 && (k.length() == 1 || k.charAt(0) != '0');
            for (int i = 0; index && i < k.length(); i++) if (k.charAt(i) < '0' || k.charAt(i) > '9') index = false;
            if (index && Long.parseLong(k) < 4294967295L) idx.add(k); else rest.add(k);
        }
        idx.sort((a, b) -> Long.compare(Long.parseLong(a), Long.parseLong(b)));
        idx.addAll(rest);
        return idx;
    }

    @SuppressWarnings("unchecked")
    private static String subjectKey(Object s) {
        if (!isRec(s) || !(((Map<?, ?>) s).get("format") instanceof String) || ((String) ((Map<?, ?>) s).get("format")).isEmpty()) return null;
        Map<String, Object> m = (Map<String, Object>) s;
        List<String> keys = new ArrayList<>(m.keySet());
        keys.sort(String::compareTo); // the reference compares with < (UTF-16 code units)
        Map<String, Object> o = new LinkedHashMap<>();
        for (String k : jsKeyOrder(keys)) o.put(k, m.get(k));
        return Jose.stringify(o);
    }

    /** SSF 7.1 transmitter configuration metadata (served at /.well-known/ssf-configuration). deliveryMethods and jwksUri may be null. */
    public static Map<String, Object> transmitterMetadata(String issuer, List<String> deliveryMethods, String base, String jwksUri) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("spec_version", "1_0");
        m.put("issuer", issuer);
        if (jwksUri != null && !jwksUri.isEmpty()) m.put("jwks_uri", jwksUri);
        m.put("delivery_methods_supported", new ArrayList<Object>(deliveryMethods != null ? deliveryMethods : List.of(SsfStream.DELIVERY_PUSH, SsfStream.DELIVERY_POLL)));
        m.put("configuration_endpoint", base + "/ssf/configuration");
        m.put("status_endpoint", base + "/ssf/status");
        m.put("add_subject_endpoint", base + "/ssf/add_subject");
        m.put("remove_subject_endpoint", base + "/ssf/remove_subject");
        m.put("verification_endpoint", base + "/ssf/verification");
        m.put("default_subjects", "NONE");
        return m;
    }

    /** Authenticates a request: returns the receiver {id, aud}, or null when unauthenticated. May throw (the handler answers 500). */
    public interface Authenticate { Map<String, Object> apply(Object req); }

    /** The request handler returned by {@link #ssfManagementHandler}: never throws; a failure answers 500. */
    public interface Handler { Map<String, Object> handle(Object req); }

    private static final SecureRandom RNG = new SecureRandom();

    /**
     * The SSF management endpoints as one handler. Routes on the last path segment (configuration, status, add_subject,
     * remove_subject, verification) and the method. 401 when authenticate yields no receiver, 500 on any failure.
     */
    @SuppressWarnings("unchecked")
    public static Handler ssfManagementHandler(Options o, Authenticate authenticate) {
        final List<String> methods = o.deliveryMethods != null ? o.deliveryMethods : List.of(SsfStream.DELIVERY_PUSH, SsfStream.DELIVERY_POLL);
        final Supplier<String> newId = o.newId != null ? o.newId : () -> { byte[] b = new byte[12]; RNG.nextBytes(b); return Keys.b64u(b); };
        final double maxStreams = o.maxStreamsPerReceiver != null ? o.maxStreamsPerReceiver : 1;

        class Core {
            Map<String, Object> own(Map<String, Object> rcv, Object id) {
                if (!(id instanceof String)) return null;
                Map<String, Object> r = o.store.get((String) id);
                return r != null && Objects.equals(r.get("receiver"), rcv.get("id")) ? r : null;
            }

            List<Object> delivered(List<?> requested) {
                List<Object> out = new ArrayList<>();
                for (String e : o.eventsSupported) if (requested == null || requested.contains(e)) out.add(e);
                return out;
            }

            boolean eventsRequestedOk(Object v) {
                if (!(v instanceof List) || ((List<?>) v).isEmpty()) return false;
                for (Object e : (List<?>) v) if (!JsVal.nonEmpty(e)) return false;
                return true;
            }

            /** [ok, delivery map | why]. present = the member exists (undefined is absent; null is a value). */
            Object[] deliveryFor(String id, boolean present, Object d) {
                if (!present) {
                    if (!methods.contains(SsfStream.DELIVERY_POLL)) return new Object[] {false, "delivery is required: this transmitter does not support poll"};
                    return new Object[] {true, delivery(SsfStream.DELIVERY_POLL, o.pollEndpoint.apply(id))};
                }
                if (!isRec(d) || !(((Map<?, ?>) d).get("method") instanceof String) || !methods.contains(((Map<?, ?>) d).get("method"))) return new Object[] {false, "delivery.method is not supported by this transmitter"};
                Map<?, ?> dm = (Map<?, ?>) d;
                if (SsfStream.DELIVERY_POLL.equals(dm.get("method"))) return new Object[] {true, delivery(SsfStream.DELIVERY_POLL, o.pollEndpoint.apply(id))}; // transmitter-set; a receiver value is ignored
                if (!SsfStream.httpsUrl(dm.get("endpoint_url"))) return new Object[] {false, "push delivery needs an https endpoint_url"};
                return new Object[] {true, delivery(SsfStream.DELIVERY_PUSH, (String) dm.get("endpoint_url"))};
            }

            Map<String, Object> delivery(String method, String url) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("method", method);
                m.put("endpoint_url", url);
                return m;
            }

            Map<String, Object> build(String id, Map<String, Object> rcv, List<?> requested, Object delivery, String description) {
                Map<String, Object> c = new LinkedHashMap<>();
                c.put("stream_id", id);
                c.put("iss", o.issuer);
                c.put("aud", rcv.get("aud"));
                c.put("events_supported", new ArrayList<Object>(o.eventsSupported));
                c.put("events_delivered", delivered(requested));
                c.put("delivery", delivery);
                if (description != null) c.put("description", description.length() > 256 ? description.substring(0, 256) : description);
                return c;
            }

            Map<String, Object> route(Object req, Map<String, Object> rcv) {
                Object path = JsVal.member(req, "path");
                if (!(path instanceof String)) throw new JsVal.TypeError("path.split is not a function");
                String seg = "";
                for (String part : ((String) path).split("/", -1)) if (!part.isEmpty()) seg = part;
                Object q = JsVal.opt(req, "query") != null ? JsVal.opt(req, "query") : new LinkedHashMap<String, Object>();
                Map<String, Object> b = isRec(JsVal.opt(req, "body")) ? (Map<String, Object>) JsVal.opt(req, "body") : null;
                Object mO = JsVal.opt(req, "method");
                if (!(mO instanceof String)) throw new JsVal.TypeError("req.method.toUpperCase is not a function");
                String m = ((String) mO).toUpperCase(java.util.Locale.ROOT);
                if (!ENDPOINTS.contains(seg)) return resp(404, err("not_found"));
                boolean hasQid = JsVal.has(q, "stream_id");
                Object qid = JsVal.opt(q, "stream_id");

                if (seg.equals("configuration")) {
                    if (m.equals("POST")) { // 8.1.1.1
                        if (b == null) return bad("a JSON object body is required");
                        for (String k : jsKeyOrder(new ArrayList<>(b.keySet()))) if (!RECEIVER_SUPPLIED.contains(k)) return bad("'" + k + "' is not a receiver-supplied member");
                        if (b.containsKey("events_requested") && !eventsRequestedOk(b.get("events_requested"))) return bad("events_requested must be a non-empty array of event type URIs");
                        if (b.containsKey("description") && !(b.get("description") instanceof String)) return bad("description must be a string");
                        if (!(o.store.listByReceiver(rcv.get("id")).size() < maxStreams)) return resp(409, err("conflict", "this receiver already has the maximum number of streams"));
                        String id = newId.get();
                        Object[] d = deliveryFor(id, b.containsKey("delivery"), b.get("delivery"));
                        if (!(Boolean) d[0]) return bad((String) d[1]);
                        List<?> requested = b.containsKey("events_requested") ? (List<?>) b.get("events_requested") : null;
                        if (delivered(requested).isEmpty()) return bad("none of events_requested is supported by this transmitter");
                        Map<String, Object> config = build(id, rcv, requested, d[1], (String) b.get("description"));
                        List<String> problems = SsfStream.validateStreamConfig(config);
                        if (!problems.isEmpty()) return bad(String.join("; ", problems));
                        Map<String, Object> rec = new LinkedHashMap<>();
                        rec.put("receiver", rcv.get("id"));
                        rec.put("config", config);
                        if (JsVal.truthy(b.get("events_requested"))) rec.put("events_requested", b.get("events_requested"));
                        rec.put("status", "enabled");
                        rec.put("subjects", new LinkedHashMap<String, Object>());
                        o.store.put(id, rec);
                        return resp(201, config);
                    }
                    if (m.equals("GET")) { // 8.1.1.2
                        if (!hasQid) {
                            List<Object> out = new ArrayList<>();
                            for (Map.Entry<String, Map<String, Object>> e : o.store.listByReceiver(rcv.get("id"))) out.add(e.getValue().get("config"));
                            return resp(200, out);
                        }
                        Map<String, Object> s = own(rcv, qid);
                        return s != null ? resp(200, s.get("config")) : notFound();
                    }
                    if (m.equals("PATCH") || m.equals("PUT")) { // 8.1.1.3 / 8.1.1.4
                        if (b == null) return bad("a JSON object body is required");
                        Map<String, Object> s = own(rcv, b.get("stream_id"));
                        if (!(b.get("stream_id") instanceof String)) return bad("stream_id is required");
                        if (s == null) return notFound();
                        for (String k : jsKeyOrder(new ArrayList<>(b.keySet()))) if (!RECEIVER_SUPPLIED.contains(k) && !TRANSMITTER_SUPPLIED.contains(k)) return bad("unknown member '" + k + "'");
                        // Transmitter-supplied members may be present but must equal the expected value, checked BEFORE any update is applied.
                        Map<String, Object> cfg = (Map<String, Object>) s.get("config");
                        for (String k : TRANSMITTER_SUPPLIED) {
                            if (!b.containsKey(k)) continue;
                            if (!cfg.containsKey(k) || !Jose.stringify(b.get(k)).equals(Jose.stringify(cfg.get(k)))) return bad("'" + k + "' is transmitter-supplied and does not match");
                        }
                        if (b.containsKey("events_requested") && !eventsRequestedOk(b.get("events_requested"))) return bad("events_requested must be a non-empty array of event type URIs");
                        if (b.containsKey("description") && !(b.get("description") instanceof String)) return bad("description must be a string");
                        Object delivery = cfg.get("delivery");
                        if (b.containsKey("delivery") || m.equals("PUT")) { // PUT: a missing delivery is a deleted one, i.e. the default
                            Object[] d = deliveryFor((String) cfg.get("stream_id"), b.containsKey("delivery"), b.get("delivery"));
                            if (!(Boolean) d[0]) return bad((String) d[1]);
                            Map<String, Object> nd = (Map<String, Object>) d[1];
                            if (!Objects.equals(nd.get("method"), ((Map<String, Object>) cfg.get("delivery")).get("method"))) return bad("delivery.method cannot be changed: create a new stream");
                            delivery = nd;
                        }
                        Object requested = m.equals("PUT") ? b.get("events_requested") : b.containsKey("events_requested") ? b.get("events_requested") : s.get("events_requested");
                        Object description = m.equals("PUT") ? b.get("description") : b.containsKey("description") ? b.get("description") : cfg.get("description");
                        if (delivered((List<?>) requested).isEmpty()) return bad("none of events_requested is supported by this transmitter");
                        Map<String, Object> next = build((String) cfg.get("stream_id"), rcv, (List<?>) requested, delivery, (String) description);
                        if (cfg.containsKey("min_verification_interval")) next.put("min_verification_interval", cfg.get("min_verification_interval"));
                        s.put("config", next);
                        if (JsVal.truthy(requested)) s.put("events_requested", requested); else s.remove("events_requested");
                        o.store.put((String) next.get("stream_id"), s);
                        return resp(200, next);
                    }
                    if (m.equals("DELETE")) { // 8.1.1.5
                        Map<String, Object> s = own(rcv, qid);
                        if (s == null) return notFound();
                        o.store.delete((String) qid);
                        return resp(204, null, false);
                    }
                    return notAllowed();
                }

                if (seg.equals("status")) { // 8.1.2
                    if (m.equals("GET")) {
                        Map<String, Object> s = own(rcv, qid);
                        if (s == null) return !hasQid ? bad("stream_id is required") : notFound();
                        return resp(200, statusBody(qid, s));
                    }
                    if (m.equals("POST")) {
                        if (b == null || !(b.get("stream_id") instanceof String)) return bad("stream_id is required");
                        if (!SsfStream.STREAM_STATUSES.contains(b.get("status"))) return bad("status must be 'enabled', 'paused' or 'disabled'");
                        if (b.containsKey("reason") && !(b.get("reason") instanceof String)) return bad("reason must be a string");
                        Map<String, Object> s = own(rcv, b.get("stream_id"));
                        if (s == null) return notFound();
                        s.put("status", b.get("status"));
                        if (b.containsKey("reason")) s.put("status_reason", b.get("reason")); else s.remove("status_reason");
                        o.store.put((String) b.get("stream_id"), s);
                        return resp(200, statusBody(b.get("stream_id"), s));
                    }
                    return notAllowed();
                }

                if (seg.equals("add_subject") || seg.equals("remove_subject")) { // 8.1.3
                    if (!m.equals("POST")) return notAllowed();
                    if (b == null || !(b.get("stream_id") instanceof String)) return bad("stream_id is required");
                    String key = subjectKey(b.get("subject"));
                    if (key == null) return bad("subject must be a Subject Identifier object with a format");
                    if (b.containsKey("verified") && !(b.get("verified") instanceof Boolean)) return bad("verified must be a boolean");
                    Map<String, Object> s = own(rcv, b.get("stream_id"));
                    if (s == null) return notFound();
                    Map<String, Object> subjects = (Map<String, Object>) s.get("subjects");
                    if (seg.equals("add_subject")) {
                        double maxSubjects = o.maxSubjectsPerStream != null ? o.maxSubjectsPerStream : 10_000;
                        if (!subjects.containsKey(key) && subjects.size() >= maxSubjects) return resp(429, err("too_many_requests", "subject limit reached"));
                        subjects.put(key, b.get("verified") != null ? b.get("verified") : Boolean.TRUE); // SSF: SHOULD assume verified when omitted
                        o.store.put((String) b.get("stream_id"), s);
                        return resp(200, null, false);
                    }
                    subjects.remove(key); // an unknown subject is silently ignored (204)
                    o.store.put((String) b.get("stream_id"), s);
                    return resp(204, null, false);
                }

                // verification (8.1.4.2)
                if (!m.equals("POST")) return notAllowed();
                if (b == null) return bad("a JSON object body is required");
                Map<String, Object> s = own(rcv, b.get("stream_id"));
                if (s == null) return b.get("stream_id") instanceof String ? notFound() : bad("stream_id is required");
                if ("disabled".equals(s.get("status"))) return bad("the stream is disabled");
                Map<String, Object> cfg = (Map<String, Object>) s.get("config");
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("config", cfg);
                if (s.containsKey("lastVerification")) entry.put("lastVerification", s.get("lastVerification"));
                Map<String, Map<String, Object>> view = new LinkedHashMap<>();
                view.put((String) cfg.get("stream_id"), entry);
                Map<String, Object> vreq = new LinkedHashMap<>();
                vreq.put("stream_id", b.get("stream_id"));
                if (b.containsKey("state")) vreq.put("state", b.get("state"));
                SsfStream.VerificationOutcome out = SsfStream.handleVerificationRequest(view, vreq, o.now.getAsDouble(), o.signingKey);
                if (out.status != 204) return resp(out.status, err(out.status == 429 ? "too_many_requests" : "invalid_request", out.error));
                s.put("lastVerification", JsVal.numOf(o.now.getAsDouble()));
                o.store.put((String) cfg.get("stream_id"), s);
                o.deliver.accept(s, out.set);
                return resp(204, null, false);
            }

            Map<String, Object> statusBody(Object id, Map<String, Object> s) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("stream_id", id);
                m.put("status", s.get("status"));
                if (s.containsKey("status_reason")) m.put("reason", s.get("status_reason"));
                return m;
            }
        }
        final Core core = new Core();
        return req -> {
            try {
                Map<String, Object> rcv = authenticate.apply(req);
                if (rcv == null) return resp(401, err("unauthenticated"));
                return core.route(req, rcv);
            } catch (RuntimeException e) {
                return resp(500, err("server_error"));
            }
        };
    }
}
