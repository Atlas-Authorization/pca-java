package net.atlasauth.pca;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Supplier;

/**
 * The wire codec, per-peer inbox, in-memory network and party driver of the FROST DKG. A message is one strict-JSON envelope
 * {v, sid, kind, body} of at most 256 KiB bound to its session; the inbox keeps the first message per (kind, sender) and makes every
 * duplicate, equivocation or malformed message from a peer a sticky failure of that peer; {@link #runDkgOverChannel} runs one
 * participant's whole ceremony over any {@link DkgChannel}. Packages and messages are the same JSON-shaped maps as in {@link FrostDkg}.
 */
public final class FrostDkgChannel {
    private FrostDkgChannel() {}

    public static final int DKG_WIRE_VERSION = 1;
    public static final int DKG_MAX_MESSAGE_BYTES = 256 * 1024;
    public static final int DKG_MAX_PARTICIPANTS = 256;
    public static final List<String> DKG_MESSAGE_KINDS = List.of("round1", "share", "complaints", "rebuttals", "echo");

    /** A channel failure with a stable code: timeout, identity, wrong-session, duplicate, equivocation, malformed, oversize, closed, protocol, disqualified. */
    public static final class DkgChannelError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public final String code;
        /** The peer the failure is attributed to, or null. */
        public final Long peer;
        public final String detail;
        public DkgChannelError(String code, Long peer, String detail) {
            super("dkg channel (" + code + (peer == null ? "" : ", peer " + peer) + "): " + detail);
            this.code = code; this.peer = peer; this.detail = detail;
        }
    }

    /** One participant's view of the network. {@code collect} returns the bodies by authenticated sender, ascending by id. */
    public interface DkgChannel {
        long self();
        List<Long> peers();
        void broadcast(String kind, Object body);
        void send(long to, String kind, Object body);
        Map<Long, Object> collect(String kind, List<Long> from, double timeoutMs);
        void close();
    }

    // ---- codec -------------------------------------------------------------------------------------------------------

    private static String b64u(Object bytes) {
        if (!(bytes instanceof byte[])) throw new IllegalArgumentException("radix2.encode input should be Uint8Array");
        return Pca.b64((byte[]) bytes);
    }

    public static byte[] encodeDkgMessage(Object sessionId, Object kind, Object body) {
        Map<String, Object> env = new LinkedHashMap<>();
        env.put("v", DKG_WIRE_VERSION);
        env.put("sid", b64u(sessionId));
        env.put("kind", kind);
        env.put("body", body);
        byte[] bytes = Json.stringify(env).getBytes(StandardCharsets.UTF_8);
        if (bytes.length > DKG_MAX_MESSAGE_BYTES) throw new DkgChannelError("oversize", null, "message of " + bytes.length + " bytes exceeds the cap");
        return bytes;
    }

    /** Strict decode: size cap, valid UTF-8 and strict JSON, exactly the four members, wire version 1, a known kind and this session. Returns {kind, body}. */
    public static Map<String, Object> decodeDkgMessage(Object bytesO, Object sessionId) {
        if (!(bytesO instanceof byte[])) throw new DkgChannelError("malformed", null, "message is not bytes");
        byte[] bytes = (byte[]) bytesO;
        if (bytes.length > DKG_MAX_MESSAGE_BYTES) throw new DkgChannelError("oversize", null, "message of " + bytes.length + " bytes exceeds the cap");
        Object msg;
        try {
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes)).toString();
            msg = Json.parse(text);
        } catch (CharacterCodingException | RuntimeException e) {
            throw new DkgChannelError("malformed", null, "message is not strict JSON");
        }
        Map<String, Object> o = asRecord(msg, new String[] { "v", "sid", "kind", "body" }, "envelope");
        Object v = o.get("v");
        if (!(v instanceof Json.Num || v instanceof Number) || IntentJs.num(v) == null || IntentJs.num(v) != (double) DKG_WIRE_VERSION) throw new DkgChannelError("malformed", null, "unsupported wire version");
        if (!(o.get("kind") instanceof String) || !DKG_MESSAGE_KINDS.contains(o.get("kind"))) throw new DkgChannelError("malformed", null, "unknown message kind");
        if (!b64u(sessionId).equals(o.get("sid"))) throw new DkgChannelError("wrong-session", null, "message names another session");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("kind", o.get("kind"));
        out.put("body", o.get("body"));
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asRecord(Object x, String[] keys, String what) {
        if (!(x instanceof Map)) throw new DkgChannelError("malformed", null, what + " is not an object");
        Map<String, Object> m = (Map<String, Object>) x;
        if (m.size() != keys.length) throw new DkgChannelError("malformed", null, what + " has unexpected or missing members");
        for (String k : keys) if (!m.containsKey(k)) throw new DkgChannelError("malformed", null, what + " has unexpected or missing members");
        return m;
    }

    private static long posInt(Object x, String what) {
        if (!(x instanceof Json.Num || x instanceof Number) || !IntentJs.isSafeInteger(x) || IntentJs.num(x) <= 0) throw new DkgChannelError("malformed", null, what + " is not a positive integer");
        return IntentJs.lng(x);
    }

    private static String b64Field(Object x, String what, int len) {
        if (Pca.decodeB64uStrict(x, len) == null) throw new DkgChannelError("malformed", null, what + " is not canonical base64url");
        return (String) x;
    }

    private static Map<String, Object> mapOf(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    /** A round-1 package that commits to exactly t coefficients (32-byte points) with a 32-byte R and mu. */
    public static Map<String, Object> decodeDkgRound1Package(Object x, Object t) {
        Map<String, Object> o = asRecord(x, new String[] { "identifier", "sessionId", "coefficientCommitments", "proofOfKnowledge" }, "round-1 package");
        Map<String, Object> pok = asRecord(o.get("proofOfKnowledge"), new String[] { "R", "mu" }, "proof of knowledge");
        Object cc = o.get("coefficientCommitments");
        Double td = IntentJs.num(t);
        if (!(cc instanceof List) || td == null || ((List<?>) cc).size() != td) throw new DkgChannelError("malformed", null, "round-1 package must commit to exactly t=" + AttestNvidia.jsString(t) + " coefficients");
        long id = posInt(o.get("identifier"), "identifier");
        String sid = b64Field(o.get("sessionId"), "sessionId", -1);
        List<Object> cs = new ArrayList<>();
        for (Object c : (List<?>) cc) cs.add(b64Field(c, "coefficient commitment", 32));
        return mapOf("identifier", id, "sessionId", sid, "coefficientCommitments", cs,
            "proofOfKnowledge", mapOf("R", b64Field(pok.get("R"), "PoP R", 32), "mu", b64Field(pok.get("mu"), "PoP mu", 32)));
    }

    /** A share message {from, to, sessionId, share (decoded to 32 bytes), sig}. */
    public static Map<String, Object> decodeDkgShareMessage(Object x) {
        Map<String, Object> o = asRecord(x, new String[] { "from", "to", "sessionId", "share", "sig" }, "share message");
        long from = posInt(o.get("from"), "from"), to = posInt(o.get("to"), "to");
        String sid = b64Field(o.get("sessionId"), "sessionId", -1);
        byte[] share = Pca.decodeB64uStrict(b64Field(o.get("share"), "share", 32), -1);
        String sig = b64Field(o.get("sig"), "share signature", 64);
        return mapOf("from", from, "to", to, "sessionId", sid, "share", share, "sig", sig);
    }

    private static Map<String, Object> complaintOf(Object x) {
        Map<String, Object> o = asRecord(x, new String[] { "accused", "accuser", "sessionId", "revealedShare", "shareSig" }, "complaint");
        return mapOf("accused", posInt(o.get("accused"), "accused"), "accuser", posInt(o.get("accuser"), "accuser"), "sessionId", b64Field(o.get("sessionId"), "sessionId", -1),
            "revealedShare", b64Field(o.get("revealedShare"), "revealed share", 32), "shareSig", b64Field(o.get("shareSig"), "share signature", 64));
    }

    private static Map<String, Object> rebuttalOf(Object x) {
        Map<String, Object> o = asRecord(x, new String[] { "accused", "accuser", "sessionId", "presentedShare", "shareSig" }, "rebuttal");
        return mapOf("accused", posInt(o.get("accused"), "accused"), "accuser", posInt(o.get("accuser"), "accuser"), "sessionId", b64Field(o.get("sessionId"), "sessionId", -1),
            "presentedShare", b64Field(o.get("presentedShare"), "presented share", 32), "shareSig", b64Field(o.get("shareSig"), "share signature", 64));
    }

    private static List<Object> listOf(Object x, String key, java.util.function.Function<Object, Map<String, Object>> one) {
        Map<String, Object> o = asRecord(x, new String[] { key }, key);
        Object l = o.get(key);
        if (!(l instanceof List) || ((List<?>) l).size() > DKG_MAX_PARTICIPANTS) throw new DkgChannelError("malformed", null, key + " is not a bounded list");
        List<Object> out = new ArrayList<>();
        for (Object e : (List<?>) l) out.add(one.apply(e));
        return out;
    }

    public static List<Object> decodeDkgComplaints(Object x) { return listOf(x, "complaints", FrostDkgChannel::complaintOf); }

    public static List<Object> decodeDkgRebuttals(Object x) { return listOf(x, "rebuttals", FrostDkgChannel::rebuttalOf); }

    public static Map<String, Object> decodeDkgEcho(Object x) {
        Map<String, Object> o = asRecord(x, new String[] { "identifier", "sessionId", "transcriptDigest" }, "echo");
        return mapOf("identifier", posInt(o.get("identifier"), "identifier"), "sessionId", b64Field(o.get("sessionId"), "sessionId", -1),
            "transcriptDigest", b64Field(o.get("transcriptDigest"), "transcript digest", 32));
    }

    // ---- inbox -----------------------------------------------------------------------------------------------------------

    private static final class Seen {
        final String digest;
        final Object body;
        Seen(String digest, Object body) { this.digest = digest; this.body = body; }
    }

    /**
     * Messages received for one session from a fixed peer set. The first message per (kind, sender) is kept; a second identical one is a
     * duplicate and a second different one an equivocation, and every failure of a peer is sticky (the first one wins). Senders are the
     * transport-authenticated ids, never a claim inside a message.
     */
    public static final class DkgInbox {
        private final Map<String, Seen> seen = new HashMap<>();
        private final Map<Long, DkgChannelError> errors = new HashMap<>();
        private final Set<Long> gone = new HashSet<>();
        private boolean closed;
        public final byte[] sessionId;
        public final List<Long> peers;

        public DkgInbox(byte[] sessionId, List<Long> peers) { this.sessionId = sessionId; this.peers = peers; }

        public synchronized void fail(long peer, DkgChannelError err) {
            if (!errors.containsKey(peer)) errors.put(peer, new DkgChannelError(err.code, peer, err.detail));
            notifyAll();
        }

        public synchronized void accept(long sender, Object bytes) {
            if (!peers.contains(sender)) return; // not a participant: nothing to attribute to
            try {
                Map<String, Object> d = decodeDkgMessage(bytes, sessionId);
                String kind = (String) d.get("kind");
                String key = kind + "\u0000" + sender;
                String digest = Pca.b64((byte[]) bytes);
                Seen prev = seen.get(key);
                if (prev != null) throw new DkgChannelError(prev.digest.equals(digest) ? "duplicate" : "equivocation", sender, "second " + kind + " message");
                seen.put(key, new Seen(digest, d.get("body")));
                notifyAll();
            } catch (RuntimeException e) {
                fail(sender, e instanceof DkgChannelError ? (DkgChannelError) e : new DkgChannelError("malformed", sender, "undecodable message"));
            }
        }

        public synchronized void peerGone(long peer) { gone.add(peer); notifyAll(); }

        public synchronized void close() { closed = true; notifyAll(); }

        /** The bodies of {@code kind} from every id in {@code from}; a peer failure, a closed channel, a vanished link or the deadline is an error. */
        public synchronized Map<Long, Object> collect(String kind, List<Long> from, double timeoutMs) {
            List<Long> want = new ArrayList<>(from);
            Collections.sort(want);
            long deadline = System.nanoTime() + (long) (timeoutMs * 1_000_000.0);
            for (;;) {
                for (Long id : want) {
                    DkgChannelError e = errors.get(id);
                    if (e != null) throw e;
                }
                Map<Long, Object> out = new TreeMap<>();
                for (Long id : want) {
                    Seen m = seen.get(kind + "\u0000" + id);
                    if (m != null) out.put(id, m.body);
                }
                if (out.size() == want.size()) return out;
                if (closed) throw new DkgChannelError("closed", null, "channel closed before all messages arrived");
                for (Long id : want) {
                    if (!out.containsKey(id) && gone.contains(id)) throw new DkgChannelError("closed", id, "link ended before its " + kind + " message arrived");
                }
                long leftNs = deadline - System.nanoTime();
                if (leftNs <= 0) {
                    List<Long> missing = new ArrayList<>();
                    StringBuilder names = new StringBuilder();
                    for (Long id : want) if (!out.containsKey(id)) { if (names.length() > 0) names.append(','); names.append(id); missing.add(id); }
                    throw new DkgChannelError("timeout", missing.get(0), "no " + kind + " message from " + names);
                }
                try {
                    wait(leftNs / 1_000_000L, (int) (leftNs % 1_000_000L));
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new DkgChannelError("closed", null, "interrupted");
                }
            }
        }
    }

    // ---- in-memory network ------------------------------------------------------------------------------------------------

    /** A hook over every routed message: return the bytes to deliver (the same, or altered) or null to drop it. */
    public interface Intercept { byte[] apply(long from, long to, String kind, byte[] bytes); }

    public static final class MemoryDkgNetwork {
        public final Map<Long, DkgChannel> channels;
        private final Map<Long, DkgInbox> inboxes;
        MemoryDkgNetwork(Map<Long, DkgChannel> channels, Map<Long, DkgInbox> inboxes) { this.channels = channels; this.inboxes = inboxes; }
        /** Hand bytes to a recipient's inbox as if {@code from} had sent them (an adversary's entry point); an unknown recipient loses them. */
        public void deliver(long from, long to, Object bytes) {
            DkgInbox ib = inboxes.get(to);
            if (ib != null) ib.accept(from, bytes);
        }
    }

    public static MemoryDkgNetwork createMemoryDkgNetwork(List<Long> ids, byte[] sessionId, Intercept intercept) {
        List<Long> sorted = new ArrayList<>(ids);
        Collections.sort(sorted);
        Map<Long, DkgInbox> inboxes = new LinkedHashMap<>();
        for (Long id : sorted) {
            List<Long> peers = new ArrayList<>();
            for (Long p : sorted) if (!p.equals(id)) peers.add(p);
            inboxes.put(id, new DkgInbox(sessionId, peers));
        }
        Map<Long, DkgChannel> channels = new LinkedHashMap<>();
        MemoryDkgNetwork net = new MemoryDkgNetwork(channels, inboxes);
        for (Long selfBoxed : sorted) {
            final long self = selfBoxed;
            final List<Long> peers = new ArrayList<>();
            for (Long p : sorted) if (!p.equals(selfBoxed)) peers.add(p);
            channels.put(selfBoxed, new DkgChannel() {
                private void route(long to, String kind, Object body) {
                    byte[] bytes = encodeDkgMessage(sessionId, kind, body);
                    byte[] out = intercept != null ? intercept.apply(self, to, kind, bytes) : bytes;
                    if (out != null) net.deliver(self, to, out);
                }
                @Override public long self() { return self; }
                @Override public List<Long> peers() { return peers; }
                @Override public void broadcast(String kind, Object body) { for (Long p : peers) route(p, kind, body); }
                @Override public void send(long to, String kind, Object body) {
                    if (!peers.contains(to)) throw new DkgChannelError("identity", to, "not a connected peer");
                    route(to, kind, body);
                }
                @Override public Map<Long, Object> collect(String kind, List<Long> from, double timeoutMs) { return inboxes.get(self).collect(kind, from, timeoutMs); }
                @Override public void close() { inboxes.get(self).close(); }
            });
        }
        return net;
    }

    // ---- party driver ------------------------------------------------------------------------------------------------------

    private static DkgChannelError bound(long peer, DkgChannelError e) { return new DkgChannelError(e.code, peer, e.detail); }

    private static boolean has(List<Object> ids, Object id) {
        Double d = IntentJs.num(id);
        for (Object x : ids) if (d != null && IntentJs.num(x).doubleValue() == d.doubleValue()) return true;
        return false;
    }

    public static Map<String, Object> runDkgOverChannel(DkgChannel ch, Map<String, Object> opts) { return runDkgOverChannel(ch, opts, Frost::randomScalarBytes); }

    /**
     * One participant's whole ceremony: round 1, shares (a bad one becomes an admissible complaint), complaints, rebuttals, the blame
     * round, echo agreement and finalize. {@code opts}: t, participants, sessionId (bytes), timeoutMs (default 30000), coefficients
     * (optional, for vectors). Returns {keyPackage, qualified, complaints}; any protocol violation is a {@link DkgChannelError}.
     */
    public static Map<String, Object> runDkgOverChannel(DkgChannel ch, Map<String, Object> opts, Supplier<byte[]> random) {
        final long self = ch.self();
        List<Object> partsIn = opts.get("participants") instanceof List ? new ArrayList<>((List<?>) opts.get("participants")) : null;
        if (partsIn == null) throw new DkgChannelError("protocol", null, "participants must be distinct positive integers within the cap");
        List<Double> sortedD = new ArrayList<>();
        for (Object p : partsIn) sortedD.add(IntentJs.num(p));
        for (Double d : sortedD) if (d == null) throw new DkgChannelError("protocol", null, "participants must be distinct positive integers within the cap");
        Collections.sort(sortedD);
        boolean bad = sortedD.size() > DKG_MAX_PARTICIPANTS;
        for (int k = 0; k < sortedD.size() && !bad; k++) {
            Double i = sortedD.get(k);
            if (!IntentJs.isSafeInteger(i) || i <= 0 || (k > 0 && sortedD.get(k - 1).doubleValue() == i.doubleValue())) bad = true;
        }
        if (bad) throw new DkgChannelError("protocol", null, "participants must be distinct positive integers within the cap");
        List<Object> ids = new ArrayList<>();
        for (Double d : sortedD) ids.add((long) (double) d);
        if (!has(ids, self)) throw new DkgChannelError("protocol", null, "this participant is not in the participant list");
        Object tO = opts.get("t");
        if (!IntentJs.isSafeInteger(tO) || IntentJs.num(tO) < 1 || IntentJs.num(tO) > ids.size()) throw new DkgChannelError("protocol", null, "need 1 <= t <= n");
        List<Long> others = new ArrayList<>();
        for (Object i : ids) if ((Long) i != self) others.add((Long) i);
        List<Long> peers = ch.peers();
        if (peers.size() != others.size()) throw new DkgChannelError("protocol", null, "the channel peers are not exactly the other participants");
        for (int k = 0; k < others.size(); k++) if (!peers.get(k).equals(others.get(k))) throw new DkgChannelError("protocol", null, "the channel peers are not exactly the other participants");
        byte[] sid = (byte[]) opts.get("sessionId");
        String sidB64 = Pca.b64(sid);
        double tmo = opts.get("timeoutMs") != null ? IntentJs.num(opts.get("timeoutMs")) : 30_000;
        int n = ids.size();
        Map<String, Object> r1o = new LinkedHashMap<>();
        if (opts.get("coefficients") != null) r1o.put("coefficients", opts.get("coefficients"));
        FrostDkg.DkgRound1Result r1 = FrostDkg.dkgRound1(self, tO, n, sid, r1o, random);
        ch.broadcast("round1", r1.pkg);
        List<Object> pkgs = new ArrayList<>();
        pkgs.add(r1.pkg);
        for (Map.Entry<Long, Object> e : ch.collect("round1", others, tmo).entrySet()) {
            long from = e.getKey();
            Map<String, Object> p;
            try { p = decodeDkgRound1Package(e.getValue(), tO); } catch (DkgChannelError x) { throw bound(from, x); }
            if ((Long) p.get("identifier") != from) throw new DkgChannelError("identity", from, "package claims identifier " + p.get("identifier"));
            if (!sidB64.equals(p.get("sessionId"))) throw new DkgChannelError("wrong-session", from, "package names another session");
            pkgs.add(p);
        }
        Map<Long, Map<String, Object>> byId = new HashMap<>();
        for (Object p : pkgs) { @SuppressWarnings("unchecked") Map<String, Object> pm = (Map<String, Object>) p; byId.put((Long) pm.get("identifier"), pm); }
        List<Object> pok = new ArrayList<>();
        for (Object p : pkgs) { @SuppressWarnings("unchecked") Map<String, Object> pm = (Map<String, Object>) p; if (FrostDkg.dkgVerifyRound1(pm.get("identifier"), pm, sid)) pok.add(pm); }
        List<Long> okPeers = new ArrayList<>();
        for (Long o : others) for (Object p : pok) { @SuppressWarnings("unchecked") Map<String, Object> pm = (Map<String, Object>) p; if (o.equals(pm.get("identifier"))) { okPeers.add(o); break; } }
        for (Map<String, Object> s : FrostDkg.dkgRound2(r1.state, pok)) {
            ch.send(IntentJs.lng(s.get("to")), "share", mapOf("from", s.get("from"), "to", s.get("to"), "sessionId", s.get("sessionId"), "share", Pca.b64((byte[]) s.get("share")), "sig", s.get("sig")));
        }
        List<Object> inbox = new ArrayList<>();
        List<Object> mine = new ArrayList<>();
        for (Map.Entry<Long, Object> e : ch.collect("share", okPeers, tmo).entrySet()) {
            long from = e.getKey();
            Map<String, Object> m;
            try { m = decodeDkgShareMessage(e.getValue()); } catch (DkgChannelError x) { throw bound(from, x); }
            if ((Long) m.get("from") != from) throw new DkgChannelError("identity", from, "share claims sender " + m.get("from"));
            if ((Long) m.get("to") != self) throw new DkgChannelError("identity", from, "share is addressed to " + m.get("to"));
            if (!sidB64.equals(m.get("sessionId"))) throw new DkgChannelError("wrong-session", from, "share names another session");
            Map<String, Object> received = mapOf("from", from, "sessionId", m.get("sessionId"), "share", m.get("share"), "sig", m.get("sig"));
            Map<String, Object> sender = byId.get(from);
            if (FrostDkg.dkgVerifyShare(received, sender, self, sid)) { inbox.add(received); continue; }
            Map<String, Object> c = FrostDkg.dkgFileComplaint(mapOf("accused", from, "accuser", self, "receivedShare", m.get("share"), "shareSig", m.get("sig"),
                "senderCommitments", sender.get("coefficientCommitments"), "sessionId", sid));
            if (!Boolean.TRUE.equals(FrostDkg.dkgVerifyComplaint(c, pkgs).get("justified"))) throw new DkgChannelError("protocol", from, "share failed verification and is not admissible blame");
            mine.add(c);
        }
        ch.broadcast("complaints", mapOf("complaints", mine));
        List<Object> complaints = new ArrayList<>(mine);
        for (Map.Entry<Long, Object> e : ch.collect("complaints", others, tmo).entrySet()) {
            long from = e.getKey();
            List<Object> list;
            try { list = decodeDkgComplaints(e.getValue()); } catch (DkgChannelError x) { throw bound(from, x); }
            Set<String> pairs = new HashSet<>();
            for (Object co : list) {
                @SuppressWarnings("unchecked") Map<String, Object> c = (Map<String, Object>) co;
                if ((Long) c.get("accuser") != from) throw new DkgChannelError("identity", from, "complaint filed as " + c.get("accuser"));
                if (!sidB64.equals(c.get("sessionId"))) throw new DkgChannelError("wrong-session", from, "complaint names another session");
                if ((Long) c.get("accused") == from || !has(ids, c.get("accused"))) throw new DkgChannelError("protocol", from, "complaint names an invalid accused");
                if (!pairs.add(String.valueOf(c.get("accused")))) throw new DkgChannelError("duplicate", from, "two complaints against one accused");
                complaints.add(c);
            }
        }
        List<Object> rebuttals = new ArrayList<>();
        for (Object co : complaints) {
            @SuppressWarnings("unchecked") Map<String, Object> c = (Map<String, Object>) co;
            if (IntentJs.lng(c.get("accused")) == self) rebuttals.add(FrostDkg.dkgRebut(self, c, r1.state));
        }
        ch.broadcast("rebuttals", mapOf("rebuttals", rebuttals));
        List<Object> allRebuttals = new ArrayList<>(rebuttals);
        for (Map.Entry<Long, Object> e : ch.collect("rebuttals", others, tmo).entrySet()) {
            long from = e.getKey();
            List<Object> list;
            try { list = decodeDkgRebuttals(e.getValue()); } catch (DkgChannelError x) { throw bound(from, x); }
            for (Object ro : list) {
                @SuppressWarnings("unchecked") Map<String, Object> r = (Map<String, Object>) ro;
                if ((Long) r.get("accused") != from) throw new DkgChannelError("identity", from, "rebuttal made as " + r.get("accused"));
                if (!sidB64.equals(r.get("sessionId"))) throw new DkgChannelError("wrong-session", from, "rebuttal names another session");
                allRebuttals.add(r);
            }
        }
        List<Object> qualified = FrostDkg.dkgQualifiedSet(ids, complaints, pkgs, allRebuttals);
        if (!has(qualified, self)) throw new DkgChannelError("disqualified", self, "this participant was disqualified by the blame round");
        if (qualified.size() < IntentJs.lng(tO)) throw new DkgChannelError("protocol", null, "fewer than t participants remain qualified");
        Map<String, Object> echo = FrostDkg.dkgEcho(mapOf("identifier", self, "round1Packages", pkgs, "complaints", complaints, "qualified", qualified, "sessionId", sid));
        ch.broadcast("echo", echo);
        List<Object> echoes = new ArrayList<>();
        echoes.add(echo);
        List<Long> echoFrom = new ArrayList<>();
        for (Object q : qualified) if ((Long) q != self) echoFrom.add((Long) q);
        for (Map.Entry<Long, Object> e : ch.collect("echo", echoFrom, tmo).entrySet()) {
            long from = e.getKey();
            Map<String, Object> ec;
            try { ec = decodeDkgEcho(e.getValue()); } catch (DkgChannelError x) { throw bound(from, x); }
            if ((Long) ec.get("identifier") != from) throw new DkgChannelError("identity", from, "echo claims identifier " + ec.get("identifier"));
            echoes.add(ec);
        }
        Map<String, Object> agreement = FrostDkg.dkgCheckEchoes(qualified, echoes, sid);
        if (!Boolean.TRUE.equals(agreement.get("agreed"))) throw new DkgChannelError("equivocation", null, String.valueOf(agreement.get("reason")));
        Map<String, Object> keyPackage = FrostDkg.dkgFinalize(self, r1.state, inbox, pkgs, qualified, mapOf("echoes", echoes, "complaints", complaints));
        return mapOf("keyPackage", keyPackage, "qualified", qualified, "complaints", complaints);
    }
}
