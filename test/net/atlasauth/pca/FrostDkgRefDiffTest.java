package net.atlasauth.pca;

import static net.atlasauth.pca.FrostRefSupport.arg;
import static net.atlasauth.pca.FrostRefSupport.bytes;
import static net.atlasauth.pca.FrostRefSupport.errOut;
import static net.atlasauth.pca.FrostRefSupport.l;
import static net.atlasauth.pca.FrostRefSupport.lng;
import static net.atlasauth.pca.FrostRefSupport.m;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;
import net.atlasauth.pca.FrostDkgChannel.DkgChannel;
import net.atlasauth.pca.FrostDkgChannel.DkgChannelError;
import net.atlasauth.pca.FrostDkgChannel.DkgInbox;
import net.atlasauth.pca.FrostRefSupport.Script;
import org.junit.jupiter.api.Test;

/**
 * The FROST distributed key generation against the reference corpus (ref-frost-dkg: 439 committed cases and 286 generated in CI because they
 * carry derived shares): rounds, complaints, rebuttals, blame, qualified set, echo agreement, finalize, the whole-ceremony simulation, the
 * wire codec, the inbox, the in-memory network, the TLS framing and one party's ceremony replayed over a scripted channel.
 */
class FrostDkgRefDiffTest {
    static final String MODULE = "ref-frost-dkg";
    static final int TOTAL = 439 + 286;
    private static final List<String> PHASES = List.of("round1", "share", "complaints", "rebuttals", "echo");

    @Test void genCorpusIsPresent() { BaseOracle.requireGen(MODULE); }

    private static Supplier<byte[]> rng(Script r) { return r != null ? r : () -> { throw new IllegalStateException("unscripted randomness draw"); }; }

    @SuppressWarnings("unchecked")
    private static FrostDkg.DkgState stateOf(Object specO) {
        Map<String, Object> spec = m(specO);
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("coefficients", spec.get("coefficients"));
        o.put("popNonce", spec.get("popNonce"));
        return FrostDkg.dkgRound1(spec.get("id"), spec.get("t"), spec.get("n"), spec.get("sessionId"), o).state;
    }

    private static List<Long> longs(Object o) {
        List<Long> out = new ArrayList<>();
        for (Object x : l(o)) out.add((long) (double) IntentJs.num(x));
        return out;
    }

    private static Map<String, Object> mo(Object... kv) {
        Map<String, Object> o = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) o.put((String) kv[i], kv[i + 1]);
        return o;
    }

    private static Map<String, Object> bodies(Map<Long, Object> got) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<Long, Object> e : got.entrySet()) out.put(String.valueOf(e.getKey()), e.getValue());
        return out;
    }

    // ---- inbox ----------------------------------------------------------------------------------------------------------

    private static Object inboxRun(Map<String, Object> a) {
        DkgInbox ib = new DkgInbox(bytes(a.get("sessionId")), longs(a.get("peers")));
        List<Object> out = new ArrayList<>();
        for (Object oo : l(a.get("ops"))) {
            Map<String, Object> op = m(oo);
            try {
                String k = (String) op.get("op");
                if (k.equals("accept")) { ib.accept(lng(op.get("sender")), op.get("bytes")); out.add(mo("ok", true)); }
                else if (k.equals("fail")) { ib.fail(lng(op.get("peer")), new DkgChannelError((String) op.get("code"), null, (String) op.get("message"))); out.add(mo("ok", true)); }
                else if (k.equals("peerGone")) { ib.peerGone(lng(op.get("peer"))); out.add(mo("ok", true)); }
                else if (k.equals("close")) { ib.close(); out.add(mo("ok", true)); }
                else if (k.equals("collect")) {
                    Map<Long, Object> got = ib.collect((String) op.get("kind"), longs(op.get("from")), IntentJs.num(op.get("timeoutMs")));
                    out.add(mo("ok", true, "bodies", bodies(got)));
                } else throw new IllegalArgumentException("bad op");
            } catch (RuntimeException e) {
                out.add(errOut(e));
            }
        }
        return out;
    }

    // ---- memory network -------------------------------------------------------------------------------------------------------

    private static Object netRun(Map<String, Object> a) {
        Map<String, Object> im = m(a.get("intercept"));
        FrostDkgChannel.Intercept intercept = im == null ? null : (from, to, kind, bytes) -> {
            boolean hit = (!im.containsKey("kind") || im.get("kind").equals(kind)) && (!im.containsKey("from") || lng(im.get("from")) == from) && (!im.containsKey("to") || lng(im.get("to")) == to);
            if (!hit) return bytes;
            if ("drop".equals(im.get("action"))) return null;
            if ("replace".equals(im.get("action"))) return (byte[]) im.get("bytes");
            return bytes;
        };
        FrostDkgChannel.MemoryDkgNetwork net = FrostDkgChannel.createMemoryDkgNetwork(longs(a.get("ids")), bytes(a.get("sessionId")), intercept);
        List<Object> out = new ArrayList<>();
        Map<String, Object> summary = new LinkedHashMap<>();
        for (Map.Entry<Long, DkgChannel> e : net.channels.entrySet()) summary.put(String.valueOf(e.getKey()), mo("self", e.getValue().self(), "peers", new ArrayList<Object>(e.getValue().peers())));
        out.add(mo("channels", summary));
        for (Object oo : l(a.get("ops"))) {
            Map<String, Object> op = m(oo);
            try {
                String k = (String) op.get("op");
                DkgChannel ch = op.containsKey("at") ? net.channels.get(lng(op.get("at"))) : null;
                if (k.equals("broadcast")) { net.channels.get(lng(op.get("from"))).broadcast((String) op.get("kind"), op.get("body")); out.add(mo("ok", true)); }
                else if (k.equals("send")) { net.channels.get(lng(op.get("from"))).send(lng(op.get("to")), (String) op.get("kind"), op.get("body")); out.add(mo("ok", true)); }
                else if (k.equals("deliver")) { net.deliver(lng(op.get("from")), lng(op.get("to")), op.get("bytes")); out.add(mo("ok", true)); }
                else if (k.equals("collect")) { out.add(mo("ok", true, "bodies", bodies(ch.collect((String) op.get("kind"), longs(op.get("fromIds")), IntentJs.num(op.get("timeoutMs")))))); }
                else if (k.equals("close")) { ch.close(); out.add(mo("ok", true)); }
                else throw new IllegalArgumentException("bad op");
            } catch (RuntimeException e) {
                out.add(errOut(e));
            }
        }
        return out;
    }

    // ---- TLS framing model ----------------------------------------------------------------------------------------------------

    private static Object tlsDecode(Map<String, Object> a) {
        List<Object> accepted = new ArrayList<>();
        String[] error = { null };
        FrostDkgTls.FrameReader rd = new FrostDkgTls.FrameReader(accepted::add, len -> error[0] = "oversize");
        for (Object c : l(a.get("chunks"))) rd.feed((byte[]) c);
        return mo("accepted", accepted, "error", error[0], "buffered", rd.buffered());
    }

    // ---- one party over a scripted channel -------------------------------------------------------------------------------------------

    private static Object partyRun(Map<String, Object> spec, Script script) {
        byte[] sid = bytes(spec.get("sessionId"));
        List<Long> participants = longs(spec.get("participants"));
        List<Long> peers;
        if (spec.get("peers") != null) peers = longs(spec.get("peers"));
        else {
            peers = new ArrayList<>();
            for (Long p : participants) if (p != lng(spec.get("self"))) peers.add(p);
            java.util.Collections.sort(peers);
        }
        DkgInbox inbox = new DkgInbox(sid, peers);
        List<Map<String, Object>> pending = new ArrayList<>();
        if (spec.get("inbound") != null) for (Object o : l(spec.get("inbound"))) pending.add(m(o));
        List<Object> outbound = new ArrayList<>();
        if (spec.get("gone") != null) for (Object g : l(spec.get("gone"))) inbox.peerGone(lng(g));
        final long self = lng(spec.get("self"));
        final List<Long> chPeers = peers;
        DkgChannel ch = new DkgChannel() {
            @Override public long self() { return self; }
            @Override public List<Long> peers() { return chPeers; }
            @Override public void broadcast(String kind, Object body) { outbound.add(mo("op", "broadcast", "kind", kind, "bytes", FrostDkgChannel.encodeDkgMessage(sid, kind, body))); }
            @Override public void send(long to, String kind, Object body) {
                if (!chPeers.contains(to)) throw new DkgChannelError("identity", to, "not a connected peer");
                outbound.add(mo("op", "send", "kind", kind, "to", to, "bytes", FrostDkgChannel.encodeDkgMessage(sid, kind, body)));
            }
            @Override public Map<Long, Object> collect(String kind, List<Long> from, double timeoutMs) {
                int lim = PHASES.indexOf(kind);
                List<Map<String, Object>> keep = new ArrayList<>();
                for (Map<String, Object> msg : pending) {
                    if (PHASES.indexOf((String) msg.get("kind")) <= lim) inbox.accept(lng(msg.get("from")), msg.get("bytes"));
                    else keep.add(msg);
                }
                pending.clear();
                pending.addAll(keep);
                return inbox.collect(kind, from, timeoutMs);
            }
            @Override public void close() { inbox.close(); }
        };
        Map<String, Object> opts = new LinkedHashMap<>();
        opts.put("t", spec.get("t"));
        opts.put("participants", spec.get("participants"));
        opts.put("sessionId", sid);
        opts.put("timeoutMs", spec.get("timeoutMs"));
        try {
            Map<String, Object> r = FrostDkgChannel.runDkgOverChannel(ch, opts, rng(script));
            return mo("outbound", outbound, "result", mo("qualified", r.get("qualified"), "complaints", r.get("complaints"), "keyPackage", r.get("keyPackage")));
        } catch (RuntimeException e) {
            return mo("outbound", outbound, "error", errOut(e));
        }
    }

    // ---- the test ---------------------------------------------------------------------------------------------------------------------

    @Test void everyFunction() throws Exception {
        BaseOracle.requireGen(MODULE);
        Map<String, FrostRefSupport.Body> f = new LinkedHashMap<>();
        f.put("constants", (a, r) -> mo("DKG_WIRE_VERSION", FrostDkgChannel.DKG_WIRE_VERSION, "DKG_MAX_MESSAGE_BYTES", FrostDkgChannel.DKG_MAX_MESSAGE_BYTES,
            "DKG_MAX_PARTICIPANTS", FrostDkgChannel.DKG_MAX_PARTICIPANTS, "DKG_MESSAGE_KINDS", new ArrayList<Object>(FrostDkgChannel.DKG_MESSAGE_KINDS)));
        f.put("dkgRound1", (a, r) -> mo("package", FrostDkg.dkgRound1(arg(a, 0), arg(a, 1), arg(a, 2), arg(a, 3), m(arg(a, 4)), rng(r)).pkg));
        f.put("dkgVerifyRound1", (a, r) -> FrostDkg.dkgVerifyRound1(arg(a, 0), arg(a, 1), arg(a, 2)));
        f.put("dkgSignShare", (a, r) -> FrostDkg.dkgSignShare(stateOf(arg(a, 0)), arg(a, 1), bytes(arg(a, 2))));
        f.put("dkgRound2", (a, r) -> FrostDkg.dkgRound2(stateOf(arg(a, 0)), arg(a, 1)));
        f.put("dkgVerifyShare", (a, r) -> FrostDkg.dkgVerifyShare(arg(a, 0), arg(a, 1), arg(a, 2), arg(a, 3)));
        f.put("dkgFileComplaint", (a, r) -> FrostDkg.dkgFileComplaint(m(arg(a, 0))));
        f.put("dkgVerifyComplaint", (a, r) -> FrostDkg.dkgVerifyComplaint(arg(a, 0), arg(a, 1)));
        f.put("dkgRebut", (a, r) -> FrostDkg.dkgRebut(arg(a, 0), m(arg(a, 1)), stateOf(arg(a, 2))));
        f.put("dkgResolveBlame", (a, r) -> FrostDkg.dkgResolveBlame(arg(a, 0), arg(a, 1), arg(a, 2)));
        f.put("dkgQualifiedSet", (a, r) -> FrostDkg.dkgQualifiedSet(arg(a, 0), arg(a, 1), arg(a, 2), arg(a, 3)));
        f.put("dkgTranscriptDigest", (a, r) -> FrostDkg.dkgTranscriptDigest(m(arg(a, 0))));
        f.put("dkgEcho", (a, r) -> FrostDkg.dkgEcho(m(arg(a, 0))));
        f.put("dkgCheckEchoes", (a, r) -> FrostDkg.dkgCheckEchoes(arg(a, 0), arg(a, 1), arg(a, 2)));
        f.put("dkgFinalize", (a, r) -> FrostDkg.dkgFinalize(arg(a, 0), stateOf(arg(a, 1)), arg(a, 2), arg(a, 3), arg(a, 4), m(arg(a, 5))));
        f.put("frostDkgSimulate", (a, r) -> FrostDkg.frostDkgSimulate(arg(a, 0), arg(a, 1), m(arg(a, 2)), rng(r)));
        f.put("encodeDkgMessage", (a, r) -> FrostDkgChannel.encodeDkgMessage(arg(a, 0), arg(a, 1), arg(a, 2)));
        f.put("decodeDkgMessage", (a, r) -> FrostDkgChannel.decodeDkgMessage(arg(a, 0), arg(a, 1)));
        f.put("decodeDkgRound1Package", (a, r) -> FrostDkgChannel.decodeDkgRound1Package(arg(a, 0), arg(a, 1)));
        f.put("decodeDkgShareMessage", (a, r) -> FrostDkgChannel.decodeDkgShareMessage(arg(a, 0)));
        f.put("decodeDkgComplaints", (a, r) -> FrostDkgChannel.decodeDkgComplaints(arg(a, 0)));
        f.put("decodeDkgRebuttals", (a, r) -> FrostDkgChannel.decodeDkgRebuttals(arg(a, 0)));
        f.put("decodeDkgEcho", (a, r) -> FrostDkgChannel.decodeDkgEcho(arg(a, 0)));
        f.put("dkgInbox", (a, r) -> inboxRun(m(arg(a, 0))));
        f.put("memoryNetwork", (a, r) -> netRun(m(arg(a, 0))));
        f.put("tlsFrameEncode", (a, r) -> FrostDkgTls.frameEncode(bytes(arg(a, 0))));
        f.put("tlsFrameDecode", (a, r) -> tlsDecode(m(arg(a, 0))));
        f.put("runDkgOverChannel", (a, r) -> partyRun(m(arg(a, 0)), r));

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);
        for (Map.Entry<String, FrostRefSupport.Body> e : f.entrySet()) FrostRefSupport.each(MODULE, e.getKey(), e.getValue());
    }
}
