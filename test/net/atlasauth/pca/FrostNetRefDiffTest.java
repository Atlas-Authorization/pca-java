package net.atlasauth.pca;

import static net.atlasauth.pca.FrostRefSupport.arg;
import static net.atlasauth.pca.FrostRefSupport.bytes;
import static net.atlasauth.pca.FrostRefSupport.errOut;
import static net.atlasauth.pca.FrostRefSupport.l;
import static net.atlasauth.pca.FrostRefSupport.lng;
import static net.atlasauth.pca.FrostRefSupport.m;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.DoubleSupplier;
import net.atlasauth.pca.FrostRefSupport.Script;
import org.junit.jupiter.api.Test;

/**
 * Networked FROST signing against the reference corpus (ref-frost-net, 634 cases): allow tokens, signer proof of possession, the
 * equivocation guard, the wire decoders, the signer service, the coordinator (hostile transports included), the nonce store contract,
 * the hybrid guardian co-sign and the PQ quorum. Seeds and dealer shares are descriptors resolved here; randomness comes from the
 * script each case carries.
 */
class FrostNetRefDiffTest {
    static final String MODULE = "ref-frost-net";
    static final int TOTAL = 634;

    // ---- stores ----------------------------------------------------------------------------------------------------

    static class FailStore extends FrostNet.MemoryNonceStore {
        private final String mode;
        FailStore(String mode) { this.mode = mode; }
        private void chk(String m) { if (mode.equals(m)) throw new IllegalStateException("store down"); }
        @Override public void create(String s, FrostNet.NonceRecord r) { chk("create"); super.create(s, r); }
        @Override public FrostNet.NonceRecord load(String s) { chk("load"); return super.load(s); }
        @Override public void spend(String s) { chk("spend"); super.spend(s); }
        @Override public void drop(String s) { chk("drop"); super.drop(s); }
        @Override public boolean isSpent(String s) { chk("isSpent"); return super.isSpent(s); }
    }

    static Object mkStore(Object kind) {
        if (kind == null || "none".equals(kind)) return null;
        if ("memory".equals(kind)) return new FrostNet.MemoryNonceStore();
        if ("invalid-no-spend".equals(kind)) return new Object();
        String k = (String) kind;
        if (k.startsWith("fail-")) return new FailStore(k.substring(5));
        throw new IllegalArgumentException("store " + k);
    }

    /** A store with exactly one defect, for the contract check. */
    static class Broken implements FrostNet.NonceStore {
        final String kind;
        final Map<String, FrostNet.NonceRecord> live = new HashMap<>();
        final Set<String> spent = new HashSet<>();
        Broken(String kind) { this.kind = kind; }
        private static FrostNet.NonceRecord cp(FrostNet.NonceRecord r) {
            return new FrostNet.NonceRecord(r.hiding.clone(), r.binding.clone(), r.hidingCommitment.clone(), r.bindingCommitment.clone(), r.createdAt);
        }
        @Override public void create(String id, FrostNet.NonceRecord r) {
            if (!kind.equals("create-overwrites") && live.containsKey(id)) throw new IllegalStateException("exists");
            if (!kind.equals("create-over-spent") && spent.contains(id)) throw new IllegalStateException("spent");
            live.put(id, kind.equals("create-aliases-input") ? r : cp(r));
        }
        @Override public FrostNet.NonceRecord load(String id) {
            FrostNet.NonceRecord r = live.get(id);
            if (r == null) return null;
            return kind.equals("load-aliases") ? r : cp(r);
        }
        @Override public void spend(String id) {
            if (!live.containsKey(id)) {
                if (kind.equals("spend-unknown-ok") || (kind.equals("spend-twice-ok") && spent.contains(id))) return;
                throw new IllegalStateException("not live");
            }
            live.remove(id);
            spent.add(id);
        }
        @Override public void drop(String id) { live.remove(id); if (kind.equals("drop-marks-spent")) spent.add(id); }
        @Override public boolean isSpent(String id) { return kind.equals("unknown-reports-spent") || spent.contains(id); }
        FrostNet.NonceStore reopen(FrostNet.NonceStore s) {
            if (kind.equals("spent-forgotten-on-restart")) spent.clear();
            if (kind.equals("live-lost-on-restart")) live.clear();
            return s;
        }
    }

    // ---- helpers ------------------------------------------------------------------------------------------------------

    private static Map<String, Object> mo(Object... kv) {
        Map<String, Object> o = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) o.put((String) kv[i], kv[i + 1]);
        return o;
    }

    private static Object frostBytes(Object x) {
        if (x != null && !(x instanceof byte[])) throw new IllegalArgumentException("frostActionDigest: message must be bytes");
        return x;
    }

    private static Map<String, Object> commitmentOut(Frost.FrostCommitment c) { return mo("identifier", c.identifier, "hiding", c.hiding, "binding", c.binding); }

    @SuppressWarnings("unchecked")
    private static Object deepCopy(Object v) {
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) out.put(e.getKey(), deepCopy(e.getValue()));
            return out;
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(deepCopy(x));
            return out;
        }
        return v;
    }

    private static String flipStr(String s) {
        byte[] u = Keys.unb64u(s);
        u[0] ^= 1;
        return Keys.b64u(u);
    }

    private static Frost.FrostParticipantShare participant(Object o) {
        Map<String, Object> p = m(o);
        return new Frost.FrostParticipantShare(lng(p.get("identifier")), bytes(p.get("share")), bytes(p.get("publicKey")));
    }

    private static Pq.KeyPair mlDsa(Object seed) { return Pq.mlDsa65Keygen(bytes(seed)); }

    // ---- signer service scenarios -------------------------------------------------------------------------------------

    private static Object signerService(Map<String, Object> cfg, List<Object> steps, Script rng) {
        double[] clock = { cfg.get("clock") != null ? IntentJs.num(cfg.get("clock")) : 1_000_000 };
        Object store = mkStore(cfg.get("store"));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ctor", null);
        List<Object> outSteps = new ArrayList<>();
        out.put("steps", outSteps);
        Map<String, Object> opts = new LinkedHashMap<>();
        for (String k : new String[] { "identifier", "share", "groupPublicKey", "threshold", "policyAuthorityPublicKey", "sessionTtlMs" }) opts.put(k, cfg.get(k));
        opts.put("now", (DoubleSupplier) () -> clock[0]);
        opts.put("nonceStore", store);
        opts.put("random", rng);
        FrostNet.GuardianSignerService[] svc = new FrostNet.GuardianSignerService[1];
        try {
            svc[0] = new FrostNet.GuardianSignerService(opts);
            out.put("ctor", mo("verificationShare", svc[0].verificationShare(), "pop", svc[0].proofOfPossession(), "enrollment", svc[0].enrollment()));
        } catch (RuntimeException e) {
            out.put("ctor", errOut(e));
            return out;
        }
        for (Object so : steps) {
            Map<String, Object> st = m(so);
            String op = (String) st.get("op");
            try {
                if (op.equals("round1")) outSteps.add(svc[0].round1(st.get("req")));
                else if (op.equals("round2")) outSteps.add(svc[0].round2(st.get("req")));
                else if (op.equals("clock")) { clock[0] += IntentJs.num(st.get("ms")); outSteps.add(mo("clock", clock[0])); }
                else if (op.equals("restart")) {
                    svc[0] = new FrostNet.GuardianSignerService(opts);
                    outSteps.add(mo("restarted", true, "pop", svc[0].proofOfPossession()));
                }
                else if (op.equals("storeLoad")) outSteps.add(mo("live", ((FrostNet.NonceStore) store).load((String) st.get("sid")) != null));
                else if (op.equals("storeIsSpent")) outSteps.add(mo("spent", ((FrostNet.NonceStore) store).isSpent((String) st.get("sid"))));
                else throw new IllegalArgumentException("bad step");
            } catch (RuntimeException e) {
                outSteps.add(errOut(e));
            }
        }
        return out;
    }

    // ---- coordinator scenarios ------------------------------------------------------------------------------------------

    private static void edit(Map<String, Object> resp, List<Object> edits, int round) {
        if (edits == null) return;
        for (Object eo : edits) {
            Map<String, Object> e = m(eo);
            if (lng(e.get("round")) != round) continue;
            List<Object> path = l(e.get("path"));
            Object parent = resp;
            for (int i = 0; i < path.size() - 1 && parent != null; i++) parent = parent instanceof Map ? ((Map<?, ?>) parent).get(path.get(i)) : null;
            if (!(parent instanceof Map)) continue;
            @SuppressWarnings("unchecked") Map<String, Object> pm = (Map<String, Object>) parent;
            String key = (String) path.get(path.size() - 1);
            String op = (String) e.get("op");
            if (op.equals("set")) pm.put(key, e.get("value"));
            else if (op.equals("delete")) pm.remove(key);
            else if (op.equals("flip")) pm.put(key, flipStr((String) pm.get(key)));
        }
    }

    private static final class ScriptedTransport implements FrostNet.SignerTransport {
        final Map<String, Object> s;
        final long id;
        final FrostNet.GuardianSignerService service;
        int r1, r2;
        ScriptedTransport(Map<String, Object> s) {
            this.s = s;
            this.id = lng(s.get("identifier"));
            if (s.get("canned") != null) { service = null; return; }
            Map<String, Object> o = new LinkedHashMap<>();
            for (String k : new String[] { "identifier", "share", "groupPublicKey", "threshold", "policyAuthorityPublicKey", "sessionTtlMs" }) o.put(k, s.get(k));
            o.put("now", (DoubleSupplier) () -> 1_000_000);
            o.put("nonceStore", mkStore(s.get("store")));
            o.put("random", FrostRefSupport.script(s.get("rng")));
            service = new FrostNet.GuardianSignerService(o);
        }
        @Override public long identifier() { return id; }
        private Map<String, Object> respond(int round, Map<String, Object> req) throws Exception {
            String key = round == 1 ? "r1" : "r2";
            int n = round == 1 ? r1++ : r2++;
            Map<String, Object> delay = m(s.get("delay")), thr = m(s.get("throws"));
            if (delay != null && delay.get(key) != null && IntentJs.num(delay.get(key)) > 0) Thread.sleep((long) (double) IntentJs.num(delay.get(key)));
            if (thr != null && Boolean.TRUE.equals(thr.get(key))) throw new IllegalStateException("unreachable");
            Map<String, Object> resp;
            Map<String, Object> canned = m(s.get("canned"));
            if (canned != null) {
                List<Object> list = l(canned.get(round == 1 ? "round1" : "round2"));
                Object c = n < list.size() ? list.get(n) : null;
                if (c == null || "throw".equals(c)) throw new IllegalStateException("unreachable");
                resp = m(deepCopy(c));
            } else {
                resp = m(deepCopy(round == 1 ? service.round1(req) : service.round2(req)));
            }
            edit(resp, l(s.get("edits")), round);
            return resp;
        }
        @Override public Map<String, Object> round1(Map<String, Object> req) throws Exception { return respond(1, req); }
        @Override public Map<String, Object> round2(Map<String, Object> req) throws Exception { return respond(2, req); }
    }

    private static Object coordinator(Map<String, Object> cfg) {
        Map<String, Object> out = new LinkedHashMap<>();
        List<Object> calls = new ArrayList<>();
        out.put("calls", calls);
        List<FrostNet.SignerTransport> transports = new ArrayList<>();
        for (Object so : l(cfg.get("signers"))) transports.add(new ScriptedTransport(m(so)));
        List<Object> sids = new ArrayList<>();
        if (l(cfg.get("sessionIds")) != null) sids.addAll(l(cfg.get("sessionIds")));
        Map<String, Object> opts = new LinkedHashMap<>();
        opts.put("groupPublicKey", cfg.get("groupPublicKey"));
        opts.put("threshold", cfg.get("threshold"));
        opts.put("signers", transports);
        if (cfg.containsKey("verificationShares")) opts.put("verificationShares", cfg.get("verificationShares"));
        if (cfg.containsKey("enroll")) opts.put("enroll", cfg.get("enroll"));
        opts.put("timeoutMs", cfg.get("timeoutMs"));
        opts.put("newSessionId", (java.util.function.Supplier<String>) () -> {
            if (sids.isEmpty()) throw new IllegalStateException("no more scripted session ids");
            return (String) sids.remove(0);
        });
        FrostNet.NetworkCoordinator coord;
        try {
            coord = new FrostNet.NetworkCoordinator(opts);
        } catch (RuntimeException e) {
            out.put("ctor", errOut(e));
            return out;
        }
        for (Object co : l(cfg.get("calls"))) {
            Map<String, Object> c = m(co);
            try {
                Map<String, Object> o = new LinkedHashMap<>();
                o.put("signerIds", c.get("signerIds"));
                o.put("timeoutMs", c.get("timeoutMs"));
                calls.add(coord.sign(c.get("message"), c.get("allow"), o));
            } catch (RuntimeException e) {
                calls.add(errOut(e));
            }
        }
        return out;
    }

    // ---- the test ---------------------------------------------------------------------------------------------------------

    @Test void everyFunction() throws Exception {
        Map<String, FrostRefSupport.Body> f = new LinkedHashMap<>();
        f.put("constants", (a, r) -> mo("ALLOW_TOKEN_TYP", FrostNet.ALLOW_TOKEN_TYP, "SIGNER_POP_DST", FrostNet.SIGNER_POP_DST,
            "MAX_FROST_SIGNING_SET", FrostNet.MAX_FROST_SIGNING_SET, "DEFAULT_FROST_GROUP_ALG", FrostPq.DEFAULT_FROST_GROUP_ALG,
            "PQ_QUORUM_VERSION", FrostPq.PQ_QUORUM_VERSION, "PQ_QUORUM_ALG", FrostPq.PQ_QUORUM_ALG, "MAX_PQ_QUORUM_ENTRIES", FrostPq.MAX_PQ_QUORUM_ENTRIES));
        f.put("frostActionDigest", (a, r) -> FrostNet.frostActionDigest((byte[]) frostBytes(arg(a, 0))));
        f.put("issueAllowToken", (a, r) -> r == null ? FrostNet.issueAllowToken(bytes(arg(a, 0)), m(arg(a, 1))) : FrostNet.issueAllowToken(bytes(arg(a, 0)), m(arg(a, 1)), r));
        f.put("verifyAllowToken", (a, r) -> FrostNet.verifyAllowToken(arg(a, 0), m(arg(a, 1))));
        f.put("createSignerPoP", (a, r) -> r == null ? FrostNet.createSignerPoP(arg(a, 0), arg(a, 1), m(arg(a, 2))) : FrostNet.createSignerPoP(arg(a, 0), arg(a, 1), m(arg(a, 2)), r));
        f.put("verifySignerPoP", (a, r) -> FrostNet.verifySignerPoP(arg(a, 0), m(arg(a, 1))));
        f.put("enrollVerificationShares", (a, r) -> FrostNet.enrollVerificationShares(arg(a, 0), m(arg(a, 1))));
        f.put("equivocationGuard", (a, r) -> {
            FrostNet.EquivocationGuard g = new FrostNet.EquivocationGuard();
            List<Object> res = new ArrayList<>();
            for (Object oo : l(arg(a, 0))) {
                Map<String, Object> op = m(oo);
                try {
                    if (op.get("op").equals("observe")) g.observe(op.get("session_id"), op.get("round"), op.get("identifier"), op.get("message"));
                    else if (op.get("op").equals("forget")) g.forget(op.get("session_id"));
                    else throw new IllegalArgumentException("bad op");
                    res.add(mo("ok", true));
                } catch (RuntimeException e) {
                    res.add(errOut(e));
                }
            }
            return res;
        });
        f.put("decodeCommitment", (a, r) -> commitmentOut(FrostNet.decodeCommitment(arg(a, 0))));
        f.put("decodeCommitments", (a, r) -> {
            List<Object> out = new ArrayList<>();
            for (Frost.FrostCommitment c : FrostNet.decodeCommitments(arg(a, 0))) out.add(commitmentOut(c));
            return out;
        });
        f.put("decodeVerificationShares", (a, r) -> {
            List<Object> out = new ArrayList<>();
            for (Frost.VerificationShare v : FrostNet.decodeVerificationShares(arg(a, 0))) out.add(mo("identifier", v.identifier, "publicKey", v.publicKey));
            return out;
        });
        f.put("signerService", (a, r) -> signerService(m(arg(a, 0)), l(arg(a, 1)), r));
        f.put("coordinator", (a, r) -> coordinator(m(arg(a, 0))));
        f.put("nonceStore", (a, r) -> {
            FrostNet.MemoryNonceStore s = new FrostNet.MemoryNonceStore();
            List<Object> res = new ArrayList<>();
            for (Object oo : l(arg(a, 0))) {
                Map<String, Object> op = m(oo);
                Object sidO = op.get("sid");
                String sid = sidO instanceof String ? (String) sidO : null;
                try {
                    String kind = (String) op.get("op");
                    if (kind.equals("create")) {
                        if (sid == null) throw new IllegalArgumentException("nonce-store: session id must be a non-empty string");
                        Map<String, Object> r0 = m(op.get("rec"));
                        FrostNet.NonceRecord rec = new FrostNet.NonceRecord(bytes(r0.get("hiding")), bytes(r0.get("binding")), bytes(r0.get("hidingCommitment")), bytes(r0.get("bindingCommitment")), IntentJs.num(r0.get("createdAt")));
                        s.create(sid, rec);
                        if (Boolean.TRUE.equals(op.get("mutateInputAfter"))) {
                            java.util.Arrays.fill(rec.hiding, (byte) 0xee);
                            java.util.Arrays.fill(rec.hidingCommitment, (byte) 0xee);
                        }
                        res.add(mo("ok", true));
                    } else if (kind.equals("load")) {
                        FrostNet.NonceRecord rec = sid == null ? null : s.load(sid);
                        Object j = rec == null ? null : mo("hiding", rec.hiding.clone(), "binding", rec.binding.clone(), "hidingCommitment", rec.hidingCommitment, "bindingCommitment", rec.bindingCommitment, "createdAt", rec.createdAt);
                        if (rec != null && Boolean.TRUE.equals(op.get("mutate"))) {
                            java.util.Arrays.fill(rec.hiding, (byte) 0xee);
                            java.util.Arrays.fill(rec.binding, (byte) 0xee);
                        }
                        res.add(mo("value", j));
                    } else if (kind.equals("spend")) {
                        if (sid == null) throw new IllegalStateException("nonce-store: cannot spend a session that is not live");
                        s.spend(sid);
                        res.add(mo("ok", true));
                    } else if (kind.equals("drop")) {
                        if (sid != null) s.drop(sid);
                        res.add(mo("ok", true));
                    } else if (kind.equals("isSpent")) {
                        res.add(mo("value", sid != null && s.isSpent(sid)));
                    } else throw new IllegalArgumentException("bad op");
                } catch (RuntimeException e) {
                    res.add(errOut(e));
                }
            }
            return res;
        });
        f.put("assertNonceStoreContract", (a, r) -> {
            String store = (String) m(arg(a, 0)).get("store");
            try {
                if (store.equals("memory")) FrostNet.assertNonceStoreContract(FrostNet.MemoryNonceStore::new, s -> s);
                else {
                    Broken b = new Broken(store.substring("broken:".length()));
                    FrostNet.assertNonceStoreContract(() -> b, b::reopen);
                }
                return null;
            } catch (RuntimeException e) {
                return errOut(e);
            }
        });
        f.put("resolveFrostGroupAlg", (a, r) -> a.length == 0 ? FrostPq.resolveFrostGroupAlg() : FrostPq.resolveFrostGroupAlg(a[0]));
        f.put("frostSignerSetDigest", (a, r) -> FrostPq.frostSignerSetDigest(arg(a, 0)));
        f.put("frostCosignRepresentative", (a, r) -> FrostPq.frostCosignRepresentative(arg(a, 0), bytes(arg(a, 1)), arg(a, 2), arg(a, 3)));
        f.put("signHybridFrostCosign", (a, r) -> {
            List<Frost.FrostParticipantShare> quorum = new ArrayList<>();
            for (Object p : l(arg(a, 1))) quorum.add(participant(p));
            Map<String, Object> o = new LinkedHashMap<>(m(arg(a, 3)));
            if (o.get("guardianMlDsaSeed") != null) { o.put("guardianMlDsa", mlDsa(o.get("guardianMlDsaSeed"))); }
            o.remove("guardianMlDsaSeed");
            byte[] gpk = bytes(arg(a, 0)), msg = bytes(arg(a, 2));
            Map<String, Object> res = FrostPq.signHybridFrostCosign(gpk, quorum, msg, o);
            byte[] sig = Keys.unb64u((String) res.get("sig"));
            Map<String, Object> out = new LinkedHashMap<>(res);
            out.remove("sig");
            out.put("sigVerifies", Pca.ed25519Strict(gpk, msg, sig));
            out.put("sigLength", sig.length);
            return out;
        });
        f.put("verifyHybridFrostCosign", (a, r) -> FrostPq.verifyHybridFrostCosign(arg(a, 0), bytes(arg(a, 1)), arg(a, 2), arg(a, 3), m(arg(a, 4))));
        f.put("pqQuorumRepresentative", (a, r) -> FrostPq.pqQuorumRepresentative(bytes(arg(a, 0))));
        f.put("signPqQuorum", (a, r) -> {
            List<Pq.KeyPair> kps = new ArrayList<>();
            for (Object s : l(arg(a, 1))) kps.add(mlDsa(s));
            return FrostPq.signPqQuorum(bytes(arg(a, 0)), kps, arg(a, 2));
        });
        f.put("normalizePqQuorumPool", (a, r) -> new ArrayList<Object>(FrostPq.normalizePqQuorumPool(l(arg(a, 0)))));
        f.put("verifyPqQuorum", (a, r) -> {
            Set<String> pool = new HashSet<>();
            for (Object p : l(arg(a, 2))) pool.add((String) p);
            return FrostPq.verifyPqQuorum(arg(a, 0), bytes(arg(a, 1)), pool, arg(a, 3));
        });

        List<Map<String, Object>> all = BaseOracle.of(MODULE, null);
        assertEquals(TOTAL, all.size());
        Set<String> fns = new TreeSet<>();
        for (Map<String, Object> c : all) fns.add((String) c.get("fn"));
        assertEquals(new TreeSet<>(f.keySet()), fns);
        for (Map.Entry<String, FrostRefSupport.Body> e : f.entrySet()) FrostRefSupport.each(MODULE, e.getKey(), e.getValue());
    }
}
