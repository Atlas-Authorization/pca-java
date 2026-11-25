package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills (round 5, tag G2) for {@link Mesh}: a self-built, self-signed mesh proof (domain, witness and capability keys
 * are generated here) so every unsigned part of the evidence (hop evidence, cosignature table, pin proofs, bindings, revocation
 * maps, head table) can be varied while the signatures that cover the rest stay valid. Every expectation is the exact verdict the
 * reference (packages/pca/src/mesh.ts verifyMeshProof / checkCosignedHead / checkHeadAdvance) gives.
 */
public class K05R5G2MeshTest {

    // ---- helpers ----

    static Json.Num n(long v) { return IntentJs.ofLong(v); }
    static Map<String, Object> obj(Object... kv) { return MeshK05KillTest.obj(kv); }
    static Map<String, Object> m(Object o) { return MeshK05KillTest.m(o); }
    static List<Object> l(Object o) { return MeshK05KillTest.l(o); }
    static List<Object> list(Object... xs) { return new ArrayList<>(Arrays.asList(xs)); }
    static String vv(Mesh.Verdict r) { return MeshK05KillTest.v(r); }
    static byte[] msg(String domain, Object body) { return Pca.concat(domain.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(body)); }

    /** An Ed25519 key generated from a name (the conformance keys.json only has four). */
    static final class Key {
        final byte[] seed;
        final String pub;
        Key(String name) {
            seed = Pca.sha(name.getBytes(StandardCharsets.UTF_8));
            byte[] pk = new byte[32];
            org.bouncycastle.math.ec.rfc8032.Ed25519.generatePublicKey(seed, 0, pk, 0);
            pub = Pca.b64(pk);
        }
        String sign(byte[] message) {
            byte[] s = new byte[64];
            org.bouncycastle.math.ec.rfc8032.Ed25519.sign(seed, 0, message, 0, message.length, s, 0);
            return Pca.b64(s);
        }
    }

    static final long NOW = 1_000_000L;
    static final String[] NAMES = {"principal", "agent", "subagent"};

    static Map<String, Object> scope(String... a) { return obj("type", "scope", "actions", list((Object[]) a)); }
    static Map<String, Object> prefix(String p) { return obj("type", "resource", "prefix", p); }
    static Map<String, Object> aud(String... d) { return obj("type", "audience", "domains", list((Object[]) d)); }
    static Map<String, Object> maxHops(long k) { return obj("type", "max_hops", "n", n(k)); }
    static List<Object> base() { return list(scope("pay"), prefix("/o/"), aud("svc")); }
    static List<Object> plus(List<Object> a, Object... more) { List<Object> out = new ArrayList<>(a); out.addAll(Arrays.asList(more)); return out; }

    static final class M {
        final Key d = new Key("g2-domain"), w = new Key("g2-witness");
        final List<Object> chain = new ArrayList<>();
        final List<byte[]> leaves = new ArrayList<>();
        Map<String, Object> head, chm, proof, trust;
        List<Object> hops;
    }

    static Map<String, Object> binding(M x, String issuerPub, Object role) {
        Map<String, Object> body = obj("agent", issuerPub, "domain", x.d.pub, "role", role);
        return obj("agent", issuerPub, "domain", x.d.pub, "role", role, "sig", x.d.sign(msg(Mesh.BINDING_DOMAIN, body)));
    }

    /** A valid proof: one capability hop per element of perHop (principal -> agent -> subagent), one head, an empty revocation set. */
    static M build(List<List<Object>> perHop, int extraLeaves) throws Exception {
        M x = new M();
        Map<String, Object> prev = null;
        for (int i = 0; i < perHop.size(); i++) {
            Map<String, Object> cap = PqChainTest.cap(PqChainTest.pub(NAMES[i]), PqChainTest.pub(NAMES[i + 1]), new ArrayList<>(perHop.get(i)),
                prev == null ? null : Pca.capHash(prev), NAMES[i], null, null, null);
            x.chain.add(cap);
            prev = cap;
        }
        for (Object c : x.chain) x.leaves.add(Pca.leafHash(Pca.capHash(m(c))));
        for (int i = 0; i < extraLeaves; i++) x.leaves.add(Pca.leafHash("extra-" + i));
        x.head = obj("domain", x.d.pub, "root", Pca.b64(Pca.build(x.leaves)), "rev_root", Mesh.bindRevRoot(0, Ledger.EMPTY_TREE_ROOT),
            "size", n(x.leaves.size()), "rev_size", n(0), "timestamp", n(NOW));
        x.chm = obj("head", x.head, "sig", x.d.sign(msg(Mesh.HEAD_DOMAIN, x.head)),
            "cosigs", list(obj("witness", x.w.pub, "sig", x.w.sign(msg(Mesh.COSIG_DOMAIN, x.head)))));
        x.hops = new ArrayList<>();
        for (int i = 0; i < x.chain.size(); i++) {
            Map<String, Object> ev = obj("domain", x.d.pub, "head", n(0),
                "inclusion", obj("index", n(i), "size", n(x.leaves.size()), "path", MeshK05KillTest.path(x.leaves, i)),
                "revocation", obj("cap", obj("size", n(0)), "issuer_key", obj("size", n(0))));
            if (i > 0) ev.put("binding", binding(x, PqChainTest.pub(NAMES[i]), "agent"));
            x.hops.add(ev);
        }
        Map<String, Object> action = obj("type", "pay", "resource", "/o/1", "service_domain", "svc", "nonce", "n1", "at", n(NOW));
        String tipHash = Pca.capHash(m(x.chain.get(x.chain.size() - 1)));
        String actionSig = PqChainTest.edSign(NAMES[perHop.size()], msg(Mesh.ACTION_DOMAIN, obj("action", action, "tip", tipHash)));
        x.proof = obj("chain", x.chain, "hops", x.hops, "heads", list(x.chm), "rev_leaves", list(), "action", action, "action_sig", actionSig);
        x.trust = obj("humanPrincipal", PqChainTest.pub("principal"), "witnesses", list(x.w.pub), "threshold", n(1), "now", n(NOW),
            "allowedDomains", list(x.d.pub), "rootDomain", x.d.pub);
        return x;
    }

    static Mesh.Verdict run(M x) { return Mesh.verifyMeshProof(x.proof, x.trust); }

    // ---- the valid proof and the admission of the action ----

    @Test void validProofWithoutAHopCaveatIsAdmitted() throws Exception {
        M x = build(List.of(base()), 0);
        Mesh.Verdict r = run(x);
        assertEquals("ok", vv(r));
        assertTrue(r.ok);
        assertEquals("", r.reason);
        assertEquals(-1, r.hop);
    }

    @Test void maxHopsCountsTheChainLength() throws Exception {
        assertEquals("ok", vv(run(build(List.of(base(), plus(base(), maxHops(2))), 0))));
        assertEquals("action not admitted: chain exceeds max_hops 1|-1", vv(run(build(List.of(base(), plus(base(), maxHops(1))), 0))));
        assertEquals("ok", vv(run(build(List.of(base(), base()), 0))));
    }

    @Test void admissionNeedsTheActionsOwnTypeResourceAndDomain() throws Exception {
        M x = build(List.of(base()), 0);
        Map<String, Object> a = m(x.proof.get("action"));
        // the action fields are what the admission reads (a mutated read would use the key text itself)
        assertEquals("ok", vv(run(x)));
        assertEquals("pay", a.get("type"));
        x = build(List.of(list(scope("other"), prefix("/o/"), aud("svc"))), 0);
        assertEquals("action not admitted: action \"pay\" not in scope|-1", vv(run(x)));
        x = build(List.of(list(scope("pay"), prefix("/p/"), aud("svc"))), 0);
        assertEquals("action not admitted: resource \"/o/1\" outside prefix \"/p/\"|-1", vv(run(x)));
        x = build(List.of(list(scope("pay"), prefix("/o/"), aud("elsewhere"))), 0);
        assertEquals("action not admitted: service domain not in audience|-1", vv(run(x)));
    }

    // ---- the auth record starts with empty lists ----

    @Test void effectiveAuthorityStartsWithEmptyLists() {
        Mesh.Auth e = Mesh.effective(MeshK05KillTest.js("[]"));
        assertNotNull(e.actions);
        assertNotNull(e.audience);
        assertNotNull(e.prefixes);
        assertTrue(e.actions.isEmpty());
        assertTrue(e.audience.isEmpty());
        assertTrue(e.prefixes.isEmpty());
    }

    // ---- narrowing of the scope caveat ----

    @Test void narrowingScope() {
        String p = "[{\"type\":\"scope\",\"actions\":[\"a\",\"b\"]}]";
        assertFalse(MeshK05KillTest.narrows("[]", p));
        assertFalse(MeshK05KillTest.narrows("[{\"type\":\"scope\",\"actions\":[\"c\"]}]", p));
        assertFalse(MeshK05KillTest.narrows("[{\"type\":\"scope\",\"actions\":[\"a\",\"c\"]}]", p));
        assertTrue(MeshK05KillTest.narrows("[{\"type\":\"scope\",\"actions\":[\"a\"]}]", p));
        assertTrue(MeshK05KillTest.narrows("[{\"type\":\"scope\",\"actions\":[\"b\",\"a\"]}]", p));
        assertTrue(MeshK05KillTest.narrows("[{\"type\":\"scope\",\"actions\":[]}]", p));
        assertTrue(MeshK05KillTest.narrows("[{\"type\":\"scope\",\"actions\":[\"z\"]}]", "[]"));
        assertTrue(MeshK05KillTest.narrows("[]", "[]"));
    }

    // ---- the cosignature table ----

    @Test void cosignatureTableIsBoundedAt256() throws Exception {
        for (int total : new int[] {1, 255, 256, 257, 300}) {
            M x = build(List.of(base()), 0);
            List<Object> cs = l(x.chm.get("cosigs"));
            while (cs.size() < total) cs.add("x"); // a non-object entry is skipped
            assertEquals(total > 256 ? "source-domain anchor: malformed head|0" : "ok", vv(run(x)), "cosigs " + total);
        }
    }

    @Test void onlyTrustedWitnessesWithAValidSignatureCount() throws Exception {
        String none = "source-domain anchor: head has 0/1 trusted witness cosignatures|0";
        M x = build(List.of(base()), 0);
        Key rogue = new Key("g2-untrusted-witness");
        x.chm.put("cosigs", list(obj("witness", rogue.pub, "sig", rogue.sign(msg(Mesh.COSIG_DOMAIN, x.head)))));
        assertEquals(none, vv(run(x)));
        x.chm.put("cosigs", list(obj("witness", x.w.pub, "sig", x.w.sign(msg(Mesh.COSIG_DOMAIN, obj("other", n(1)))))));
        assertEquals(none, vv(run(x)));
        x.chm.put("cosigs", list(obj("witness", x.w.pub)));
        assertEquals(none, vv(run(x)));
        x.chm.put("cosigs", list(obj("sig", x.w.sign(msg(Mesh.COSIG_DOMAIN, x.head)))));
        assertEquals(none, vv(run(x)));
        x.chm.put("cosigs", "x");
        assertEquals("source-domain anchor: malformed head|0", vv(run(x)));
        x.chm.remove("cosigs");
        assertEquals("source-domain anchor: malformed head|0", vv(run(x)));
        // a duplicated trusted cosignature counts once: threshold 2 over two witnesses
        Key w2 = new Key("g2-witness-2");
        x.chm.put("cosigs", list(obj("witness", x.w.pub, "sig", x.w.sign(msg(Mesh.COSIG_DOMAIN, x.head))),
            obj("witness", x.w.pub, "sig", x.w.sign(msg(Mesh.COSIG_DOMAIN, x.head)))));
        x.trust.put("witnesses", list(x.w.pub, w2.pub));
        x.trust.put("threshold", n(2));
        assertEquals("source-domain anchor: head has 1/2 trusted witness cosignatures|0", vv(run(x)));
        l(x.chm.get("cosigs")).set(1, obj("witness", w2.pub, "sig", w2.sign(msg(Mesh.COSIG_DOMAIN, x.head))));
        assertEquals("ok", vv(run(x)));
    }

    // ---- revocation maps that refuse a null key ----

    @Test void immutableRevocationMapsAreAccepted() throws Exception {
        M x = build(List.of(base()), 0);
        m(x.hops.get(0)).put("revocation", Map.of("cap", Map.of("size", n(0)), "issuer_key", Map.of("size", n(0))));
        assertEquals("ok", vv(run(x)));
    }

    // ---- pinned heads ----

    @Test void pinnedHeadTruthiness() throws Exception {
        String malformed = "source-domain anchor: malformed head (vs pinned head)|0";
        Object[][] rows = {
            {null, "ok"}, {Boolean.FALSE, "ok"}, {"", "ok"}, {0.0d, "ok"}, {-0.0d, "ok"}, {Double.NaN, "ok"}, {0L, "ok"},
            {Boolean.TRUE, malformed}, {"x", malformed}, {1.0d, malformed}, {-1.0d, malformed}, {0.5d, malformed}, {list(), malformed}, {obj(), malformed},
        };
        for (Object[] row : rows) {
            M x = build(List.of(base()), 0);
            x.trust.put("pinnedHeads", obj(x.d.pub, row[0]));
            assertEquals(row[1], vv(run(x)), String.valueOf(row[0]));
        }
    }

    @Test void pinProofIsChosenByTheHeadsDomain() throws Exception {
        M x = build(List.of(base()), 1); // the head covers [cap leaf, extra leaf]
        Map<String, Object> pinned = obj("domain", x.d.pub, "root", Pca.b64(x.leaves.get(0)), "rev_root", x.head.get("rev_root"),
            "size", n(1), "rev_size", n(0), "timestamp", n(NOW));
        x.trust.put("pinnedHeads", obj(x.d.pub, pinned));
        Map<String, Object> good = MeshK05KillTest.cproof(1, 2, list(Pca.b64(x.leaves.get(1))));
        Map<String, Object> wrong = MeshK05KillTest.cproof(1, 2, list(Pca.b64(x.leaves.get(0))));
        x.proof.put("pin_proofs", list(obj("domain", x.d.pub, "proof", good)));
        assertEquals("ok", vv(run(x)));
        x.proof.put("pin_proofs", list(obj("domain", "another-domain", "proof", good)));
        assertEquals("source-domain anchor: consistency proof required for a larger head (vs pinned head)|0", vv(run(x)));
        x.proof.put("pin_proofs", list(obj("domain", "another-domain", "proof", wrong), obj("domain", x.d.pub, "proof", good)));
        assertEquals("ok", vv(run(x)));
        x.proof.put("pin_proofs", list(obj("domain", x.d.pub, "proof", wrong), obj("domain", x.d.pub, "proof", good)));
        assertEquals("source-domain anchor: head is not consistent with the previous head (fork or rewrite) (vs pinned head)|0", vv(run(x)));
        x.proof.remove("pin_proofs");
        assertEquals("source-domain anchor: consistency proof required for a larger head (vs pinned head)|0", vv(run(x)));
    }

    // ---- the proof's tables ----

    @Test void everyTableMustBeAList() {
        for (String key : new String[] {"chain", "hops", "heads", "rev_leaves"}) {
            Map<String, Object> p = MeshK05KillTest.junk(0, 0, 0);
            p.remove(key);
            assertEquals("malformed proof|-1", vv(Mesh.verifyMeshProof(p, MeshK05KillTest.trust())), key + " missing");
            p.put(key, "x");
            assertEquals("malformed proof|-1", vv(Mesh.verifyMeshProof(p, MeshK05KillTest.trust())), key + " not a list");
            p.put(key, obj());
            assertEquals("malformed proof|-1", vv(Mesh.verifyMeshProof(p, MeshK05KillTest.trust())), key + " an object");
        }
    }

    @Test void pinProofEntriesAreChecked() {
        Map<String, Object> good = MeshK05KillTest.cproof(0, 0, new ArrayList<Object>());
        Object[] bad = {
            "x", null, obj("domain", n(5), "proof", good), obj("proof", good), obj("domain", "d", "proof", "x"), obj("domain", "d"),
            obj("domain", "d", "proof", MeshK05KillTest.cproof(0, 0, "x")),
        };
        for (Object entry : bad) {
            Map<String, Object> p = MeshK05KillTest.junk(1, 0, 0);
            p.put("pin_proofs", list(entry));
            assertEquals("malformed pin proofs|-1", vv(Mesh.verifyMeshProof(p, MeshK05KillTest.trust())), String.valueOf(entry));
        }
        Map<String, Object> p = MeshK05KillTest.junk(1, 0, 0);
        p.put("pin_proofs", list(obj("domain", "d", "proof", good)));
        assertEquals(MeshK05KillTest.BAD_HOP, vv(Mesh.verifyMeshProof(p, MeshK05KillTest.trust())));
    }

    @Test void aHeadEntryWithoutAHeadIsMalformed() throws Exception {
        M x = build(List.of(base()), 0);
        x.proof.put("heads", list(obj()));
        assertEquals("malformed proof|-1", vv(run(x)));
        x.proof.put("heads", list("x"));
        assertEquals("malformed proof|-1", vv(run(x)));
        x.proof.put("heads", list(obj("head", null)));
        assertEquals("malformed proof|-1", vv(run(x)));
        x.proof.put("heads", list(obj("head", "x")));
        assertEquals("source-domain anchor: head is for a different domain|0", vv(run(x)));
    }

    // ---- hop evidence ----

    @Test void inclusionSizeMustEqualTheHeadsSize() throws Exception {
        M x = build(List.of(base()), 2); // head size 3
        assertEquals("ok", vv(run(x)));
        // size 4 has the same audit-path shape for leaf 0 and the same hashes: only the size check refuses it
        m(m(x.hops.get(0)).get("inclusion")).put("size", n(4));
        assertEquals("hop not included in the issuing domain log|0", vv(run(x)));
        m(m(x.hops.get(0)).get("inclusion")).put("size", n(3));
        assertEquals("ok", vv(run(x)));
        m(x.hops.get(0)).remove("inclusion");
        assertEquals("hop not included in the issuing domain log|0", vv(run(x)));
    }

    @Test void domainBindingMustNameTheIssuerAndCarryARoleAndSignature() throws Exception {
        String issuer = PqChainTest.pub("agent");
        String missing = "missing or mismatched domain binding for issuer|1";
        M x = build(List.of(base(), base()), 0);
        assertEquals("ok", vv(run(x)));
        Map<String, Object> ev = m(x.hops.get(1));
        // no role, but a signature over {agent, domain, role: null}: the role check alone refuses it
        Map<String, Object> noRole = binding(x, issuer, null);
        noRole.remove("role");
        ev.put("binding", noRole);
        assertEquals(missing, vv(run(x)));
        // no signature
        Map<String, Object> noSig = binding(x, issuer, "agent");
        noSig.remove("sig");
        ev.put("binding", noSig);
        assertEquals(missing, vv(run(x)));
        // another agent's binding, validly signed by the domain
        ev.put("binding", binding(x, PqChainTest.pub("rogue"), "agent"));
        assertEquals(missing, vv(run(x)));
        // another domain
        Map<String, Object> otherDomain = binding(x, issuer, "agent");
        otherDomain.put("domain", "another-domain");
        ev.put("binding", otherDomain);
        assertEquals(missing, vv(run(x)));
        ev.remove("binding");
        assertEquals(missing, vv(run(x)));
        ev.put("binding", "x");
        assertEquals(missing, vv(run(x)));
        // a non-string role / signature
        Map<String, Object> numRole = binding(x, issuer, "agent");
        numRole.put("role", n(5));
        ev.put("binding", numRole);
        assertEquals(missing, vv(run(x)));
        // a signature by another key
        Map<String, Object> forged = binding(x, issuer, "agent");
        forged.put("sig", new Key("g2-forger").sign(msg(Mesh.BINDING_DOMAIN, obj("agent", issuer, "domain", x.d.pub, "role", "agent"))));
        ev.put("binding", forged);
        assertEquals("domain binding signature invalid|1", vv(run(x)));
    }

    // ---- checkHeadAdvance ----

    static Map<String, Object> hd(long size, String root, long revSize, String revRoot) {
        return obj("domain", "D", "root", root, "rev_root", revRoot, "size", n(size), "rev_size", n(revSize), "timestamp", n(0));
    }

    @Test void headsThatShrinkRollBack() {
        assertEquals("head rolls back", Mesh.checkHeadAdvance(hd(3, "R3", 0, "v"), hd(2, "R2", 0, "v"), null));
        assertEquals("head rolls back", Mesh.checkHeadAdvance(hd(2, "R", 5, "v5"), hd(2, "R", 3, "v3"), null));
        assertEquals("head rolls back", Mesh.checkHeadAdvance(hd(2, "R", 1, "v1"), hd(2, "R", 0, "v0"), null));
        assertEquals("head rolls back", Mesh.checkHeadAdvance(hd(5, "R", 0, "v"), hd(4, "R", 9, "w"), null));
        assertEquals("", Mesh.checkHeadAdvance(hd(3, "R", 4, "v"), hd(3, "R", 4, "v"), null));
        assertEquals("", Mesh.checkHeadAdvance(hd(3, "R", 0, "v"), hd(3, "R", 0, "v"), null));
        assertEquals("", Mesh.checkHeadAdvance(hd(2, "R", 2, "va"), hd(2, "R", 3, "vb"), null));
        assertEquals("", Mesh.checkHeadAdvance(hd(2, "R", 0, "va"), hd(2, "R", 3, "vb"), null));
    }

    @Test void theRevocationSetCannotFork() {
        assertEquals("equivocation (revocation set)", Mesh.checkHeadAdvance(hd(3, "R", 4, "va"), hd(3, "R", 4, "vb"), null));
        assertEquals("equivocation (revocation set)", Mesh.checkHeadAdvance(hd(3, "R", 1, "va"), hd(3, "R", 1, "vb"), null));
        assertEquals("equivocation (revocation set)", Mesh.checkHeadAdvance(hd(3, "R", 0, "va"), hd(3, "R", 0, "vb"), null));
        assertEquals("equivocation (same size, different log)", Mesh.checkHeadAdvance(hd(3, "R", 4, "v"), hd(3, "S", 4, "v"), null));
    }

    @Test void validConsistencyProofsAreAccepted() {
        for (int first = 1; first <= 7; first++) {
            for (int second = first + 1; second <= 9; second++) {
                assertEquals("", Mesh.checkHeadAdvance(MeshK05KillTest.head(first, MeshK05KillTest.logRoot(first)), MeshK05KillTest.head(second, MeshK05KillTest.logRoot(second)),
                    MeshK05KillTest.cproof(first, second, MeshK05KillTest.consistencyPath(first, second))), first + "->" + second);
            }
        }
    }

    /** A proof whose path ends before the new tree's levels do, with a new root claimed to be the partial hash: refused. */
    @Test void aShortPathThatReachesAnIntermediateNodeIsNotConsistent() {
        String fork = "head is not consistent with the previous head (fork or rewrite)";
        // old size 1, claimed new size 3 with the root of the first two leaves
        assertEquals(fork, Mesh.checkHeadAdvance(MeshK05KillTest.head(1, MeshK05KillTest.logRoot(1)), MeshK05KillTest.head(3, MeshK05KillTest.logRoot(2)),
            MeshK05KillTest.cproof(1, 3, list(Pca.b64(MeshK05KillTest.LOG.get(1))))));
        // the honest 1 -> 2 proof (a complete walk) is accepted
        assertEquals("", Mesh.checkHeadAdvance(MeshK05KillTest.head(1, MeshK05KillTest.logRoot(1)), MeshK05KillTest.head(2, MeshK05KillTest.logRoot(2)),
            MeshK05KillTest.cproof(1, 2, list(Pca.b64(MeshK05KillTest.LOG.get(1))))));
        // old size 2, claimed new size 5 with the root of the first four leaves
        assertEquals(fork, Mesh.checkHeadAdvance(MeshK05KillTest.head(2, MeshK05KillTest.logRoot(2)), MeshK05KillTest.head(5, MeshK05KillTest.logRoot(4)),
            MeshK05KillTest.cproof(2, 5, list(Pca.b64(Pca.build(MeshK05KillTest.LOG.subList(2, 4)))))));
    }
}
