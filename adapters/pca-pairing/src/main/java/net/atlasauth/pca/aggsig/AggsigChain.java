package net.atlasauth.pca.aggsig;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;

/**
 * A BLS-suite attenuable capability chain: the same structure as the core chain (hash-linked, holder-to-issuer continuity,
 * append-only caveats) but each hop is signed with the BLS12-381 PoP scheme, so an M-hop chain's signatures collapse into one
 * 96-byte aggregate checked with one pairing-product AggregateVerify. Capabilities are JSON maps (issuer, holder, caveats,
 * parent?, id, body_digest, sig, suite).
 */
public final class AggsigChain {
    private AggsigChain() {}

    private static final String CAP_BLS_DOMAIN = "atlas-pca/cap-bls/v1\0";
    public static final String BLS_SUITE = "bls12-381-pop";
    public static final int MAX_CHAIN_DEPTH = 16;

    private static Map<String, Object> bodyOf(Map<String, Object> c) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("issuer", c.get("issuer"));
        b.put("holder", c.get("holder"));
        b.put("caveats", c.get("caveats"));
        b.put("parent", c.get("parent"));
        return b;
    }

    private static byte[] sigMessage(String bodyDigest) {
        byte[] d = Keys.unb64u(bodyDigest);
        byte[] p = AggsigCore.utf8(CAP_BLS_DOMAIN);
        byte[] m = new byte[p.length + d.length];
        System.arraycopy(p, 0, m, 0, p.length);
        System.arraycopy(d, 0, m, p.length, d.length);
        return m;
    }

    /** Identity of a capability: the hash of everything EXCEPT sig, so a free sig string cannot mint distinct identities for one hop. */
    public static String capHash(Map<String, Object> c) {
        Map<String, Object> rest = new LinkedHashMap<>(c);
        rest.remove("sig");
        return Pca.hashCanonical(rest);
    }

    @SuppressWarnings("unchecked")
    private static List<Object> cloneCaveats(List<?> cs) {
        return (List<Object>) Json.parse(Json.canonicalizeStrict(cs));
    }

    private static Map<String, Object> seal(String issuer, String holder, List<Object> caveats, String parent, byte[] signerSecret) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("issuer", issuer);
        body.put("holder", holder);
        body.put("caveats", caveats);
        body.put("parent", parent);
        String digest = Pca.hashCanonical(body);
        String sig = Keys.b64u(AggsigCore.sign(signerSecret, sigMessage(digest)));
        Map<String, Object> cap = new LinkedHashMap<>();
        cap.put("id", digest);
        cap.put("issuer", issuer);
        cap.put("holder", holder);
        cap.put("caveats", caveats);
        cap.put("body_digest", digest);
        cap.put("sig", sig);
        cap.put("suite", BLS_SUITE);
        if (parent != null) cap.put("parent", parent);
        return cap;
    }

    /** b64u BLS G1 public key for a secret scalar: the identity a chain is rooted at / delegated to. */
    public static String blsPublicKey(byte[] secretKey) { return Keys.b64u(AggsigCore.publicKeyOf(secretKey)); }

    /** Mint a root capability, signed by the principal. */
    public static Map<String, Object> mintBlsRoot(byte[] principalSecret, String principalPublic, String holder, List<?> caveats) {
        return seal(principalPublic, holder, cloneCaveats(caveats), null, principalSecret);
    }

    /** Child with the SAME holder; caveats = parent caveats then added. Signed by the parent's holder. */
    public static Map<String, Object> blsAttenuate(Map<String, Object> parent, List<?> added, byte[] signerSecret) {
        return blsDelegate(parent, (String) parent.get("holder"), added, signerSecret);
    }

    /** Like blsAttenuate, but rebinds the holder to a new sub-agent key. */
    public static Map<String, Object> blsDelegate(Map<String, Object> parent, String toHolder, List<?> added, byte[] signerSecret) {
        List<Object> cav = new ArrayList<>(cloneCaveats((List<?>) parent.get("caveats")));
        cav.addAll(cloneCaveats(added));
        return seal((String) parent.get("holder"), toHolder, cav, capHash(parent), signerSecret);
    }

    private static boolean wellTyped(Object o) {
        if (!(o instanceof Map)) return false;
        Map<?, ?> x = (Map<?, ?>) o;
        if (!(x.get("id") instanceof String && x.get("issuer") instanceof String && x.get("holder") instanceof String
                && x.get("body_digest") instanceof String && x.get("sig") instanceof String && BLS_SUITE.equals(x.get("suite")))) return false;
        if (x.containsKey("parent") && !(x.get("parent") instanceof String)) return false;
        if (!(x.get("caveats") instanceof List)) return false;
        for (Object cv : (List<?>) x.get("caveats")) {
            if (!(cv instanceof Map) || !(((Map<?, ?>) cv).get("type") instanceof String)) return false;
        }
        return true;
    }

    /** Collapse every per-hop signature into one 96-byte aggregate. Throws on an empty chain or a sig that is not valid b64u. */
    @SuppressWarnings("unchecked")
    public static byte[] aggregateChainSignatures(List<Object> chain) {
        if (chain == null || chain.isEmpty()) throw new IllegalArgumentException("aggregateChainSignatures: empty chain");
        List<byte[]> sigs = new ArrayList<>();
        for (Object c : chain) sigs.add(Keys.unb64u((String) ((Map<String, Object>) c).get("sig")));
        return Aggsig.aggregate(sigs);
    }

    private static Map<String, Object> ok() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", Boolean.TRUE);
        return m;
    }

    private static Map<String, Object> fail(String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", Boolean.FALSE);
        m.put("reason", reason);
        return m;
    }

    /**
     * Verify an entire BLS capability chain against one aggregate signature: depth bound, well-typedness, root has no parent,
     * optional expected root principal, parent hash-links, holder-to-issuer continuity, append-only caveat prefixes, then one
     * distinct-message AggregateVerify. Every hop issuer must be in the registry. Never throws.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyAggregatedChain(List<Object> chain, byte[] aggSig, KeyRegistry registry, String expectedRootPrincipal) {
        if (registry == null) return fail("a KeyRegistry of proof-of-possession-verified keys is required");
        if (chain == null || chain.isEmpty()) return fail("empty chain");
        if (chain.size() > MAX_CHAIN_DEPTH) return fail("chain too long (max " + MAX_CHAIN_DEPTH + " hops)");
        for (int i = 0; i < chain.size(); i++) if (!wellTyped(chain.get(i))) return fail("hop " + i + ": malformed capability");

        List<RegisteredKey> pks = new ArrayList<>();
        List<byte[]> msgs = new ArrayList<>();
        Map<String, Object> root = (Map<String, Object>) chain.get(0);
        if (root.containsKey("parent")) return fail("hop 0: root must not have a parent");
        if (expectedRootPrincipal != null && !expectedRootPrincipal.equals(root.get("issuer"))) return fail("hop 0: root issuer is not the expected principal");

        for (int i = 0; i < chain.size(); i++) {
            Map<String, Object> c = (Map<String, Object>) chain.get(i);
            String digest;
            try {
                digest = Pca.hashCanonical(bodyOf(c));
            } catch (RuntimeException e) {
                return fail("hop " + i + ": malformed body");
            }
            if (!digest.equals(c.get("body_digest")) || !c.get("id").equals(c.get("body_digest"))) return fail("hop " + i + ": body digest mismatch");

            RegisteredKey pk;
            try {
                pk = registry.get(Keys.unb64u((String) c.get("issuer")));
            } catch (RuntimeException e) {
                return fail("hop " + i + ": malformed issuer key");
            }
            if (pk == null) return fail("hop " + i + ": issuer key has no verified proof of possession (not in the registry)");

            if (i > 0) {
                Map<String, Object> parent = (Map<String, Object>) chain.get(i - 1);
                if (!capHash(parent).equals(c.get("parent"))) return fail("hop " + i + ": broken parent link");
                if (!c.get("issuer").equals(parent.get("holder"))) return fail("hop " + i + ": issuer is not the parent's bound holder");
                List<Object> cc = (List<Object>) c.get("caveats");
                List<Object> pc = (List<Object>) parent.get("caveats");
                if (cc.size() < pc.size()) return fail("hop " + i + ": drops parent caveat(s)");
                for (int j = 0; j < pc.size(); j++) {
                    if (!Pca.hashCanonical(cc.get(j)).equals(Pca.hashCanonical(pc.get(j)))) return fail("hop " + i + ": caveat " + j + " altered or reordered");
                }
            }
            pks.add(pk);
            msgs.add(sigMessage((String) c.get("body_digest")));
        }

        try {
            List<byte[]> raws = new ArrayList<>();
            for (int i = 0; i < chain.size(); i++) {
                String s = (String) ((Map<String, Object>) chain.get(i)).get("sig");
                byte[] raw = Keys.unb64u(s);
                if (!Keys.b64u(raw).equals(s)) return fail("hop " + i + ": non-canonical sig encoding");
                raws.add(raw);
            }
            if (!Arrays.equals(Aggsig.aggregate(raws), aggSig)) return fail("hop sig fields do not sum to the aggregate signature");
        } catch (RuntimeException e) {
            return fail("malformed hop sig");
        }

        if (!Aggsig.aggregateVerify(pks, msgs, aggSig)) return fail("aggregate signature does not verify over all hops");
        return ok();
    }
}
