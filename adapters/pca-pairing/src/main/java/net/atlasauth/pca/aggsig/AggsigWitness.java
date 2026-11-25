package net.atlasauth.pca.aggsig;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;

/**
 * BLS aggregation of transparency-ledger witness cosignatures: a quorum cosigns the same tree-head statement
 * {size, root, prev_root, guardian_epoch}; the quorum collapses into one 96-byte aggregate verified by one FastAggregateVerify.
 */
public final class AggsigWitness {
    private AggsigWitness() {}

    private static final String STH_WITNESS_BLS_DOMAIN = "atlas-pca/sth-witness-bls/v1\0";

    private static byte[] witnessMessage(Map<String, Object> h) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("size", h.get("size"));
        b.put("root", h.get("root"));
        b.put("prev_root", h.get("prev_root"));
        Object ge = h.get("guardian_epoch");
        b.put("guardian_epoch", ge == null ? new Json.Num("0") : ge);
        byte[] body = Json.canonicalizeStrict(b).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] p = AggsigCore.utf8(STH_WITNESS_BLS_DOMAIN);
        byte[] m = new byte[p.length + body.length];
        System.arraycopy(p, 0, m, 0, p.length);
        System.arraycopy(body, 0, m, p.length, body.length);
        return m;
    }

    /** A trusted witness cosigns the tree-head statement with its BLS secret key: {key, sig, suite}. */
    public static Map<String, Object> cosignTreeHead(Map<String, Object> statement, byte[] witnessSecret) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("key", Keys.b64u(AggsigCore.publicKeyOf(witnessSecret)));
        c.put("sig", Keys.b64u(AggsigCore.sign(witnessSecret, witnessMessage(statement))));
        c.put("suite", AggsigChain.BLS_SUITE);
        return c;
    }

    /** Verify ONE cosignature against the exact statement. Never throws. */
    public static boolean verifyWitnessCosignature(Map<String, Object> statement, Map<String, Object> cosig) {
        try {
            if (cosig == null || !AggsigChain.BLS_SUITE.equals(cosig.get("suite"))) return false;
            return AggsigCore.verify(Keys.unb64u((String) cosig.get("key")), witnessMessage(statement), Keys.unb64u((String) cosig.get("sig")));
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Collapse a quorum of cosignatures into one aggregate. Throws on an empty set or a sig that is not valid b64u. */
    public static byte[] aggregateWitnessCosignatures(List<Map<String, Object>> cosigs) {
        if (cosigs == null || cosigs.isEmpty()) throw new IllegalArgumentException("aggregateWitnessCosignatures: empty set");
        List<byte[]> sigs = new ArrayList<>();
        for (Map<String, Object> c : cosigs) sigs.add(Keys.unb64u((String) c.get("sig")));
        return Aggsig.aggregate(sigs);
    }

    /** One FastAggregateVerify over the statement for exactly the registered witness keys supplied; a repeated witness is refused. Never throws. */
    public static boolean verifyAggregatedWitnessCosignatures(Map<String, Object> statement, List<RegisteredKey> witnessKeys, byte[] aggSig) {
        try {
            if (witnessKeys == null || witnessKeys.isEmpty()) return false;
            Set<String> seen = new HashSet<>();
            for (RegisteredKey k : witnessKeys) if (!seen.add(Aggsig.hex(k.bytes()))) return false;
            return Aggsig.fastAggregateVerify(witnessKeys, witnessMessage(statement), aggSig);
        } catch (RuntimeException e) {
            return false;
        }
    }
}
