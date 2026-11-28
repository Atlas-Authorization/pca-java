package net.atlasauth.pca.pqthreshold;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.W3Bridge;

/**
 * The signed group descriptor that pins a FROST threshold to its group key. A FROST aggregate is a plain Ed25519 signature, so its threshold
 * is a label until an authority the verifier pins attests how the group was formed. Ed25519 and SHA-256 are the JDK/BouncyCastle ones.
 */
public final class GroupDescriptor {
    private GroupDescriptor() {}

    public static final int GROUP_DESCRIPTOR_VERSION = 1;
    public static final String GROUP_SUITE = "frost-ed25519";
    private static final String DESCRIPTOR_DOMAIN = "atlas-pca-pq-threshold/group-descriptor/v1\0";
    private static final String SIGNER_SET_DOMAIN = "atlas-pca-pq-threshold/signer-set/v1\0";
    public static final int MAX_GROUP_SIZE = 1024;

    // ---- JavaScript-flavoured value helpers (wire values arrive as parsed JSON) --------------------------------------

    /** The JavaScript number value of a parsed JSON number, or null when the value is not a number. */
    static Double numOf(Object o) {
        if (o instanceof Json.Num) { try { return Double.parseDouble(((Json.Num) o).raw); } catch (NumberFormatException e) { return null; } }
        if (o instanceof Integer || o instanceof Long || o instanceof Double || o instanceof Short) return ((Number) o).doubleValue();
        return null;
    }

    /** {@code Number.isInteger}. */
    static boolean isInteger(Object o) {
        Double d = numOf(o);
        return d != null && !d.isNaN() && !d.isInfinite() && d == Math.floor(d);
    }

    /** A member of a JSON object; an array or a non-object has no such member (null). */
    @SuppressWarnings("unchecked")
    static Object member(Object o, String k) { return o instanceof Map ? ((Map<String, Object>) o).get(k) : null; }

    static boolean isObject(Object o) { return o instanceof Map || o instanceof List; }

    static String asB64u(Object k) { return k instanceof byte[] ? Keys.b64u((byte[]) k) : k instanceof String ? (String) k : null; }

    private static String fmt(Object o) {
        Double d = numOf(o);
        if (d == null) return String.valueOf(o);
        return isInteger(o) && Math.abs(d) < 1e21 ? new BigDecimal(d).toBigInteger().toString() : String.valueOf(d);
    }

    private static byte[] sha256(byte[] b) {
        try { return MessageDigest.getInstance("SHA-256").digest(b); } catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    private static byte[] withDomain(String domain, byte[] body) {
        byte[] d = Json.utf8(domain);
        byte[] m = new byte[d.length + body.length];
        System.arraycopy(d, 0, m, 0, d.length);
        System.arraycopy(body, 0, m, d.length, body.length);
        return m;
    }

    // ---- signer set -----------------------------------------------------------------------------------------------

    /**
     * {@code sha256(DOMAIN || canonical(sorted [{id, pk}]))}; order-insensitive, ids distinct. Each participant is a JSON object
     * {identifier (positive safe integer), publicKey (canonical b64u 32 bytes, or raw bytes)}.
     */
    public static String signerSetCommitment(List<?> participants) {
        if (participants == null || participants.isEmpty() || participants.size() > MAX_GROUP_SIZE) throw new IllegalArgumentException("signerSetCommitment: need 1.." + MAX_GROUP_SIZE + " participants");
        List<long[]> ids = new ArrayList<>();
        List<String> pks = new ArrayList<>();
        for (Object p : participants) {
            if (p == null) throw new IllegalArgumentException("signerSetCommitment: participant is null");
            Object idObj = member(p, "identifier");
            String pk = asB64u(member(p, "publicKey"));
            Double id = numOf(idObj);
            if (id == null || !isInteger(idObj) || id <= 0 || id > 9007199254740991d) throw new IllegalArgumentException("signerSetCommitment: participant identifiers must be positive safe integers");
            if (pk == null || Pca.decodeB64uStrict(pk, 32) == null) throw new IllegalArgumentException("signerSetCommitment: verification share is not a canonical b64u(32) value");
            ids.add(new long[] {id.longValue()});
            pks.add(pk);
        }
        Integer[] order = new Integer[ids.size()];
        for (int i = 0; i < order.length; i++) order[i] = i;
        java.util.Arrays.sort(order, (a, b) -> Long.compare(ids.get(a)[0], ids.get(b)[0]));
        List<Object> rows = new ArrayList<>();
        for (int i = 0; i < order.length; i++) {
            if (i > 0 && ids.get(order[i])[0] == ids.get(order[i - 1])[0]) throw new IllegalArgumentException("signerSetCommitment: duplicate participant identifier");
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", ids.get(order[i])[0]);
            row.put("pk", pks.get(order[i]));
            rows.add(row);
        }
        return Keys.b64u(sha256(withDomain(SIGNER_SET_DOMAIN, Json.canonicalize(rows).getBytes(StandardCharsets.UTF_8))));
    }

    private static byte[] descriptorBytes(Object v, Object suite, Object groupPk, Object t, Object n, Object signerSet) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("v", v); body.put("suite", suite); body.put("group_pk", groupPk); body.put("t", t); body.put("n", n); body.put("signer_set", signerSet);
        return withDomain(DESCRIPTOR_DOMAIN, Json.canonicalize(body).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Issue a descriptor at dealing time: {descriptor: {v, suite, groupPublicKey, t, n, signerSetCommitment}, authority, sig}. The authority secret is a
     * 32-byte Ed25519 seed. Throws on an impossible group (t < 1, t > n, a non-canonical group key, a bad authority key).
     */
    public static Map<String, Object> issueGroupDescriptor(byte[] authoritySecretKey, Object groupPublicKey, Object t, List<?> participants) {
        int n = participants.size();
        Double td = numOf(t);
        if (td == null || !isInteger(t) || td < 1 || td > n) throw new IllegalArgumentException("issueGroupDescriptor: need 1 <= t <= n (t=" + t + ", n=" + n + ")");
        String gpk = asB64u(groupPublicKey);
        if (gpk == null || Pca.decodeB64uStrict(gpk, 32) == null) throw new IllegalArgumentException("issueGroupDescriptor: group public key is not canonical b64u(32)");
        if (authoritySecretKey == null || authoritySecretKey.length != 32) throw new IllegalArgumentException("issueGroupDescriptor: authority key must be a 32-byte Ed25519 secret key");
        String commitment = signerSetCommitment(participants);
        long tl = td.longValue();
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("v", (long) GROUP_DESCRIPTOR_VERSION); d.put("suite", GROUP_SUITE); d.put("groupPublicKey", gpk); d.put("t", tl); d.put("n", (long) n); d.put("signerSetCommitment", commitment);
        Keys.EdKey ak = Keys.edFromSeed(authoritySecretKey);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("descriptor", d);
        out.put("authority", ak.id());
        out.put("sig", Keys.b64u(ak.sign(descriptorBytes((long) GROUP_DESCRIPTOR_VERSION, GROUP_SUITE, gpk, tl, (long) n, commitment))));
        return out;
    }

    private static Map<String, Object> fail(String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("reason", reason);
        return m;
    }

    /**
     * Check a signed descriptor against the verifier's pins; never throws. {@code trustedAuthorities} are pinned b64u keys (String or byte[]),
     * {@code groupKey} the pinned group key, {@code t} the threshold the verifier requires (the descriptor's t must EQUAL it), and
     * {@code signerSetCommitment} an optional pin (null when absent). Returns {ok: true, descriptor} or {ok: false, reason}.
     */
    public static Map<String, Object> verifyGroupDescriptor(Object s, Object trustedAuthorities, Object groupKey, Object t, String signerSetCommitment) {
        try {
            if (!isObject(s)) return fail("no signed group descriptor: the threshold is unattested");
            Object d = member(s, "descriptor");
            Object authority = member(s, "authority"), sig = member(s, "sig");
            if (!isObject(d) || !(authority instanceof String) || !(sig instanceof String)) return fail("malformed group descriptor");
            Object dv = member(d, "v");
            Double dvn = numOf(dv);
            if (dvn == null || dvn != GROUP_DESCRIPTOR_VERSION || !GROUP_SUITE.equals(member(d, "suite"))) return fail("unsupported group descriptor version or suite");
            Object gpk = member(d, "groupPublicKey"), ssc = member(d, "signerSetCommitment");
            if (!(gpk instanceof String) || !(ssc instanceof String)) return fail("malformed group descriptor");
            Object dt = member(d, "t"), dn = member(d, "n");
            if (!isInteger(dt) || !isInteger(dn) || numOf(dt) < 1 || numOf(dn) < numOf(dt) || numOf(dn) > MAX_GROUP_SIZE) return fail("malformed group descriptor: need 1 <= t <= n");
            if (!(trustedAuthorities instanceof List)) return fail("group descriptor could not be verified (malformed)");
            Set<String> trusted = new HashSet<>();
            for (Object a : (List<?>) trustedAuthorities) { String x = asB64u(a); if (x != null) trusted.add(x); }
            if (!trusted.contains(authority)) return fail("group descriptor authority is not trusted");
            if (Pca.decodeB64uStrict(authority, 32) == null || Pca.decodeB64uStrict(sig, 64) == null) return fail("malformed authority key or signature");
            if (!W3Bridge.verifyB64u((String) authority, descriptorBytes((long) GROUP_DESCRIPTOR_VERSION, GROUP_SUITE, gpk, dt, dn, ssc), (String) sig)) return fail("group descriptor signature does not verify");
            if (!gpk.equals(asB64u(groupKey))) return fail("group descriptor is for a different group key");
            if (!isInteger(t) || numOf(t) < 1) return fail("required t must be a positive integer");
            if (!numOf(dt).equals(numOf(t))) return fail("group was set up as " + fmt(dt) + "-of-" + fmt(dn) + " but " + fmt(t) + " is required: the threshold is not bound to this key");
            if (signerSetCommitment != null && !ssc.equals(signerSetCommitment)) return fail("group descriptor is for a different signer set");
            Map<String, Object> ok = new LinkedHashMap<>();
            ok.put("ok", true);
            ok.put("descriptor", d);
            return ok;
        } catch (RuntimeException e) {
            return fail("group descriptor could not be verified (malformed)");
        }
    }
}
