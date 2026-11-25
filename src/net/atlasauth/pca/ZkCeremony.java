package net.atlasauth.pca;

import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Circuit provenance and trusted-setup ceremony transcript checks for the Groth16 circuits: the verifying-key id, the provenance record
 * of a circuit build, and the structural check of a multi-party ceremony transcript (chained contributions, a random beacon, the final
 * key). Pure: SHA-256 and canonical JSON only. Transcripts, records and keys are parsed JSON values (maps, lists, strings, numbers).
 */
public final class ZkCeremony {
    private ZkCeremony() {}

    private static final Pattern H64 = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern VK_ID = Pattern.compile("vk_[0-9a-f]{64}");

    private static String hex(byte[] b) { return HexFormat.of().formatHex(b); }

    private static Object get(Object o, String k) { return o instanceof Map ? ((Map<?, ?>) o).get(k) : null; }

    private static boolean has(Object o, String k) { return o instanceof Map && ((Map<?, ?>) o).containsKey(k); }

    /** The reference's {@code H64.test(String(v))}: the text form of the value is 64 lower-case hex digits. */
    private static boolean h64(Object o, String k) { return H64.matcher(IntentRevocation.jsText(get(o, k), has(o, k))).matches(); }

    /** JavaScript {@code a[ka] === b[kb]} over parsed JSON (an absent member equals only an absent member). */
    private static boolean same(Object a, String ka, Object b, String kb) {
        boolean ha = has(a, ka), hb = has(b, kb);
        if (!ha || !hb) return ha == hb;
        return Ledger.jsEq(get(a, ka), get(b, kb));
    }

    /** {@code vk_} followed by the SHA-256 of the key's canonical JSON, in hex. */
    public static String vkId(Object vkey) { return "vk_" + hex(Pca.sha(Pca.canonBytes(vkey))); }

    /**
     * The provenance record {@code {circuit, sourceSha256, r1csSha256, vkId}} of a circuit build. {@code args} holds {@code circuit},
     * {@code sourceSha256}, {@code r1csSha256} and {@code vkey}. Throws on a malformed hash, an empty circuit id or a missing key.
     */
    public static Map<String, Object> circuitProvenance(Map<String, Object> args) {
        if (!h64(args, "sourceSha256") || !h64(args, "r1csSha256") || "".equals(args.get("circuit"))) throw new IllegalArgumentException("circuitProvenance: bad circuit id or hash");
        if (!args.containsKey("vkey")) throw new IllegalArgumentException("circuitProvenance: a verifying key is required");
        Map<String, Object> out = new LinkedHashMap<>();
        if (args.containsKey("circuit")) out.put("circuit", args.get("circuit"));
        out.put("sourceSha256", args.get("sourceSha256"));
        out.put("r1csSha256", args.get("r1csSha256"));
        out.put("vkId", vkId(args.get("vkey")));
        return out;
    }

    /**
     * Checks a provenance record against what the verifier pins ({@code expect}: {@code circuit}, {@code sourceSha256}, optional
     * {@code r1csSha256}, {@code vkey}). Returns the first problem, or null. Throws when {@code expect} carries no key.
     */
    public static String checkCircuitProvenance(Object prov, Map<String, Object> expect) {
        if (!(prov instanceof Map) && !(prov instanceof List)) return "not a provenance record";
        if (!same(prov, "circuit", expect, "circuit")) return "record is for another circuit";
        if (!same(prov, "sourceSha256", expect, "sourceSha256")) return "circuit sources differ from the pinned version";
        Object r = get(prov, "r1csSha256");
        if (!(r instanceof String) || !H64.matcher((String) r).matches() || (expect.containsKey("r1csSha256") && !same(prov, "r1csSha256", expect, "r1csSha256"))) return "constraint system differs";
        if (!expect.containsKey("vkey")) throw new IllegalArgumentException("checkCircuitProvenance: a verifying key is required");
        if (!vkId(expect.get("vkey")).equals(get(prov, "vkId"))) return "verifying key is not the recorded one";
        return null;
    }

    /** The SHA-256 of the transcript's canonical JSON, in hex. */
    public static String transcriptSha256(Object transcript) { return hex(Pca.sha(Pca.canonBytes(transcript))); }

    public static String checkTranscript(Object t) { return checkTranscript(t, null); }

    /**
     * Structural check of a version-1 ceremony transcript: at least {@code max(2, opts.minContributions, transcript.minContributions)}
     * contributions that chain from the initial key with distinct names and keys, a random beacon applied after the last one, the final
     * key equal to the beacon output and a verifying-key id. {@code opts} (nullable) may pin {@code circuit}, {@code r1csSha256} and
     * {@code minContributions}. Returns the first problem, or null.
     */
    public static String checkTranscript(Object x, Map<String, Object> opts) {
        if (!(x instanceof Map) || !Zk.isNum(get(x, "version"), 1)) return "not a version-1 transcript";
        Object circuit = get(x, "circuit");
        if (!(circuit instanceof String) || ((String) circuit).isEmpty()) return "no circuit id";
        if (opts != null && opts.containsKey("circuit") && !same(x, "circuit", opts, "circuit")) return "transcript is for another circuit";
        Object curve = get(x, "curve");
        if (!"bn128".equals(curve) && !"bls12-381".equals(curve)) return "unknown curve";
        for (String k : new String[] {"r1csSha256", "ptauSha256", "initZkeySha256"}) if (!h64(x, k)) return k + " is not a SHA-256";
        if (opts != null && opts.containsKey("r1csSha256") && !same(x, "r1csSha256", opts, "r1csSha256")) return "transcript is for a different constraint system";
        // Math.max(2, opts.minContributions ?? 2, the transcript's own minimum when it is a safe integer)
        Object om = opts == null ? null : opts.get("minContributions");
        Double o = om == null ? Double.valueOf(2) : IntentJs.num(om);
        if (o == null) throw new IllegalArgumentException("checkTranscript: minContributions must be a number");
        double own = IntentJs.isSafeInteger(get(x, "minContributions")) ? IntentJs.num(get(x, "minContributions")) : 2;
        double min = Double.isNaN(o) ? Double.NaN : Math.max(2, Math.max(o, own));
        Object cs = get(x, "contributions");
        if (!(cs instanceof List) || ((List<?>) cs).size() < min) return "fewer than " + IntentHistory.jsString(min) + " contributions";
        Set<String> names = new HashSet<>(), keys = new HashSet<>();
        Object prevHolder = x;
        String prevKey = "initZkeySha256";
        List<?> list = (List<?>) cs;
        for (int i = 0; i < list.size(); i++) {
            Object c = list.get(i);
            Object name = get(c, "name");
            Object idx = get(c, "index");
            boolean indexOk = Zk.isNum(idx, i) && !IntentJs.isNegZero(IntentJs.num(idx));
            if (!indexOk || !(name instanceof String) || ((String) name).isEmpty()) return "contribution " + i + " is malformed";
            if (!h64(c, "zkeySha256") || !same(c, "prevZkeySha256", prevHolder, prevKey)) return "contribution " + i + " does not chain from the previous key";
            Object key = get(c, "zkeySha256");
            if (names.contains(name) || (key instanceof String && keys.contains(key))) return "contribution " + i + " repeats a name or key";
            names.add((String) name);
            if (key instanceof String) keys.add((String) key);
            prevHolder = c;
            prevKey = "zkeySha256";
        }
        Object b = get(x, "beacon");
        Object it = get(b, "iterationsExp");
        if (!h64(b, "hashHex") || !IntentJs.isSafeInteger(it) || IntentJs.num(it) < 10 || IntentJs.num(it) > 63) return "no valid random beacon";
        if (!same(b, "prevZkeySha256", prevHolder, prevKey) || !h64(b, "zkeySha256")) return "beacon is not applied after the last contribution";
        if (!same(x, "finalZkeySha256", b, "zkeySha256")) return "final key is not the beacon output";
        Object id = get(x, "vkId");
        if (!(id instanceof String) || !VK_ID.matcher((String) id).matches()) return "no verifying-key id";
        return null;
    }

    /**
     * {@code "multi-party"} only when {@code evidence} ({@code {transcript, sha256, r1csSha256?, circuit?}}) is a well-formed transcript
     * whose digest is the pinned {@code sha256} and which names this verifying key; {@code "single-party"} otherwise. Never throws.
     */
    public static String ceremonyOf(Object vkey, Object evidence) {
        try {
            if (!Zk.truthy(vkey) || !Zk.truthy(evidence)) return "single-party";
            Object t = get(evidence, "transcript");
            Map<String, Object> opts = new LinkedHashMap<>();
            if (has(evidence, "r1csSha256")) opts.put("r1csSha256", get(evidence, "r1csSha256"));
            if (has(evidence, "circuit")) opts.put("circuit", get(evidence, "circuit"));
            if (checkTranscript(t, opts) != null) return "single-party";
            if (!transcriptSha256(t).equals(get(evidence, "sha256")) || !vkId(vkey).equals(get(t, "vkId"))) return "single-party";
            return "multi-party";
        } catch (RuntimeException e) {
            return "single-party";
        }
    }
}
