package net.atlasauth.pca.invariants;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Issue;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.revoke.JsVal;

/**
 * The deterministic building blocks of the PCA safety-invariant harness: Ed25519 key pairs derived from seeds, the builder of
 * legally attenuating signed delegation chains from a model, the "pointwise worse risk input" helper and the registry constants.
 * The property layer lives beside it: {@link Arbitraries} (seeded generators over {@link Rng}), {@link InvariantProperties} (the twelve
 * properties, the registry and {@code checkInvariants}), with no property-testing dependency.
 */
public final class Invariants {
    private Invariants() {}

    public static final long DEFAULT_SEED = 20260108L;
    public static final int DEFAULT_NUM_RUNS = 1000;

    /** The names of the twelve safety invariants, in registry order. */
    public static final List<String> INVARIANT_NAMES = List.of(
        "attenuation-monotonicity", "risk-wellformed-and-monotone", "admission-soundness", "cumulative-budget-bound",
        "fail-closed:undecidable-leaf", "fail-closed:undecidable-groups", "fail-closed:member-of-cycle-safe", "fail-closed:unknown-caveat-type",
        "fail-closed:forged-chain-rejected", "fail-closed:garbage-chain-rejected", "forbid-monotone", "determinism");

    /** An Ed25519 key pair whose 32-byte secret IS the seed. */
    public static final class GenKeyPair {
        public final byte[] secretKey;
        public final byte[] publicKey;
        /** The b64u public key: the string form used as {@code issuer} / {@code holder}. */
        public final String pub;
        private final Keys.EdKey key;

        GenKeyPair(byte[] secretKey, Keys.EdKey key) { this.secretKey = secretKey; this.key = key; this.publicKey = key.pub; this.pub = key.id(); }

        /** The signing key of this pair. */
        public Keys.EdKey key() { return key; }

        /** {secretKey, publicKey, pub}. */
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("secretKey", secretKey);
            m.put("publicKey", publicKey);
            m.put("pub", pub);
            return m;
        }
    }

    /** The key pair whose secret is {@code seed} (32 bytes; any other length throws). */
    public static GenKeyPair keyPairFromSeed(byte[] seed) {
        if (seed == null || seed.length != 32) throw new IllegalArgumentException("private key of length 32 expected, got " + (seed == null ? 0 : seed.length));
        return new GenKeyPair(seed.clone(), Keys.edFromSeed(seed));
    }

    private static final double BUDGET_ALLOC_BASE = 1_000_000;

    private static Json.Num num(long v) { return new Json.Num(Long.toString(v)); }

    private static Map<String, Object> caveat(String type, Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("type", type);
        for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]);
        return m;
    }

    /** One caveat spec to a concrete caveat, threading the running budget allocation (monotone non-increasing). */
    private static Map<String, Object> specToCaveat(Map<String, Object> spec, double[] running) {
        Object k = spec.get("k");
        if ("expires".equals(k)) return caveat("expires", "at", spec.get("at"));
        if ("not_before".equals(k)) return caveat("not_before", "at", spec.get("at"));
        if ("rate".equals(k)) return caveat("rate", "max", spec.get("max"), "per_secs", spec.get("per_secs"));
        if ("max_blast_radius".equals(k)) return caveat("max_blast_radius", "max", spec.get("max"));
        if ("reversibility_max".equals(k)) return caveat("reversibility_max", "class", spec.get("cls"));
        if ("delegation_depth".equals(k)) return caveat("delegation_depth", "max", spec.get("max"));
        if ("budget_frac".equals(k)) {
            double base = !Double.isNaN(running[0]) && !Double.isInfinite(running[0]) ? running[0] : BUDGET_ALLOC_BASE;
            // frac in [0,1] and base a non-negative integer: the floor is an integer in [0, base], never above the previous allocation
            double limit = Math.floor(base * JsVal.num(spec.get("frac")));
            running[0] = limit;
            return caveat("budget_alloc", "limit", num((long) limit));
        }
        // a spec of no known kind falls through the reference's switch and yields undefined, which cannot be signed
        throw new IllegalArgumentException("unknown caveat spec kind: " + JsVal.str(k));
    }

    @SuppressWarnings("unchecked")
    private static List<Object> specs(Object o) {
        List<Object> out = new ArrayList<>();
        return o == null ? out : (List<Object>) o;
    }

    /**
     * Build a signed, legally attenuating chain from a model: {@code principalSeed}, {@code holder0Seed} (32-byte seeds),
     * {@code rootSpecs}, {@code hops} ({@code holderSeed}, {@code addedSpecs}) and the fixed envelope {@code predicates}. Returns
     * {caps, predicates, rootIssuer, holders}.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> buildChain(Map<String, Object> m) {
        double[] running = {Double.POSITIVE_INFINITY};
        GenKeyPair principal = keyPairFromSeed((byte[]) m.get("principalSeed"));
        GenKeyPair holder0 = keyPairFromSeed((byte[]) m.get("holder0Seed"));

        List<Object> rootCaveats = new ArrayList<>();
        for (Object s : specs(m.get("rootSpecs"))) rootCaveats.add(specToCaveat((Map<String, Object>) s, running));
        Map<String, Object> root = Issue.mintRoot(Keys.ed25519(principal.key()), holder0.pub, null, rootCaveats);

        List<Object> caps = new ArrayList<>();
        caps.add(root);
        List<Object> holders = new ArrayList<>();
        holders.add(holder0.pub);
        Map<String, Object> prev = root;
        GenKeyPair signer = holder0; // the next hop is signed by the key the parent is bound to
        for (Object ho : specs(m.get("hops"))) {
            Map<String, Object> hop = (Map<String, Object>) ho;
            GenKeyPair to = keyPairFromSeed((byte[]) hop.get("holderSeed"));
            List<Object> added = new ArrayList<>();
            for (Object s : specs(hop.get("addedSpecs"))) added.add(specToCaveat((Map<String, Object>) s, running));
            Map<String, Object> cap = Issue.delegate(prev, to.pub, added, Keys.ed25519(signer.key()), null);
            caps.add(cap);
            holders.add(to.pub);
            prev = cap;
            signer = to;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("caps", caps);
        out.put("predicates", m.get("predicates"));
        out.put("rootIssuer", principal.pub);
        out.put("holders", holders);
        return out;
    }

    private static double clamp01(double x) { return x < 0 ? 0 : x > 1 ? 1 : x; }

    private static double d(Object o) { return JsVal.num(o); }

    /**
     * A risk input that is at least {@code base} in every risk-increasing axis and at most it in every protective axis. {@code d}
     * holds the non-negative deltas {@code dSem}, {@code dBlast}, {@code dTaint}, {@code dAge}, {@code dRev}, {@code dConf}.
     */
    public static Map<String, Object> worsen(Map<String, Object> base, Map<String, Object> d) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("semanticDistance", clamp01(d(base.get("semanticDistance")) + d(d.get("dSem"))));
        out.put("blastRadius", clamp01(d(base.get("blastRadius")) + d(d.get("dBlast"))));
        out.put("taint", clamp01(d(base.get("taint")) + d(d.get("dTaint"))));
        out.put("age", clamp01(d(base.get("age")) + d(d.get("dAge"))));
        out.put("reversibility", clamp01(d(base.get("reversibility")) - d(d.get("dRev"))));
        out.put("confidence", clamp01(d(base.get("confidence")) - d(d.get("dConf"))));
        return out;
    }
}
