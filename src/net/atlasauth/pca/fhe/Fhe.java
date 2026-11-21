package net.atlasauth.pca.fhe;

import java.math.BigDecimal;
import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.Json;

/**
 * The pure, scheme-independent parts of the homomorphic risk gate: risk-input transformation and fixed-point quantization, the
 * public gate policy, the risk claim binding read from a signed action, and the plaintext reference verdict. Values are parsed
 * JSON (maps, lists, {@link Json.Num}); a JavaScript number that is not finite is the fail-closed worst case, as in the reference.
 *
 * <p>NOT ported: the BFV evaluation itself (key generation, encryption of the risk inputs, the homomorphic weighted sum and slack,
 * decryption of the verdict). It runs on Microsoft SEAL through its WebAssembly build in the reference; there is no vetted,
 * maintained JVM binding for SEAL, and a hand-written BFV would be a hand-rolled lattice cryptosystem, so those entry points
 * (createFheContext, keygen, encryptRiskInputs, evalRiskGate, decryptVerdict, encryptedRiskClaim, evalSignedRiskClaim) are
 * n/a here. The signed-claim layer in {@link Origin} is scheme-independent and is ported in full: a Java verifier can check a
 * claim produced by the reference and attest a verdict over a ciphertext it never opens.
 */
public final class Fhe {
    private Fhe() {}

    public static final int POLY_MODULUS_DEGREE = 8192;
    public static final int PLAIN_MODULUS_BITS = 30;
    public static final long PLAIN_MODULUS = 1_073_692_673L;
    public static final long SIGNED_BOUND = PLAIN_MODULUS / 2;
    public static final long DEFAULT_SCALE = 1000;
    public static final int RISK_DIM = 6;

    private static final String[] INPUT_FIELDS = {"semanticDistance", "reversibility", "blastRadius", "taint", "confidence", "age"};

    /** The JavaScript number value of a parsed JSON number; NaN for anything that is not a number (Number.isFinite fails). */
    static double num(Object o) {
        if (o instanceof Json.Num) {
            try { return Double.parseDouble(o.toString()); } catch (NumberFormatException e) { return Double.NaN; }
        }
        if (o instanceof Number) return ((Number) o).doubleValue();
        return Double.NaN;
    }

    private static boolean finite(double x) { return !Double.isNaN(x) && !Double.isInfinite(x); }

    private static double clamp01(double x) { return x < 0 ? 0 : x > 1 ? 1 : x; }

    private static double unit(double x, double worst) { return finite(x) ? clamp01(x) : worst; }

    private static double wt(double x) { return finite(x) && x > 0 ? x : 0; }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) {
        if (!(o instanceof Map)) throw new IllegalArgumentException("not an object");
        return (Map<String, Object>) o;
    }

    private static double field(Map<String, Object> m, String k) {
        if (m == null) throw new IllegalArgumentException("cannot read a member of null");
        return num(m.get(k));
    }

    /** [d, 1 - rev, bl, taint, 1 - conf, age], each through {@code unit} with the worst case of the risk score. */
    public static double[] transformedInputs(Map<String, Object> i) {
        return new double[] {
            unit(field(i, "semanticDistance"), 1),
            1 - unit(field(i, "reversibility"), 0),
            unit(field(i, "blastRadius"), 1),
            unit(field(i, "taint"), 1),
            1 - unit(field(i, "confidence"), 0),
            unit(field(i, "age"), 1),
        };
    }

    /** The weight vector of the risk score in canonical order with its clamp applied. */
    public static double[] weightVector(Map<String, Object> w) {
        return new double[] {wt(field(w, "alpha")), wt(field(w, "beta")), wt(field(w, "gamma")), wt(field(w, "delta")), wt(field(w, "epsilon")), wt(field(w, "zeta"))};
    }

    /** JavaScript Math.round (ties toward +infinity), exact. */
    static double jsRound(double x) {
        if (!finite(x)) return x;
        double f = Math.floor(x);
        return x - f >= 0.5 ? f + 1 : f;
    }

    private static void requireScale(double scale) {
        if (!finite(scale) || scale != Math.rint(scale) || scale <= 0) throw new IllegalArgumentException("scale must be a positive integer");
    }

    /** round(x_i * scale) for each transformed input: the integer vector the agent encrypts. {@code scale} is a JSON number. */
    public static double[] quantizeRiskInputs(Map<String, Object> i, Object scale) {
        double s = num(scale);
        requireScale(s);
        double[] t = transformedInputs(i);
        double[] out = new double[t.length];
        for (int k = 0; k < t.length; k++) out[k] = jsRound(t[k] * s);
        return out;
    }

    public static double[] quantizeRiskInputs(Map<String, Object> i) { return quantizeRiskInputs(i, Long.valueOf(DEFAULT_SCALE)); }

    /** A JSON number value for a JavaScript number: a safe integer as a Long, else a plain decimal. */
    static Object numVal(double d) {
        if (d == Math.rint(d) && Math.abs(d) <= 9007199254740991.0) return Long.valueOf((long) d);
        return new Json.Num(new BigDecimal(Double.toString(d)).stripTrailingZeros().toPlainString());
    }

    private static Object[] numVals(double[] a) {
        Object[] o = new Object[a.length];
        for (int i = 0; i < a.length; i++) o[i] = numVal(a[i]);
        return o;
    }

    /**
     * The public gate policy from a risk policy {weights, kappa} and the trust budget B, at fixed-point scale S: weights
     * round(w_i S), kappa-weighted weights round(kappa w_i S), budget round(B S^2). Refuses a policy whose scaled values could
     * overflow the signed plain-modulus range (a wrap would silently corrupt the verdict).
     */
    public static Map<String, Object> fheRiskPolicy(Map<String, Object> core, Object budget, Object scaleArg) {
        double scale = num(scaleArg);
        requireScale(scale);
        double b = num(budget);
        if (!(finite(b) && b >= 0)) throw new IllegalArgumentException("budget must be finite and >= 0");
        double kappa = field(core, "kappa");
        if (!(finite(kappa) && kappa > 0)) throw new IllegalArgumentException("policy.kappa must be finite and > 0");
        double[] w = weightVector(obj(core.get("weights")));
        double[] ws = new double[w.length], kws = new double[w.length];
        double sumW = 0, sumK = 0;
        for (int i = 0; i < w.length; i++) {
            ws[i] = jsRound(w[i] * scale);
            kws[i] = jsRound(kappa * w[i] * scale);
            sumW += ws[i];
            sumK += kws[i];
        }
        double budgetScaled = jsRound(b * scale * scale);
        double maxAbs = Math.max(Math.max(sumW * scale, sumK * scale), budgetScaled);
        if (maxAbs >= SIGNED_BOUND) {
            throw new IllegalArgumentException("policy/scale overflow the plain modulus: max |value| " + maxAbs + " must be < SIGNED_BOUND " + SIGNED_BOUND + ". Lower the scale or the weights/budget.");
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("scale", numVal(scale));
        m.put("dim", Integer.valueOf(RISK_DIM));
        m.put("weightsScaled", java.util.Arrays.asList(numVals(ws)));
        m.put("kappaWeightsScaled", java.util.Arrays.asList(numVals(kws)));
        m.put("budgetScaled", numVal(budgetScaled));
        m.put("kappa", numVal(kappa));
        return m;
    }

    public static Map<String, Object> fheRiskPolicy(Map<String, Object> core, Object budget) { return fheRiskPolicy(core, budget, Long.valueOf(DEFAULT_SCALE)); }

    /** The six normalized risk inputs of a signed action's risk claim; a missing or non-numeric field is NaN (fail-closed). */
    public static Map<String, Object> riskInputsFromPCActn(Map<String, Object> p) {
        Map<String, Object> src = obj(obj(p.get("risk_claim")).get("inputs"));
        Map<String, Object> out = new LinkedHashMap<>();
        for (String k : INPUT_FIELDS) {
            Object v = src.get(k);
            out.put(k, v instanceof Json.Num || v instanceof Number ? v : Double.valueOf(Double.NaN));
        }
        return out;
    }

    /** The replay binding of a signed action: audience, action digest, counter and the optional nonce. */
    public static Map<String, Object> bindingFromPCActn(Map<String, Object> p) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("aud", p.get("aud"));
        m.put("actionRef", obj(p.get("action")).get("params_digest"));
        m.put("counter", p.get("counter"));
        if (p.containsKey("nonce")) m.put("nonce", p.get("nonce"));
        return m;
    }

    /** The plaintext reference verdict: r = risk score, admit iff kappa-cost(r) <= budget. Returns {r, admit}. */
    public static Map<String, Object> plaintextVerdict(Map<String, Object> inputs, Map<String, Object> core, Object budget) {
        Map<String, Object> w = obj(core.get("weights"));
        double r = clamp01(wt(field(w, "alpha")) * unit(field(inputs, "semanticDistance"), 1)
            + wt(field(w, "beta")) * (1 - unit(field(inputs, "reversibility"), 0))
            + wt(field(w, "gamma")) * unit(field(inputs, "blastRadius"), 1)
            + wt(field(w, "delta")) * unit(field(inputs, "taint"), 1)
            + wt(field(w, "epsilon")) * (1 - unit(field(inputs, "confidence"), 0))
            + wt(field(w, "zeta")) * unit(field(inputs, "age"), 1));
        double kappa = field(core, "kappa");
        double cost = (finite(kappa) && kappa > 0 ? kappa : 0) * clamp01(finite(r) ? r : 1);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("r", numVal(r));
        out.put("admit", Double.isFinite(num(budget)) && cost <= num(budget));
        return out;
    }
}
