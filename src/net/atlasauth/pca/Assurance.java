package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.WeakHashMap;

/**
 * Assurance labels (T8, B7).
 *
 * <p>A check's status ({@code pass} / {@code fail} / {@code not-enforced} / {@code unsupported}) says WHETHER it held; the
 * assurance report says WHAT a pass rests on: software or hardware attestation, a SNARK proof or an attested-VM statement, a
 * post-quantum or an Ed25519 signature, independent multisig shares or a FROST (preview) aggregate. It also names features the
 * verifier does not implement ({@code unsupported}), which are reported and never count as a pass.
 *
 * <p>Labels come from the VERIFIER'S configuration, never from the presented evidence: a software attestation verifier is
 * {@code software} whatever the document claims. A hook or backend without a label is {@code unknown}, which satisfies no
 * requirement. A hook declares its label by implementing {@link Labelled}, or has one attached with {@link #setLabel}
 * (for a lambda that cannot implement an interface).
 *
 * <p>{@link Requirement} turns the report into a gate: when the evidence is weaker, missing, failed, unlabelled, preview,
 * degraded or unsupported, the {@code assurance} check fails and the request is denied (see {@link Authorize.Input#requireAssurance}).
 * A report is a JSON-shaped map {@code check -> {outcome, level?, vendor?, preview?, ceremony?, suites?, t?, reason?, degraded?}}.
 */
public final class Assurance {
    private Assurance() {}

    /** What a hook, hardware verifier or SNARK backend declares about itself. */
    public static final class Label {
        /** Attestation: {@code software} | {@code hardware} | {@code multi_root}; zk: {@code groth16} | {@code policyvm_snark} | {@code stark} | {@code zkvm} | {@code attested_vm} | {@code attested_vm_hw}; threshold: {@code multisig} | {@code frost} | {@code frost_dkg} | {@code mpc}. */
        public final String level;
        /** Vendor or root id, for example {@code amd-sev-snp} (may be null). */
        public final String vendor;
        /** Preview (not production) crypto: FROST, DKG, MPC. */
        public final boolean preview;
        /** SNARK backends: {@code single-party} or {@code multi-party} (null: not declared). */
        public final String ceremony;

        public Label(String level, String vendor, boolean preview, String ceremony) {
            if (level == null) throw new IllegalArgumentException("level");
            this.level = level;
            this.vendor = vendor;
            this.preview = preview;
            this.ceremony = ceremony;
        }

        public static Label of(String level) { return new Label(level, null, false, null); }
        public Label vendor(String vendor) { return new Label(level, vendor, preview, ceremony); }
        public Label preview(boolean preview) { return new Label(level, vendor, preview, ceremony); }
        public Label ceremony(String ceremony) { return new Label(level, vendor, preview, ceremony); }
    }

    /** Implemented by a verifier hook, hardware verifier or SNARK-like backend that declares its own assurance. */
    public interface Labelled {
        Label assuranceLabel();
    }

    private static final Map<Object, Label> LABELS = Collections.synchronizedMap(new WeakHashMap<>());

    /**
     * Attach {@code label} to {@code target} (held weakly; keyed by the object's equality, so use a distinct object per
     * verifier). Returns {@code target}.
     */
    public static <T> T setLabel(T target, Label label) {
        if (target == null || label == null) throw new IllegalArgumentException("target and label are required");
        LABELS.put(target, label);
        return target;
    }

    /** The label of {@code target}: its own ({@link Labelled}) or the attached one, else null. */
    public static Label labelOf(Object target) {
        if (target == null) return null;
        if (target instanceof Labelled) return ((Labelled) target).assuranceLabel();
        return LABELS.get(target);
    }

    // ---- ranks ------------------------------------------------------------------------------------------------------

    private static int attRank(String level) {
        if (level == null) return 0;
        switch (level) {
            case "software": return 1;
            case "hardware": return 2;
            case "multi_root": return 3;
            default: return 0;
        }
    }

    private static int zkRank(String level) {
        if (level == null) return 0;
        switch (level) {
            case "attested_vm": case "attested_vm_hw": return 1;
            case "stark": case "zkvm": return 2;
            case "groth16": case "policyvm_snark": return 3;
            default: return 0;
        }
    }

    /** True for the preview threshold schemes (FROST, DKG, MPC). */
    public static boolean isPreviewScheme(String s) { return "frost".equals(s) || "frost_dkg".equals(s) || "mpc".equals(s); }

    /** A multi-root N-of-M attestation policy's root: a labelled verifier, and whether it is required. */
    public static final class Root {
        public final Object verifier;
        public final boolean required;

        public Root(Object verifier, boolean required) { this.verifier = verifier; this.required = required; }
    }

    /**
     * The attestation level a multi-root N-of-M policy guarantees: the fewest hardware roots any accepted subset can contain
     * (all required roots, filled up to {@code threshold} with the weakest optional ones). Two or more is {@code multi_root},
     * one is {@code hardware}, none is the weakest level among the roots that could make up the quorum.
     */
    public static String multiRootLevel(List<Root> roots, double threshold) {
        List<Root> chosen = new ArrayList<>();
        List<Root> opt = new ArrayList<>();
        for (Root r : roots) if (r.required) chosen.add(r); else opt.add(r);
        opt.sort((a, b) -> Integer.compare(rank(a), rank(b))); // stable, like the reference's sort
        int fill = (int) Math.max(0, Math.min(opt.size(), threshold - chosen.size()));
        chosen.addAll(opt.subList(0, fill));
        int hw = 0, min = Integer.MAX_VALUE;
        for (Root r : chosen) {
            int k = rank(r);
            if (k >= 2) hw++;
            min = Math.min(min, k);
        }
        if (hw >= 2) return "multi_root";
        if (hw == 1) return "hardware";
        return min >= 1 ? "software" : "unknown";
    }

    private static int rank(Root r) {
        Label l = labelOf(r.verifier);
        return attRank(l == null ? "unknown" : l.level);
    }

    /** Classify one signature suite (null = Ed25519): {@code ed25519}, {@code hybrid}, {@code pq}, or {@code unknown} for an unregistered one. */
    public static String signatureLevel(Object alg) {
        Object a = alg == null ? "ed25519" : alg;
        if ("ed25519".equals(a)) return "ed25519";
        if (!(a instanceof String) || !Pq.REGISTERED_SUITES.contains(a)) return "unknown";
        return ((String) a).startsWith("hybrid-") ? "hybrid" : "pq";
    }

    /** The weakest level in a chain: any unknown suite, then any Ed25519-only signer, then any hybrid, else pure PQ. */
    private static String weakest(List<String> levels) {
        for (String l : new String[] {"unknown", "ed25519", "hybrid"}) if (levels.contains(l)) return l;
        return levels.isEmpty() ? "unknown" : "pq";
    }

    // ---- the report -------------------------------------------------------------------------------------------------

    /** What {@link #report} is built from. */
    public static final class Sources {
        /** check name -> {@code pass} | {@code fail} | {@code not-enforced} | {@code unsupported}. */
        public Map<String, String> checks = new LinkedHashMap<>();
        /** The presented PCActn (its {@code alg}, {@code cap_chain} suites and {@code bond_ref} are read), or null. */
        public Map<String, Object> pcactn;
        /** The verifier's hooks (null: none): a labelled object makes a passing check report its level. */
        public Object attestationHook, zkHook, thresholdHook, revocationHook;
        /** The attestation hook actually used; it wins over {@link #attestationHook}. */
        public Object usedAttestationHook;
        /** The {@code t} the threshold hook enforced (a number), or null. */
        public Object thresholdT;
        public boolean allowUnboundPq;
        /** Passing checks that rest on a compatibility mode: check name -> why. */
        public Map<String, String> degraded;
    }

    private static final String CHAIN = "cap_chain";

    /** A suite name as JavaScript prints it. */
    private static String suiteText(Object alg) { return IntentRevocation.jsText(alg, true); }

    /** Build the per-check assurance report (pure; never throws on odd input). */
    public static Map<String, Object> report(Sources src) {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> p = src.pcactn;
        for (Map.Entry<String, String> en : src.checks.entrySet()) {
            String name = en.getKey(), status = en.getValue();
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("outcome", status);
            if ("unsupported".equals(status)) e.put("reason", name + " is not implemented by this verifier");
            if ("pass".equals(status)) {
                Object hook = null;
                if (name.equals("attestation")) hook = src.usedAttestationHook != null ? src.usedAttestationHook : src.attestationHook;
                else if (name.equals("zk_compliance")) hook = src.zkHook;
                else if (name.equals("threshold")) hook = src.thresholdHook;
                else if (name.equals("revocation")) hook = src.revocationHook;
                Label label = hook != null ? labelOf(hook) : null;
                if (name.equals("attestation") || name.equals("zk_compliance") || (name.equals("threshold") && hook != null)) {
                    String level = label != null ? label.level : "unknown";
                    e.put("level", level);
                    if (label != null && label.vendor != null) e.put("vendor", label.vendor);
                    if (name.equals("zk_compliance") && label != null && label.ceremony != null) e.put("ceremony", label.ceremony);
                    if ((label != null && label.preview) || (name.equals("threshold") && isPreviewScheme(level))) e.put("preview", Boolean.TRUE);
                    if (name.equals("threshold") && IntentJs.num(src.thresholdT) != null) e.put("t", IntentJs.normalize(src.thresholdT instanceof Json.Num ? src.thresholdT : numberOf(src.thresholdT)));
                } else if (label != null) {
                    e.put("level", label.level);
                    if (label.vendor != null) e.put("vendor", label.vendor);
                    if (label.preview) e.put("preview", Boolean.TRUE);
                }
                if (name.equals("leaf_signature") && p != null) {
                    Object alg = p.get("alg") == null ? "ed25519" : p.get("alg");
                    e.put("suites", new ArrayList<Object>(List.of(suiteText(alg))));
                    e.put("level", src.allowUnboundPq && !"ed25519".equals(alg) ? "unbound_pq" : signatureLevel(alg));
                }
                if ((name.equals(CHAIN) || name.equals("chain")) && p != null && p.get("cap_chain") instanceof List) {
                    List<Object> algs = new ArrayList<>();
                    for (Object c : (List<?>) p.get("cap_chain")) {
                        Object a = c instanceof Map ? ((Map<?, ?>) c).get("alg") : null;
                        algs.add(a == null ? "ed25519" : a);
                    }
                    List<Object> suites = new ArrayList<>();
                    List<String> levels = new ArrayList<>();
                    boolean anyNonEd = false;
                    for (Object a : algs) {
                        suites.add(suiteText(a));
                        levels.add(signatureLevel(a));
                        if (!"ed25519".equals(a)) anyNonEd = true;
                    }
                    e.put("suites", suites);
                    e.put("level", src.allowUnboundPq && anyNonEd ? "unbound_pq" : weakest(levels));
                }
            }
            out.put(name, e);
        }
        if (src.degraded != null) {
            for (Map.Entry<String, String> d : src.degraded.entrySet()) {
                Object cur = out.get(d.getKey());
                if (cur instanceof Map && "pass".equals(((Map<?, ?>) cur).get("outcome"))) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> e = new LinkedHashMap<>((Map<String, Object>) cur);
                    e.put("degraded", Boolean.TRUE);
                    e.put("reason", d.getValue());
                    out.put(d.getKey(), e);
                }
            }
        }
        // Features the verifier does not implement: reported, never a pass.
        if (p != null && p.containsKey("bond_ref")) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("outcome", "unsupported");
            e.put("reason", "bond verification is not implemented by this verifier");
            out.put("bond", e);
        }
        return out;
    }

    private static Json.Num numberOf(Object o) {
        Double d = IntentJs.num(o);
        return new Json.Num(RevocationStaleness.jsNum(d));
    }

    // ---- the requirement --------------------------------------------------------------------------------------------

    /**
     * A high-assurance policy. Every listed dimension must be met by a PASSING check; otherwise the {@code assurance} check
     * fails. An unknown dimension or value is refused (fail closed).
     */
    public static final class Requirement {
        String attestation, zk, signature;
        List<String> threshold;
        boolean allowPreview;
        /** Set when a requirement read from JSON could not be understood: it then refuses everything. */
        String invalid;

        public Requirement() {}

        /** Minimum attestation level: {@code software} &lt; {@code hardware} &lt; {@code multi_root} (two independent hardware roots). */
        public Requirement attestation(String level) { this.attestation = level; return this; }
        /** Compliance proof: {@code attested_vm}, {@code attested_vm_hardware}, {@code proof} (Groth16, Policy-VM SNARK, STARK, zkVM) or {@code snark}. */
        public Requirement zk(String level) { this.zk = level; return this; }
        /** {@code pq}: the leaf signature and every capability in the chain use a hybrid or pure post-quantum suite. */
        public Requirement signature(String level) { this.signature = level; return this; }
        /** Accepted threshold schemes for the {@code threshold} check. */
        public Requirement threshold(List<String> schemes) { this.threshold = schemes == null ? null : new ArrayList<>(schemes); return this; }
        /** Accept passing preview evidence (FROST, DKG, MPC) outside an explicit threshold list. Default false. */
        public Requirement allowPreview(boolean allow) { this.allowPreview = allow; return this; }

        /** {@code {signature: "pq"}}. */
        public static Requirement pq() { return new Requirement().signature("pq"); }

        /** From a JSON object {@code {attestation?, zk?, signature?, threshold?, allowPreview?}}. */
        public static Requirement fromJson(Object o) {
            Requirement r = new Requirement();
            if (!(o instanceof Map)) {
                r.invalid = "assurance: unknown assurance requirement(s): invalid (fail closed)";
                return r;
            }
            Map<?, ?> m = (Map<?, ?>) o;
            TreeSet<String> unknown = new TreeSet<>();
            for (Object k : m.keySet()) {
                String key = String.valueOf(k);
                if (!(key.equals("attestation") || key.equals("zk") || key.equals("signature") || key.equals("threshold") || key.equals("allowPreview") || key.equals("allow_preview")))
                    unknown.add(key);
            }
            if (!unknown.isEmpty()) {
                r.invalid = "assurance: unknown assurance requirement(s): " + String.join(", ", unknown) + " (fail closed)";
                return r;
            }
            r.attestation = dimension(m.get("attestation"));
            r.zk = dimension(m.get("zk"));
            r.signature = dimension(m.get("signature"));
            Object thr = m.get("threshold");
            if (thr instanceof List) {
                List<String> l = new ArrayList<>();
                boolean ok = true;
                for (Object x : (List<?>) thr) if (x instanceof String) l.add((String) x); else ok = false;
                if (ok) r.threshold = l;
                else r.invalid = "assurance: unknown threshold requirement " + IntentRevocation.jsText(thr, true) + " (fail closed)";
            } else if (thr != null) {
                r.invalid = "assurance: unknown threshold requirement " + IntentRevocation.jsText(thr, true) + " (fail closed)";
            }
            r.allowPreview = Boolean.TRUE.equals(m.get("allowPreview")) || Boolean.TRUE.equals(m.get("allow_preview"));
            return r;
        }
    }

    /** A requirement value as text: a non-string one can never equal a known level, so it is refused as unknown. */
    private static String dimension(Object v) { return v == null ? null : v instanceof String ? (String) v : IntentRevocation.jsText(v, true); }

    private static Map<String, Object> entry(Map<String, Object> report, String name) {
        Object e = report.get(name);
        @SuppressWarnings("unchecked")
        Map<String, Object> m = e instanceof Map ? (Map<String, Object>) e : null;
        return m;
    }

    private static String lvl(Map<String, Object> e) { return e.get("level") instanceof String ? (String) e.get("level") : "unknown"; }

    /** The outcome of an entry as text. */
    private static String outcome(Map<String, Object> e) { return IntentRevocation.jsText(e.get("outcome"), e.containsKey("outcome")); }

    /**
     * Check a report against a requirement. Returns the reason of the first unmet dimension (prefixed {@code assurance: }), or
     * null when every listed dimension is met. Missing, failed, not-enforced, unlabelled, weaker, preview, degraded and
     * unsupported evidence never meet a requirement. Never throws.
     */
    public static String unmet(Map<String, Object> report, Requirement req) {
        try {
            return unmetOrThrow(report, req);
        } catch (RuntimeException e) {
            return "assurance: the requirement could not be evaluated (fail closed)";
        }
    }

    private static String unmetOrThrow(Map<String, Object> report, Requirement req) {
        for (Map.Entry<String, Object> en : report.entrySet()) {
            Map<String, Object> e = entry(report, en.getKey());
            if (e != null && "unsupported".equals(e.get("outcome")))
                return "assurance: unsupported: " + en.getKey() + " (" + (e.get("reason") != null ? e.get("reason") : "not implemented") + "); a high-assurance policy never accepts it";
        }
        for (Map.Entry<String, Object> en : report.entrySet()) {
            Map<String, Object> e = entry(report, en.getKey());
            if (e != null && "pass".equals(e.get("outcome")) && Boolean.TRUE.equals(e.get("degraded")))
                return "assurance: " + en.getKey() + " rests on a degraded compatibility mode (" + (e.get("reason") != null ? e.get("reason") : "degraded") + "); a high-assurance policy never accepts it";
        }
        if (req == null) return "assurance: unknown assurance requirement(s): invalid (fail closed)";
        if (req.invalid != null) return req.invalid;
        if (req.attestation != null && attRank(req.attestation) == 0)
            return "assurance: unknown attestation requirement '" + req.attestation + "' (fail closed)";
        if (req.zk != null && !(req.zk.equals("attested_vm") || req.zk.equals("attested_vm_hardware") || req.zk.equals("proof") || req.zk.equals("snark")))
            return "assurance: unknown zk requirement '" + req.zk + "' (fail closed)";
        if (req.signature != null && !req.signature.equals("pq")) return "assurance: unknown signature requirement '" + req.signature + "' (fail closed)";

        if (req.attestation != null) {
            Object e = need(report, "attestation", req.attestation + " attestation");
            if (e instanceof String) return (String) e;
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) e;
            if (attRank(lvl(m)) < attRank(req.attestation)) return "assurance: " + req.attestation + " attestation required but the evidence is " + lvl(m);
        }
        if (req.zk != null) {
            Object e = need(report, "zk_compliance", "zk compliance (" + req.zk + ")");
            if (e instanceof String) return (String) e;
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) e;
            String level = lvl(m);
            // hardware-bound: the attested-VM statement with a hardware-bound prover key, or any real proof system
            if (req.zk.equals("attested_vm_hardware") && (level.equals("attested_vm") || level.equals("unknown")))
                return "assurance: zk compliance (" + req.zk + ") required but the prover key is not bound to hardware evidence";
            int want = req.zk.equals("snark") ? 3 : req.zk.equals("proof") ? 2 : 1;
            if (zkRank(level) < want) return "assurance: zk compliance (" + req.zk + ") required but the evidence is " + level;
        }
        if (req.signature != null) {
            String chain = report.containsKey(CHAIN) ? CHAIN : report.containsKey("chain") ? "chain" : CHAIN;
            for (String name : new String[] {"leaf_signature", chain}) {
                Object e = need(report, name, "post-quantum signatures");
                if (e instanceof String) return (String) e;
                @SuppressWarnings("unchecked")
                Map<String, Object> m = (Map<String, Object>) e;
                String level = lvl(m);
                if (!level.equals("pq") && !level.equals("hybrid")) return "assurance: post-quantum signatures required but " + name + " is " + level;
            }
        }
        if (req.threshold != null) {
            String names = String.join(" | ", req.threshold);
            Object e = need(report, "threshold", "threshold (" + names + ")");
            if (e instanceof String) return (String) e;
            @SuppressWarnings("unchecked")
            Map<String, Object> m = (Map<String, Object>) e;
            if (!(m.get("level") instanceof String)) return "assurance: threshold (" + names + ") required but no threshold verifier enforced it";
            if (!req.threshold.contains(m.get("level"))) return "assurance: threshold (" + names + ") required but the scheme is " + m.get("level");
        }
        if (!req.allowPreview) {
            for (Map.Entry<String, Object> en : report.entrySet()) {
                Map<String, Object> e = entry(report, en.getKey());
                if (e == null || !"pass".equals(e.get("outcome")) || !Boolean.TRUE.equals(e.get("preview"))) continue;
                if (en.getKey().equals("threshold") && req.threshold != null && e.get("level") instanceof String && req.threshold.contains(e.get("level"))) continue;
                return "assurance: " + en.getKey() + " rests on preview crypto (" + lvl(e) + "); set allowPreview or list the scheme to accept it";
            }
        }
        return null;
    }

    /** The passing entry of {@code name}, or the reason string when it is absent or did not pass. */
    private static Object need(Map<String, Object> report, String name, String what) {
        Map<String, Object> e = entry(report, name);
        if (e == null) return "assurance: " + what + " required but there is no " + name + " evidence";
        if (!"pass".equals(e.get("outcome"))) return "assurance: " + what + " required but the " + name + " check is " + outcome(e);
        return e;
    }
}
