package net.atlasauth.pca;

import java.security.MessageDigest;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * The objective risk functional (the reference's objective-risk module): every input of the heuristic risk is a pure function of COMMITTED facts
 * (a registry of verified inverses, a resource graph, an embedder and a goal vector, a calibration set) and of the CANONICAL action; nothing the
 * agent merely asserts is read. A commitment mismatch fails closed (r = 1, valid false). Digests are the LENIENT canonical hashes (any finite double,
 * printed as JavaScript prints it).
 *
 * <p>Actions, committed documents and results are JSON trees (maps and lists). Embedder vectors are integer vectors of safe integers.
 */
public final class ObjectiveRisk {
    private ObjectiveRisk() {}

    public static final String METRIC = "half-chord-v1";
    public static final double DEFAULT_EPSILON = 1.0 / 4096;
    public static final String NATIVE_SCHEME = "pca-native-hash-ngram-v1";
    public static final int DEFAULT_MAX_PARAM_LEAVES = 256;
    private static final double MAX_SAFE = 9007199254740991d;

    /** The committed default of the native embedder. */
    public static Map<String, Object> defaultNativeConfig() {
        return Issue.obj("dims", 256L, "ngramMin", 2L, "ngramMax", 4L, "seed", "pca-native-v1", "fieldWeights", Issue.obj("verb", 4L, "resource", 2L, "param", 1L));
    }

    /** A vector or commitment fault (the reference's EmbeddingError and its range errors). */
    public static class EmbeddingError extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public EmbeddingError(String m) { super(m); }
    }

    // ---- helpers ------------------------------------------------------------------------------------------------------------

    private static Map<String, Object> obj(Object... kv) { return Issue.obj(kv); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) { return o instanceof Map ? (Map<String, Object>) o : null; }

    private static Object get(Object m, String k) { return m instanceof Map ? ((Map<?, ?>) m).get(k) : null; }

    private static boolean has(Object m, String k) { return m instanceof Map && ((Map<?, ?>) m).containsKey(k); }

    private static double clamp01(double x) { return Double.isNaN(x) || Double.isInfinite(x) ? 1 : x < 0 ? 0 : x > 1 ? 1 : x; }

    private static double jsn(Object o, boolean present) { return Actions.jsNumber(o, present); }

    /** A tree prepared for the lenient canonical form: a double becomes its number text (a non-finite one is refused, as the reference refuses it). */
    @SuppressWarnings("unchecked")
    private static Object jn(Object v) {
        if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) throw new IllegalArgumentException("canonicalize: non-finite number");
            return StoreJs.num(d);
        }
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(jn(x));
            return out;
        }
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) out.put(e.getKey(), jn(e.getValue()));
            return out;
        }
        return v;
    }

    private static String canon(Object v) { return Json.canonicalize(jn(v)); }

    private static String hash(Object v) { return StoreJs.hashLenient(jn(v)); }

    private static int cmp(String a, String b) { return a.compareTo(b); }

    private static List<Object> longs(long[] v) {
        List<Object> out = new ArrayList<>();
        for (long x : v) out.add(x);
        return out;
    }

    // ---- canonical action ---------------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static Object normValue(Object v) {
        if (v instanceof String) return Normalizer.normalize((String) v, Normalizer.Form.NFC);
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<Object>) v) out.add(normValue(x));
            return out;
        }
        if (v instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                String nk = Normalizer.normalize(e.getKey(), Normalizer.Form.NFC);
                if (out.containsKey(nk)) throw new IllegalArgumentException("canonicalAction: duplicate key after NFC normalization");
                out.put(nk, normValue(e.getValue()));
            }
            return out;
        }
        return v;
    }

    /**
     * The canonical form {@code {verb, resource, params}}: verb trimmed, NFC and lower-cased, resource trimmed and NFC, every string and key of the
     * params NFC, params validated by the lenient canonical form. Throws on anything without a stable encoding.
     */
    public static Map<String, Object> canonicalAction(Object a) {
        Object verbO = get(a, "verb"), resO = get(a, "resource");
        if (!(verbO instanceof String) || !(resO instanceof String)) throw new IllegalArgumentException("canonicalAction: verb/resource must be strings");
        String verb = AttestCommon.jsTrim(Normalizer.normalize((String) verbO, Normalizer.Form.NFC)).toLowerCase(Locale.ROOT);
        String resource = AttestCommon.jsTrim(Normalizer.normalize((String) resO, Normalizer.Form.NFC));
        if (verb.isEmpty() || resource.isEmpty()) throw new IllegalArgumentException("canonicalAction: empty verb/resource");
        Object p = get(a, "params");
        Object params = normValue(p == null ? new LinkedHashMap<String, Object>() : p);
        if (!(params instanceof Map)) throw new IllegalArgumentException("canonicalAction: params must be an object");
        Map<String, Object> c = obj("verb", verb, "resource", resource, "params", params);
        canon(c);
        return c;
    }

    public static String canonicalActionJson(Object c) { return canon(c); }

    public static String canonicalActionDigest(Object c) { return hash(c); }

    // ---- reversibility: a committed registry of verified inverses -------------------------------------------------------------

    /** What the committed registry holds: the inverse of a verb (null when none), the trusted verifier ids and the digest of ALL contents. */
    public interface InverseRegistry {
        Map<String, Object> lookup(Object verb);
        List<String> trustedVerifiers();
        String digest();
    }

    public static final class InMemoryInverseRegistry implements InverseRegistry {
        private final Map<String, Map<String, Object>> m = new HashMap<>();
        private final List<String> trusted;

        public InMemoryInverseRegistry(List<String> trustedVerifiers) {
            List<String> t = new ArrayList<>(new LinkedHashSet<>(trustedVerifiers));
            t.sort(ObjectiveRisk::cmp);
            trusted = t;
        }

        /** A later entry for the same verb replaces the earlier one. */
        public InMemoryInverseRegistry register(String verb, Map<String, Object> e) {
            Map<String, Object> copy = new LinkedHashMap<>(e);
            if (Zk.truthy(e.get("verification")) && e.get("verification") instanceof Map) copy.put("verification", new LinkedHashMap<>(IntentJs.obj(e.get("verification"))));
            m.put(verb, copy);
            return this;
        }

        @Override public Map<String, Object> lookup(Object verb) {
            Map<String, Object> e = verb instanceof String ? m.get(verb) : null;
            return e == null ? null : new LinkedHashMap<>(e);
        }

        @Override public List<String> trustedVerifiers() { return trusted; }

        @Override public String digest() {
            List<String> verbs = new ArrayList<>(m.keySet());
            verbs.sort(ObjectiveRisk::cmp);
            List<Object> entries = new ArrayList<>();
            for (String verb : verbs) {
                Map<String, Object> e = m.get(verb);
                entries.add(obj("verb", verb, "inverseKind", e.get("inverseKind"), "fidelity", e.get("fidelity"), "verification", e.get("verification")));
            }
            return hash(obj("v", 1L, "trusted", new ArrayList<Object>(trusted), "entries", entries));
        }
    }

    /** Reversible iff the registry holds an inverse verified by a TRUSTED verifier AND the inverse verb is authorized; else irreversible. */
    public static Map<String, Object> reversibility(Object action, InverseRegistry registry, Set<String> authorizedKinds) {
        Map<String, Object> e = registry.lookup(get(action, "verb"));
        boolean trusted = e != null && Zk.truthy(e.get("verification")) && registry.trustedVerifiers().contains(get(e.get("verification"), "verifierId"));
        if (e == null || !trusted || !authorizedKinds.contains(e.get("inverseKind"))) return obj("class", "irreversible", "value", 0L);
        return "exact".equals(e.get("fidelity"))
            ? obj("class", "reversible", "value", 1L, "inverseKind", e.get("inverseKind"))
            : obj("class", "compensable", "value", 0.5, "inverseKind", e.get("inverseKind"));
    }

    // ---- blast radius: reachability over a committed resource graph -------------------------------------------------------------

    /** Adjacency model with a content digest the grant commits. */
    public static final class ResourceGraph {
        private final Map<String, Map<String, Object>> nodes = new LinkedHashMap<>();
        private final Map<String, List<Map<String, Object>>> out = new HashMap<>();

        /** {@code {id, harm?}}; the same id again replaces the node and keeps its edges. */
        public ResourceGraph addNode(Map<String, Object> n) {
            if (!(n.get("id") instanceof String)) throw new IllegalArgumentException("node id must be a string");
            String id = (String) n.get("id");
            nodes.put(id, n);
            out.putIfAbsent(id, new ArrayList<>());
            return this;
        }

        /** {@code {from, to, kind}}; both endpoints must be nodes. */
        public ResourceGraph addEdge(Map<String, Object> e) {
            if (!nodes.containsKey(e.get("from")) || !nodes.containsKey(e.get("to"))) throw new IllegalStateException("edge endpoints must exist");
            out.get(e.get("from")).add(e);
            return this;
        }

        public int size() { return nodes.size(); }

        public Map<String, Object> node(Object id) { return id instanceof String ? nodes.get(id) : null; }

        /** BFS reachable set (including {@code start}), restricted by {@code scope} ({@code {edgeKinds?, maxDepth?}}), sorted. */
        public List<String> reachable(Object start, Map<String, Object> scope) {
            if (!(start instanceof String) || !nodes.containsKey(start)) return new ArrayList<>();
            Set<Object> kinds = scope != null && scope.get("edgeKinds") instanceof List ? new HashSet<Object>((List<?>) scope.get("edgeKinds")) : null;
            double maxDepth = scope == null || scope.get("maxDepth") == null ? Double.POSITIVE_INFINITY : jsn(scope.get("maxDepth"), true);
            Set<String> seen = new LinkedHashSet<>();
            seen.add((String) start);
            List<String> frontier = new ArrayList<>(List.of((String) start));
            for (int d = 0; d < maxDepth && !frontier.isEmpty(); d++) {
                List<String> next = new ArrayList<>();
                for (String u : frontier)
                    for (Map<String, Object> e : out.getOrDefault(u, List.of()))
                        if ((kinds == null || kinds.contains(e.get("kind"))) && !seen.contains((String) e.get("to"))) {
                            seen.add((String) e.get("to"));
                            next.add((String) e.get("to"));
                        }
                frontier = next;
            }
            List<String> sorted = new ArrayList<>(seen);
            sorted.sort(ObjectiveRisk::cmp);
            return sorted;
        }

        public String digest() {
            List<Map<String, Object>> n = new ArrayList<>();
            for (Map<String, Object> x : nodes.values()) n.add(obj("id", x.get("id"), "harm", x.get("harm") != null ? x.get("harm") : new LinkedHashMap<String, Object>()));
            n.sort((a, b) -> cmp((String) a.get("id"), (String) b.get("id")));
            List<Map<String, Object>> e = new ArrayList<>();
            for (List<Map<String, Object>> l : out.values()) for (Map<String, Object> x : l) e.add(obj("from", x.get("from"), "to", x.get("to"), "kind", x.get("kind")));
            e.sort((a, b) -> cmp(ek(a), ek(b)));
            return hash(obj("v", 1L, "n", new ArrayList<Object>(n), "e", new ArrayList<Object>(e)));
        }

        private static String ek(Map<String, Object> x) {
            return IntentRevocation.jsText(x.get("from"), true) + "\u0000" + IntentRevocation.jsText(x.get("to"), true) + "\u0000" + IntentRevocation.jsText(x.get("kind"), true);
        }
    }

    /** {@code {count, reachable, normalized, harm}}: an unknown resource or an empty graph is normalized 1 (fail closed). */
    public static Map<String, Object> blastRadius(Object action, ResourceGraph graph, Map<String, Object> scope) {
        List<String> reachable = graph.reachable(get(action, "resource"), scope);
        if (reachable.isEmpty() || graph.size() == 0) return obj("count", 0L, "reachable", new ArrayList<Object>(reachable), "normalized", 1L, "harm", new LinkedHashMap<String, Object>());
        Map<String, Object> harm = new LinkedHashMap<>();
        for (String id : reachable) {
            Object h = get(graph.node(id), "harm");
            if (!(h instanceof Map)) continue;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) h).entrySet()) {
                Double v = Caveats.fin(e.getValue());
                if (v != null && v > 0) harm.merge((String) e.getKey(), (Object) v, (x, y) -> (Double) x + (Double) y);
            }
        }
        return obj("count", (long) reachable.size(), "reachable", new ArrayList<Object>(reachable), "normalized", reachable.size() / (double) graph.size(), "harm", harm);
    }

    // ---- committed embeddings -----------------------------------------------------------------------------------------------------

    /**
     * Maps the CANONICAL action to an integer vector (a list of safe integers; a custom embedder may return anything, the callers validate).
     * {@code modelId} is a committed identity: the hash of the native config or of the BYO descriptor.
     */
    public interface Embedder {
        String modelId();
        /** The committed descriptor behind the model id. */
        Object config();
        double dims();
        Object embed(Map<String, Object> action);
    }

    private static double maxComponent(double dims) { return Math.floor(Math.sqrt(MAX_SAFE / (2 * Math.max(1, dims)))); }

    /** {@code dims} exact length, safe integers, each within the range keeping dot products exact; negative zero becomes 0. */
    public static long[] validateVector(Object v, double dims) {
        if (!(v instanceof List) || ((List<?>) v).size() != dims) throw new EmbeddingError("vector must have exactly " + AttestCommon.jsNumString(dims) + " components");
        double lim = maxComponent(dims);
        List<?> l = (List<?>) v;
        long[] out = new long[l.size()];
        for (int i = 0; i < out.length; i++) {
            Object x = l.get(i);
            if (!IntentJs.isSafeInteger(x)) throw new EmbeddingError("vector components must be safe integers");
            double d = IntentJs.num(x);
            if (Math.abs(d) > lim) throw new EmbeddingError("vector component out of range");
            out[i] = (long) d;
        }
        return out;
    }

    private static boolean okInt(Object x, double lo, double hi) {
        if (!IntentJs.isSafeInteger(x)) return false;
        double d = IntentJs.num(x);
        return d >= lo && d <= hi;
    }

    private static void validateNativeConfig(Map<String, Object> c) {
        if (!okInt(c.get("dims"), 8, 65536)) throw new IllegalArgumentException("native config: dims must be an integer in [8, 65536]");
        if (!okInt(c.get("ngramMin"), 1, 8) || !okInt(c.get("ngramMax"), IntentJs.num(c.get("ngramMin")), 8)) throw new IllegalArgumentException("native config: need 1 <= ngramMin <= ngramMax <= 8");
        if (!(c.get("seed") instanceof String) || ((String) c.get("seed")).isEmpty()) throw new IllegalArgumentException("native config: seed required");
        Map<String, Object> fw = asMap(c.get("fieldWeights"));
        if (fw == null) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'verb')");
        for (String k : new String[] {"verb", "resource", "param"}) if (!okInt(fw.get(k), 0, 1000)) throw new IllegalArgumentException("native config: fieldWeights." + k + " must be an integer in [0, 1000]");
        if (c.containsKey("maxParamLeaves") && !okInt(c.get("maxParamLeaves"), 1, 1_000_000)) throw new IllegalArgumentException("native config: maxParamLeaves must be an integer in [1, 1000000]");
        Object pm = c.get("paramMode");
        if (c.containsKey("paramMode") && !"leaves".equals(pm) && !"digest".equals(pm)) throw new IllegalArgumentException("native config: paramMode must be 'leaves' or 'digest'");
    }

    private static void paramLeaves(Object v, String path, List<String> out) {
        if (v instanceof List) {
            List<?> l = (List<?>) v;
            for (int i = 0; i < l.size(); i++) paramLeaves(l.get(i), path + "[" + i + "]", out);
        } else if (v instanceof Map) {
            List<String> keys = new ArrayList<>();
            for (Object k : ((Map<?, ?>) v).keySet()) keys.add((String) k);
            keys.sort(Json::compareUtf8);
            for (String k : keys) paramLeaves(((Map<?, ?>) v).get(k), path.isEmpty() ? k : path + "." + k, out);
        } else out.add(path + "=" + canon(v));
    }

    private static final Pattern NOT_WORD = Pattern.compile("[^\\p{L}\\p{N}]+");

    /** Code-point n-grams of the text with boundary markers, then its lower-cased word tokens. */
    private static List<String> textFeatures(String prefix, String text, int nmin, int nmax) {
        List<String> out = new ArrayList<>();
        int[] cps = ("\u0002" + text + "\u0003").codePoints().toArray();
        for (int n = nmin; n <= nmax; n++)
            for (int i = 0; i + n <= cps.length; i++) {
                StringBuilder sb = new StringBuilder(prefix).append('c').append(n).append(':');
                for (int j = 0; j < n; j++) sb.appendCodePoint(cps[i + j]);
                out.add(sb.toString());
            }
        for (String w : NOT_WORD.split(text)) if (!w.isEmpty()) out.add(prefix + "w:" + w.toLowerCase(Locale.ROOT));
        return out;
    }

    private static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * The native embedder: for each field (verb, resource, each param leaf) code-point n-grams and word tokens, each feature hashed as
     * SHA-256(seed 0x1F feature): bucket = big-endian u32 of the first four bytes mod dims, sign = low bit of byte 4, the bucket accumulating
     * +-fieldWeight. A param-stuffed action (more leaves than the cap) fails closed.
     */
    public static Embedder nativeHashEmbedder(Object configO) {
        Map<String, Object> config = asMap(configO);
        if (config == null) throw new IllegalArgumentException("native config: not an object");
        validateNativeConfig(config);
        Map<String, Object> cfg = new LinkedHashMap<>(config);
        cfg.put("fieldWeights", new LinkedHashMap<>(asMap(config.get("fieldWeights"))));
        Map<String, Object> committed = new LinkedHashMap<>();
        committed.put("scheme", NATIVE_SCHEME);
        committed.putAll(cfg);
        String modelId = "native:" + hash(committed);
        int dims = (int) (double) IntentJs.num(cfg.get("dims"));
        int nmin = (int) (double) IntentJs.num(cfg.get("ngramMin")), nmax = (int) (double) IntentJs.num(cfg.get("ngramMax"));
        Map<String, Object> fw = asMap(cfg.get("fieldWeights"));
        long wVerb = (long) (double) IntentJs.num(fw.get("verb")), wRes = (long) (double) IntentJs.num(fw.get("resource")), wParam = (long) (double) IntentJs.num(fw.get("param"));
        byte[] prefix = Json.utf8(cfg.get("seed") + "\u001f");
        boolean digestMode = "digest".equals(cfg.get("paramMode"));
        double cap = cfg.get("maxParamLeaves") == null ? DEFAULT_MAX_PARAM_LEAVES : IntentJs.num(cfg.get("maxParamLeaves"));
        return new Embedder() {
            @Override public String modelId() { return modelId; }
            @Override public Object config() { return committed; }
            @Override public double dims() { return dims; }

            @Override public Object embed(Map<String, Object> a) {
                if (a == null) throw new IllegalArgumentException("Cannot read properties of undefined (reading 'verb')");
                long[] v = new long[dims];
                for (String f : textFeatures("v:", IntentRevocation.jsText(a.get("verb"), a.containsKey("verb")), nmin, nmax)) add(v, f, wVerb);
                for (String f : textFeatures("r:", IntentRevocation.jsText(a.get("resource"), a.containsKey("resource")), nmin, nmax)) add(v, f, wRes);
                List<String> leaves = new ArrayList<>();
                paramLeaves(a.get("params"), "", leaves);
                if (leaves.size() > cap) throw new EmbeddingError("param leaf count " + leaves.size() + " exceeds cap " + AttestCommon.jsNumString(cap));
                if (digestMode) add(v, "p#:" + hash(obj("t", "pca-objrisk-params-v1", "params", a.get("params"))), wParam);
                else for (String leaf : leaves) for (String f : textFeatures("p:", leaf, nmin, nmax)) add(v, f, wParam);
                return longs(v);
            }

            private void add(long[] v, String feat, long w) {
                if (w == 0) return;
                byte[] f = Json.utf8(feat);
                byte[] buf = new byte[prefix.length + f.length];
                System.arraycopy(prefix, 0, buf, 0, prefix.length);
                System.arraycopy(f, 0, buf, prefix.length, f.length);
                byte[] h = sha256(buf);
                long u32 = ((h[0] & 0xffL) << 24) | ((h[1] & 0xffL) << 16) | ((h[2] & 0xffL) << 8) | (h[3] & 0xffL);
                int bucket = (int) (u32 % dims);
                v[bucket] += (h[4] & 1) == 0 ? w : -w;
            }
        };
    }

    public static Embedder nativeHashEmbedder() { return nativeHashEmbedder(defaultNativeConfig()); }

    public static String byoModelId(Object descriptor) { return "byo:" + hash(descriptor); }

    /**
     * A customer-supplied model meeting the determinism contract: {@code infer} receives the canonical action JSON and returns the integer vector.
     * A claimed model id must equal the descriptor hash.
     */
    public static Embedder byoEmbedder(Object descriptorO, Function<String, Object> infer, String claimedModelId) {
        Map<String, Object> descriptor = asMap(descriptorO);
        if (descriptor == null) throw new IllegalArgumentException("Cannot read properties of null (reading 'dims')");
        if (!IntentJs.isSafeInteger(descriptor.get("dims")) || IntentJs.num(descriptor.get("dims")) < 1) throw new IllegalArgumentException("byo: dims must be a positive integer");
        Map<String, Object> q = asMap(descriptor.get("quantization"));
        if (q == null) throw new IllegalArgumentException("Cannot destructure property 'bits' of 'descriptor.quantization' as it is undefined.");
        if (!IntentJs.isSafeInteger(q.get("bits")) || IntentJs.num(q.get("bits")) < 2 || IntentJs.num(q.get("bits")) > 31 || !(jsn(q.get("scale"), q.containsKey("scale")) > 0))
            throw new IllegalArgumentException("byo: invalid quantization");
        if (!"pca-canonical-action-json-v1".equals(descriptor.get("inputEncoding"))) throw new IllegalArgumentException("byo: unsupported inputEncoding");
        String modelId = byoModelId(descriptor);
        if (claimedModelId != null && !claimedModelId.equals(modelId)) throw new IllegalArgumentException("byo: modelId does not match the committed descriptor");
        double dims = IntentJs.num(descriptor.get("dims"));
        double qmax = Math.pow(2, IntentJs.num(q.get("bits")) - 1) - 1;
        return new Embedder() {
            @Override public String modelId() { return modelId; }
            @Override public Object config() { return descriptor; }
            @Override public double dims() { return dims; }

            @Override public Object embed(Map<String, Object> a) {
                long[] v = validateVector(infer.apply(canonicalActionJson(a)), dims);
                for (long x : v) if (Math.abs(x) > qmax) throw new EmbeddingError("byo: component exceeds declared quantization range");
                return longs(v);
            }
        };
    }

    private static boolean strictEq(Object a, Object b) {
        Double x = IntentJs.num(a), y = IntentJs.num(b);
        if (x != null || y != null) return x != null && y != null && x.doubleValue() == y.doubleValue();
        return a == null ? b == null : a.equals(b);
    }

    /** Runs conformance cases {@code {action, vector}} shipped with a model; true iff all reproduce exactly. */
    public static boolean conformanceCheck(Embedder e, List<?> cases) {
        try {
            for (Object c : cases) {
                Object v = e.embed(canonicalAction(get(c, "action")));
                Object want = get(c, "vector");
                if (!(v instanceof List) || !(want instanceof List) || ((List<?>) v).size() != ((List<?>) want).size()) return false;
                for (int i = 0; i < ((List<?>) v).size(); i++) if (!strictEq(((List<?>) v).get(i), ((List<?>) want).get(i))) return false;
            }
            return true;
        } catch (RuntimeException ex) {
            return false;
        }
    }

    // ---- goal commitment and distance ---------------------------------------------------------------------------------------------

    private static Map<String, Object> goalCommitInput(Object g) {
        return obj("embedderModelId", get(g, "embedderModelId"), "config", get(g, "config"), "goalVector", get(g, "goalVector"), "metric", get(g, "metric"), "epsilon", get(g, "epsilon"));
    }

    /** Embeds the goal's CANONICAL action and binds it to the embedder; {@code epsilon} null is the default. Throws on invalid input. */
    public static Map<String, Object> commitGoal(Embedder embedder, Object goalAction, Object epsilon) {
        Object eps = epsilon == null ? StoreJs.num(DEFAULT_EPSILON) : epsilon;
        double e = jsn(eps, true);
        if (!(e > 0 && e <= 1)) throw new IllegalArgumentException("epsilon must be in (0, 1]");
        List<Object> goalVector = longs(validateVector(embedder.embed(canonicalAction(goalAction)), embedder.dims()));
        Map<String, Object> g = obj("embedderModelId", embedder.modelId(), "config", embedder.config(), "goalVector", goalVector, "metric", METRIC, "epsilon", eps);
        Map<String, Object> out = new LinkedHashMap<>(g);
        out.put("commit", hash(goalCommitInput(g)));
        return out;
    }

    /** The first failing reason (metric, epsilon, commit hash, model id, config hash, vector), or null when the goal is valid and bound to exactly this embedder. */
    public static String verifyGoalCommitment(Object g, Embedder embedder) {
        try {
            if (g == null) throw new IllegalStateException("Cannot read properties of null (reading 'metric')");
            if (!METRIC.equals(get(g, "metric"))) return "unknown metric";
            double eps = jsn(get(g, "epsilon"), has(g, "epsilon"));
            if (!(eps > 0 && eps <= 1)) return "bad epsilon";
            if (!(get(g, "commit") instanceof String) || !get(g, "commit").equals(hash(goalCommitInput(g)))) return "goal commitment hash mismatch";
            if (!embedder.modelId().equals(get(g, "embedderModelId"))) return "embedder modelId mismatch";
            if (!hash(get(g, "config")).equals(hash(embedder.config()))) return "embedder config mismatch";
            validateVector(get(g, "goalVector"), embedder.dims());
            return null;
        } catch (RuntimeException e) {
            return e.getMessage() == null ? "invalid goal commitment" : e.getMessage();
        }
    }

    /** Integer vectors to sin(theta/2) = sqrt((1 - cos) / 2), rounded UP to the epsilon grid; IEEE operations in the reference's order. */
    public static double vectorDistance(List<?> a, List<?> b, Object epsilon) {
        double eps = epsilon == null ? DEFAULT_EPSILON : jsn(epsilon, true);
        if (a.size() != b.size()) return 1;
        double dot = 0, na = 0, nb = 0;
        boolean same = true;
        for (int i = 0; i < a.size(); i++) {
            double x = jsn(a.get(i), true), y = jsn(b.get(i), true);
            dot += x * y;
            na += x * x;
            nb += y * y;
            if (!(x == y)) same = false;
        }
        if (na == 0 || nb == 0) return 1;
        if (same) return 0;
        double cos = Math.max(-1, Math.min(1, dot / Math.sqrt(na * nb)));
        double d = Math.sqrt((1 - cos) / 2);
        if (d < 1e-9) return 0;
        return clamp01(Math.ceil(d / eps) * eps);
    }

    /** {@code {ok: true, value}} (the distance to the committed goal) or {@code {ok: false, reason}} on any commitment or embedding failure. */
    public static Map<String, Object> committedDistanceChecked(Map<String, Object> action, Object goal, Embedder embedder) {
        String bad = verifyGoalCommitment(goal, embedder);
        if (bad != null && !bad.isEmpty()) return obj("ok", false, "reason", bad);
        try {
            long[] v = validateVector(embedder.embed(action), embedder.dims());
            return obj("ok", true, "value", vectorDistance(longs(v), (List<?>) get(goal, "goalVector"), get(goal, "epsilon")));
        } catch (RuntimeException e) {
            return obj("ok", false, "reason", e.getMessage() == null ? "embedding failed" : e.getMessage());
        }
    }

    /** The distance of an agent submission (canonicalized) to the goal; 1 on any failure. */
    public static double committedDistance(Object action, Object goal, Embedder embedder) {
        try {
            Map<String, Object> r = committedDistanceChecked(canonicalAction(action), goal, embedder);
            return Boolean.TRUE.equals(r.get("ok")) ? (Double) r.get("value") : 1;
        } catch (RuntimeException e) {
            return 1;
        }
    }

    // ---- split-conformal calibration ----------------------------------------------------------------------------------------------

    /** {@code 1 - (1 + #{s >= raw}) / (n + 1)}; an empty set or a non-finite raw score gives 1. */
    public static double calibrate(Object rawScore, List<?> benignScores) {
        int n = benignScores.size();
        double raw = jsn(rawScore, true);
        if (n == 0 || Double.isNaN(raw) || Double.isInfinite(raw)) return 1;
        int ge = 0;
        for (Object s : benignScores) if (jsn(s, true) >= raw) ge++;
        return 1 - (1 + ge) / (double) (n + 1);
    }

    private static int numCmp(double a, double b) { double d = a - b; return d < 0 ? -1 : d > 0 ? 1 : 0; }

    private static List<Double> sorted(List<?> scores) {
        List<Double> s = new ArrayList<>();
        for (Object x : scores) s.add(jsn(x, true));
        s.sort(ObjectiveRisk::numCmp);
        return s;
    }

    /** The split-conformal quantile: infinity when the set is too small; null where the reference reads below the array (alpha at or over 1, NaN). */
    public static Double conformalThreshold(List<?> benignScores, Object alpha) {
        int n = benignScores.size();
        double k = Math.ceil((n + 1) * (1 - jsn(alpha, true)));
        if (n == 0 || k > n) return Double.POSITIVE_INFINITY;
        if (!(k - 1 >= 0 && k - 1 < n)) return null;
        return sorted(benignScores).get((int) (k - 1));
    }

    public static String calibrationDigest(List<?> scores) {
        return hash(obj("v", 1L, "scores", new ArrayList<Object>(sorted(scores))));
    }

    // ---- harm currency ------------------------------------------------------------------------------------------------------------

    /** The weighted saturating normalization of per-denomination harm units: {@code {units, normalized}}. */
    public static Map<String, Object> harmReport(Object units, List<?> denoms) {
        if (units == null) throw new IllegalArgumentException("Cannot convert undefined or null to object");
        double num = 0, den = 0;
        for (Object d : denoms) {
            double w = jsn(get(d, "weight"), has(d, "weight")), c = jsn(get(d, "ceiling"), has(d, "ceiling"));
            if (!(w > 0) || !(c > 0)) continue;
            Object id = get(d, "id");
            double u = id instanceof String && has(units, (String) id) ? jsn(get(units, (String) id), true) : 0;
            num += w * Math.min(1, Math.max(0, u) / c);
            den += w;
        }
        return obj("units", units, "normalized", den == 0 ? 1d : clamp01(num / den));
    }

    // ---- composition --------------------------------------------------------------------------------------------------------------

    /** The committed context a verifier holds: registry, authorized inverse kinds, graph, scope, embedder, goal, commitments, denominations, weights, taint, age. */
    public static final class Context {
        public InverseRegistry registry;
        public Set<String> authorizedKinds;
        public ResourceGraph graph;
        /** {@code {edgeKinds?, maxDepth?}} or null. */
        public Map<String, Object> scope;
        public Embedder embedder;
        public Object goal;
        /** {@code {registryDigest, graphDigest, calibrationDigest?}}. */
        public Map<String, Object> commitments;
        public List<?> denominations;
        public Map<String, Object> weights;
        public Object taint;
        public Object age;
        /** Null = absent. */
        public Object attestedUncertainty;
        /** Null = no calibration. */
        public List<?> calibration;
    }

    private static Map<String, Object> reject(List<String> reasons) {
        return obj("r", 1L, "valid", false, "reasons", new ArrayList<Object>(reasons), "raw", 1L,
            "inputs", obj("semanticDistance", 1L, "reversibility", 0L, "blastRadius", 1L, "taint", 1L, "confidence", 0L, "age", 1L),
            "reversibility", obj("class", "irreversible", "value", 0L),
            "blast", obj("count", 0L, "reachable", new ArrayList<Object>(), "normalized", 1L, "harm", new LinkedHashMap<String, Object>()),
            "harm", obj("units", new LinkedHashMap<String, Object>(), "normalized", 1L), "evidenceDigest", "");
    }

    private static List<Object> sortedStrings(Iterable<?> it) {
        List<String> l = new ArrayList<>();
        for (Object o : it) l.add((String) o);
        l.sort(ObjectiveRisk::cmp);
        return new ArrayList<Object>(l);
    }

    /**
     * A pure function of the canonical action and the committed context: a commitment mismatch (registry, graph, calibration, goal or embedder
     * binding) or an unencodable action is r = 1 with {@code valid: false}. A graph with a non-finite harm weight or a calibration set with a
     * non-finite score cannot be digested: that throws, as the reference does.
     */
    public static Map<String, Object> objectiveRisk(Object submitted, Context ctx) {
        Map<String, Object> action;
        try {
            action = canonicalAction(submitted);
        } catch (RuntimeException e) {
            return reject(List.of("action: " + (e.getMessage() == null ? "not canonicalizable" : e.getMessage())));
        }
        List<String> reasons = new ArrayList<>();
        Object cm = ctx.commitments;
        if (!ctx.registry.digest().equals(get(cm, "registryDigest"))) reasons.add("registry digest does not match the committed digest");
        if (!ctx.graph.digest().equals(get(cm, "graphDigest"))) reasons.add("graph digest does not match the committed digest");
        if (ctx.calibration != null) {
            if (!has(cm, "calibrationDigest")) reasons.add("calibration set used without a committed digest");
            else if (!calibrationDigest(ctx.calibration).equals(get(cm, "calibrationDigest"))) reasons.add("calibration digest does not match the committed digest");
        }
        Map<String, Object> dist = committedDistanceChecked(action, ctx.goal, ctx.embedder);
        if (!Boolean.TRUE.equals(dist.get("ok"))) reasons.add("goal/embedder: " + dist.get("reason"));
        if (!reasons.isEmpty()) return reject(reasons);

        Map<String, Object> rev = reversibility(action, ctx.registry, ctx.authorizedKinds);
        Map<String, Object> blast = blastRadius(action, ctx.graph, ctx.scope);
        Map<String, Object> harm = harmReport(blast.get("harm"), ctx.denominations);
        double uncertainty = clamp01(ctx.attestedUncertainty == null ? 0 : jsn(ctx.attestedUncertainty, true));
        boolean harmCounts = !ctx.denominations.isEmpty() && !((Map<?, ?>) blast.get("harm")).isEmpty();
        Double taint = Caveats.fin(ctx.taint), age = Caveats.fin(ctx.age);
        Map<String, Object> inputs = obj(
            "semanticDistance", dist.get("value"),
            "reversibility", jsn(rev.get("value"), true),
            "blastRadius", Math.max(jsn(blast.get("normalized"), true), harmCounts ? jsn(harm.get("normalized"), true) : 0),
            "taint", taint != null ? taint : (Object) 1d,
            "confidence", 1 - uncertainty,
            "age", age != null ? age : (Object) 1d);
        double[] in = new double[Risk.KEYS.length];
        for (int i = 0; i < in.length; i++) in[i] = jsn(inputs.get(Risk.KEYS[i]), true);
        double raw = Risk.riskScore(in, ctx.weights);
        double r = ctx.calibration != null ? calibrate(raw, ctx.calibration) : raw;
        Object edgeKinds = ctx.scope != null && ctx.scope.get("edgeKinds") instanceof List ? sortedStrings((List<?>) ctx.scope.get("edgeKinds")) : null;
        String evidence = hash(obj(
            "action", canonicalActionDigest(action),
            "scope", obj("edgeKinds", edgeKinds, "maxDepth", ctx.scope == null ? null : ctx.scope.get("maxDepth")),
            "authorized", sortedStrings(ctx.authorizedKinds),
            "registry", get(cm, "registryDigest"), "graph", get(cm, "graphDigest"), "goal", get(ctx.goal, "commit"),
            "calibration", get(cm, "calibrationDigest"), "inputs", inputs));
        return obj("r", r, "valid", true, "reasons", new ArrayList<Object>(), "raw", raw, "inputs", inputs, "reversibility", rev, "blast", blast, "harm", harm, "evidenceDigest", evidence);
    }

    // ---- dispute-game oracle ------------------------------------------------------------------------------------------------------

    /** The contestable dispute game's oracle: recomputes a disputed input from the committed facts over the open-time snapshot. */
    public interface Oracle {
        Map<String, Object> resolve(Object input, Object snapshot);
    }

    private static Map<String, Object> bad(Object input, String reason) { return obj("input", input, "valid", false, "reason", reason); }

    /**
     * Recomputes the input ({@code reversibility_class}, {@code reversibility}, {@code blastRadius}, {@code semanticDistance}) from the snapshot's canonical
     * action; any mismatch or unencodable action is {@code valid: false} (indeterminate, slashes no one). Never throws.
     */
    public static Oracle objectiveRiskOracle(Context ctx) {
        return (input, snapshot) -> {
            try {
                Object a = get(get(snapshot, "action"), "action");
                if (!Zk.truthy(a) || !(get(a, "verb") instanceof String) || !(get(a, "resource") instanceof String)) return bad(input, "snapshot action is missing a canonical verb/resource");
                Object params = get(a, "params") instanceof Map ? get(a, "params") : new LinkedHashMap<String, Object>();
                Map<String, Object> res = objectiveRisk(obj("verb", get(a, "verb"), "resource", get(a, "resource"), "params", params), ctx);
                if (!Boolean.TRUE.equals(res.get("valid"))) {
                    String joined = String.join("; ", ((List<?>) res.get("reasons")).stream().map(String::valueOf).toArray(String[]::new));
                    return bad(input, joined.isEmpty() ? "objective risk could not be reproduced" : joined);
                }
                String in = input instanceof String ? (String) input : "";
                Map<String, Object> inputs = asMap(res.get("inputs"));
                switch (in) {
                    case "reversibility_class": return obj("input", input, "class", get(res.get("reversibility"), "class"), "valid", true);
                    case "reversibility": return obj("input", input, "value", inputs.get("reversibility"), "valid", true);
                    case "blastRadius": return obj("input", input, "value", inputs.get("blastRadius"), "valid", true);
                    case "semanticDistance": return obj("input", input, "value", inputs.get("semanticDistance"), "valid", true);
                    default: return bad(input, "unknown disputed input: " + IntentRevocation.jsText(input, true));
                }
            } catch (RuntimeException e) {
                return bad(input, "objective oracle error (fail closed): " + (e.getMessage() == null ? "unknown" : e.getMessage()));
            }
        };
    }
}
