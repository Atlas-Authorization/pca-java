package net.atlasauth.pca.abe;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import net.atlasauth.pca.Json;

/**
 * Access structures over attributes: a monotone boolean formula as a threshold tree.
 *
 * <ul>
 *   <li>{@code {"attr": a}}: leaf, the holder must own the key for attribute a</li>
 *   <li>{@code {"allOf": [...]}}: AND (n-of-n)</li>
 *   <li>{@code {"anyOf": [...]}}: OR (1-of-n)</li>
 *   <li>{@code {"threshold": k, "of": [...]}}: k-of-n</li>
 * </ul>
 *
 * The normalised form is a JSON tree: {@code {"kind":"leaf","attr":a}} or {@code {"kind":"gate","t":k,"of":[...]}} with
 * {@code t} a {@link Long}. Negation is not supported (ABE access structures are monotone).
 */
public final class AbePolicy {
    private AbePolicy() {}

    /** Upper bound on total nodes in a policy tree (bounds work on untrusted input). */
    public static final int MAX_POLICY_NODES = 1024;

    /**
     * Upper bound on gate nesting along any root-to-leaf path: the ciphertext header is authenticated as canonical JSON
     * (nesting capped at 32), each gate costs three JSON levels and the root sits at level 2, so 10 gates is the most
     * that can be authenticated. Enforcing it here makes "encryptable" imply "decryptable".
     */
    public static final int MAX_POLICY_DEPTH = 10;

    /** Result of {@link #normalize}: {@code tree} on success, else {@code reason}. */
    public static final class Result {
        public final Map<String, Object> tree;
        public final String reason;

        Result(Map<String, Object> tree, String reason) { this.tree = tree; this.reason = reason; }

        public boolean ok() { return tree != null; }

        /** The reference's JSON shape: {@code {ok:true, tree}} or {@code {ok:false, reason}}. */
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", ok());
            if (ok()) m.put("tree", tree);
            else m.put("reason", reason);
            return m;
        }
    }

    private static final class Fail extends RuntimeException {
        Fail(String reason) { super(reason, null, false, false); }
    }

    public static Map<String, Object> leaf(String attr) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kind", "leaf");
        m.put("attr", attr);
        return m;
    }

    public static Map<String, Object> gate(long t, List<Object> of) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kind", "gate");
        m.put("t", t);
        m.put("of", of);
        return m;
    }

    /** The value of a JSON number as JavaScript reads it (a double), or null when not a number. */
    static Double num(Object o) {
        if (o instanceof Json.Num) {
            try { return Double.parseDouble(((Json.Num) o).raw); } catch (NumberFormatException e) { return null; }
        }
        if (o instanceof Integer || o instanceof Long || o instanceof Double || o instanceof Float) return ((Number) o).doubleValue();
        return null;
    }

    /** JavaScript {@code typeof x === 'number' && Number.isInteger(x) && x > 0}. */
    static boolean isPosInt(Object o) {
        Double d = num(o);
        return d != null && !d.isInfinite() && !d.isNaN() && d == Math.rint(d) && d > 0;
    }

    /** JavaScript's String(n) for a positive integral double. */
    static String jsInt(double d) {
        if (d < 1e21) return new BigDecimal(d).toPlainString();
        String s = Double.toString(d); // e.g. 1.0E21
        int e = s.indexOf('E');
        String m = s.substring(0, e);
        if (m.endsWith(".0")) m = m.substring(0, m.length() - 2);
        return m + "e+" + s.substring(e + 1);
    }

    /** Validate and normalise an access structure; fails closed with a reason on any malformed node or oversized tree. */
    public static Result normalize(Object policy) {
        try {
            return new Result(walk(policy, "policy", 0, new int[1]), null);
        } catch (Fail f) {
            return new Result(null, f.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> walk(Object p, String path, int gates, int[] nodes) {
        if (++nodes[0] > MAX_POLICY_NODES) throw new Fail("policy too large (> " + MAX_POLICY_NODES + " nodes)");
        if (!(p instanceof Map)) throw new Fail(path + ": not an object");
        Map<String, Object> m = (Map<String, Object>) p;
        if (m.containsKey("attr")) {
            Object a = m.get("attr");
            if (!(a instanceof String) || ((String) a).isEmpty()) throw new Fail(path + ": 'attr' must be a non-empty string");
            if (Json.hasLoneSurrogate((String) a)) throw new Fail(path + ": 'attr' is not well-formed UTF-16");
            if (m.containsKey("allOf") || m.containsKey("anyOf") || m.containsKey("threshold") || m.containsKey("of"))
                throw new Fail(path + ": a leaf must not mix 'attr' with a gate");
            return leaf((String) a);
        }
        List<String> gateKeys = new ArrayList<>();
        for (String k : new String[] {"allOf", "anyOf", "threshold", "of"})
            if (m.containsKey(k) && !(k.equals("of") && m.containsKey("threshold"))) gateKeys.add(k);
        if (gateKeys.size() > 1)
            throw new Fail(path + ": ambiguous node (" + String.join(", ", gateKeys) + "); a gate must use exactly one of allOf/anyOf/threshold");
        if (gateKeys.size() == 1 && gates + 1 > MAX_POLICY_DEPTH) throw new Fail(path + ": policy nested deeper than " + MAX_POLICY_DEPTH + " gates");
        if (m.containsKey("allOf")) {
            List<Object> kids = children(m.get("allOf"), "allOf", path, gates, nodes);
            return gate(kids.size(), kids);
        }
        if (m.containsKey("anyOf")) return gate(1, children(m.get("anyOf"), "anyOf", path, gates, nodes));
        if (m.containsKey("threshold")) {
            Object t = m.get("threshold");
            if (!isPosInt(t)) throw new Fail(path + ": 'threshold' must be a positive integer");
            List<Object> kids = children(m.get("of"), "of", path, gates, nodes);
            double d = num(t);
            if (d > kids.size()) throw new Fail(path + ": threshold " + jsInt(d) + " exceeds the number of branches (" + kids.size() + ")");
            return gate((long) d, kids);
        }
        throw new Fail(path + ": unknown policy node (expected attr/allOf/anyOf/threshold)");
    }

    private static List<Object> children(Object raw, String key, String path, int gates, int[] nodes) {
        if (!(raw instanceof List) || ((List<?>) raw).isEmpty()) throw new Fail(path + ": '" + key + "' must be a non-empty array");
        List<?> l = (List<?>) raw;
        List<Object> out = new ArrayList<>(l.size());
        for (int i = 0; i < l.size(); i++) out.add(walk(l.get(i), path + "." + key + "[" + i + "]", gates + 1, nodes));
        return out;
    }

    static boolean isLeaf(Map<String, Object> n) { return "leaf".equals(n.get("kind")); }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> of(Map<String, Object> n) { return (List<Map<String, Object>>) (List<?>) n.get("of"); }

    static int t(Map<String, Object> n) { return num(n.get("t")).intValue(); }

    /** Non-cryptographic prediction: does the attribute set satisfy the tree? (Enforcement is the cryptography.) */
    public static boolean satisfies(Map<String, Object> tree, Set<String> attrs) {
        if (isLeaf(tree)) return attrs.contains((String) tree.get("attr"));
        int met = 0;
        for (Map<String, Object> c : of(tree)) if (satisfies(c, attrs)) met++;
        return met >= t(tree);
    }

    /** Every attribute the tree names, sorted (UTF-16 code unit order, as the reference sorts). */
    public static List<String> policyAttributes(Map<String, Object> tree) {
        Set<String> out = new TreeSet<>();
        collect(tree, out);
        return new ArrayList<>(out);
    }

    private static void collect(Map<String, Object> tree, Collection<String> into) {
        if (isLeaf(tree)) into.add((String) tree.get("attr"));
        else for (Map<String, Object> c : of(tree)) collect(c, into);
    }

    /** Leaf attributes in depth-first order (one span-program row each). */
    static List<String> leaves(Map<String, Object> tree) {
        List<String> out = new ArrayList<>();
        collect(tree, out);
        return out;
    }
}
