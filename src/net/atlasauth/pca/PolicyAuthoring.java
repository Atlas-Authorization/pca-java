package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Forbid-wins certificate check (security contract C-241) and linked policy templates (C-242, C-243): a port of
 * {@code certificateConsistent} in packages/pca/src/forbid-certificate.ts and of packages/pca/src/policy-link.ts (the TypeScript
 * is authoritative; same reason strings). Every function is total (no exception escapes); anything malformed fails closed.
 * Inputs are {@link Json} trees (maps, lists, strings, booleans, {@link Json.Num}).
 */
public final class PolicyAuthoring {
    private PolicyAuthoring() {}

    private static final String TEMPLATE_SIG_DOMAIN = "atlas-pca/policy-template/v1\0";
    private static final String TIGHTEN_SIG_DOMAIN = "atlas-pca/template-tighten/v1\0";
    private static final String NAME_SOURCE = "^[a-z][a-z0-9_]{0,63}$";
    private static final Pattern NAME_RE = Pattern.compile("[a-z][a-z0-9_]{0,63}");

    /** A result with either a value or a reason. */
    public static final class Result {
        public final Map<String, Object> policy;
        public final int overlays;
        public final String reason;
        Result(Map<String, Object> policy, int overlays, String reason) { this.policy = policy; this.overlays = overlays; this.reason = reason; }
    }

    private static boolean isOne(Object v) { Double d = IntentJs.num(v); return d != null && d == 1.0; }
    private static Object g(Object o, String k) { return IntentJs.get(o, k); }
    private static boolean nameOk(Object s) { return s instanceof String && NAME_RE.matcher((String) s).matches(); }

    // ---- forbid-wins certificate ----------------------------------------------------------------

    private record Row(String id, String kind, String value, String signer) {}

    /** Whether the certificate's own table entails its decision, winner and shadowed list (no predicate evaluator needed). */
    public static boolean forbidCertificateConsistent(Object cert, List<String> precedence) {
        try {
            if (!(cert instanceof Map) || !isOne(g(cert, "v")) || !"forbid-wins".equals(g(cert, "kind"))) return false;
            if (!(g(cert, "clauses") instanceof List) || !(g(cert, "winner") instanceof Map) || !(g(cert, "shadowed") instanceof List)) return false;
            List<?> rows = (List<?>) g(cert, "clauses");
            Map<?, ?> winner = (Map<?, ?>) g(cert, "winner");
            List<?> shadowed = (List<?>) g(cert, "shadowed");
            if ("malformed".equals(winner.get("kind"))) {
                return rows.isEmpty() && "deny".equals(g(cert, "decision")) && winner.containsKey("id") && winner.get("id") == null && shadowed.isEmpty();
            }
            List<String> prec = precedence == null ? List.of() : precedence;
            List<Row> table = new ArrayList<>();
            for (Object r : rows) {
                if (!(r instanceof Map) || !(g(r, "id") instanceof String) || !(g(r, "kind") instanceof String) || !(g(r, "value") instanceof String)) return false;
                String kind = (String) g(r, "kind"), value = (String) g(r, "value");
                if (!(kind.equals("permit") || kind.equals("forbid") || kind.equals("escalate"))) return false;
                if (!(value.equals("true") || value.equals("false") || value.equals("unknown"))) return false;
                Object s = g(r, "signer");
                table.add(new Row((String) g(r, "id"), kind, value, s instanceof String ? (String) s : null));
            }
            java.util.function.ToIntFunction<Row> rank = r -> {
                int i = r.signer() == null ? -1 : prec.indexOf(r.signer());
                return i < 0 ? prec.size() : i; // an unlisted (or absent) signer ranks last
            };
            List<Row> forbids = hit(table, "forbid");
            forbids.sort((a, b) -> {
                int c = Integer.compare(rank.applyAsInt(a), rank.applyAsInt(b));
                return c != 0 ? c : a.id().compareTo(b.id()); // String.compareTo orders by UTF-16 code unit like JavaScript
            });
            List<Row> permits = hit(table, "permit"), escalates = hit(table, "escalate");
            Row win;
            String decision, kind;
            if (!forbids.isEmpty()) { win = forbids.get(0); decision = "deny"; kind = "forbid"; }
            else if (permits.isEmpty()) { win = null; decision = "deny"; kind = "none"; }
            else if (!escalates.isEmpty()) { win = escalates.get(0); decision = "escalate"; kind = "escalate"; }
            else { win = permits.get(0); decision = "allow"; kind = "permit"; }
            List<String> others = new ArrayList<>();
            for (List<Row> group : List.of(forbids, permits, escalates)) for (Row r : group) if (r != win) others.add(r.id());
            boolean idOk = win == null ? winner.get("id") == null : win.id().equals(winner.get("id"));
            if (!decision.equals(g(cert, "decision")) || !kind.equals(winner.get("kind")) || !idOk || shadowed.size() != others.size()) return false;
            for (int i = 0; i < others.size(); i++) if (!others.get(i).equals(shadowed.get(i))) return false;
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static List<Row> hit(List<Row> table, String kind) {
        List<Row> out = new ArrayList<>();
        for (Row r : table) if (r.kind().equals(kind) && !r.value().equals("false")) out.add(r);
        return out;
    }

    // ---- linked templates -------------------------------------------------------------------------

    private static String jsString(Object x) {
        if (x == null) return "null";
        if (x instanceof String) return (String) x;
        if (x instanceof Boolean || x instanceof Json.Num) return x.toString();
        return "object";
    }

    private static boolean forbiddenKey(String k) { return k.equals("__proto__") || k.equals("constructor") || k.equals("prototype"); }

    private static String scan(Object v, Map<?, ?> decl, Set<String> used) {
        if (v instanceof List) {
            for (Object x : (List<?>) v) { String e = scan(x, decl, used); if (e != null) return e; }
            return null;
        }
        if (!(v instanceof Map)) return null;
        Map<?, ?> o = (Map<?, ?>) v;
        for (Object k : o.keySet()) if (forbiddenKey((String) k)) return "body has the forbidden key '" + k + "'";
        if (o.containsKey("$slot")) {
            for (Object k : o.keySet()) if (!k.equals("$slot") && !k.equals("pre") && !k.equals("post")) return "placeholder has unknown member '" + k + "'";
            Object name = o.get("$slot");
            if (!(name instanceof String) || !decl.containsKey(name)) return "placeholder names undeclared slot '" + jsString(name) + "'";
            for (String k : new String[] {"pre", "post"}) if (o.containsKey(k) && !(o.get(k) instanceof String)) return "placeholder " + k + " must be a string";
            used.add((String) name);
            return null;
        }
        for (Object k : o.keySet()) { String e = scan(o.get(k), decl, used); if (e != null) return e; }
        return null;
    }

    /** null for a well-formed template definition, else the first problem. */
    public static String templateDefError(Object def) {
        if (!(def instanceof Map)) return "template must be an object";
        if (!isOne(g(def, "v")) || !"pca-policy-template".equals(g(def, "kind"))) return "template v / kind mismatch";
        if (!nameOk(g(def, "id"))) return "template id must match " + NAME_SOURCE;
        Object ver = g(def, "version");
        if (!(ver instanceof String) || ((String) ver).isEmpty() || ((String) ver).length() > 64) return "template version must be a string of 1..64 characters";
        if (!(g(def, "slots") instanceof Map)) return "slots must be an object";
        Map<?, ?> slots = (Map<?, ?>) g(def, "slots");
        if (slots.size() > 32) return "more than 32 slots";
        for (Map.Entry<?, ?> en : slots.entrySet()) {
            String n = (String) en.getKey();
            if (!NAME_RE.matcher(n).matches()) return "slot name '" + n + "' must match " + NAME_SOURCE;
            if (!(en.getValue() instanceof Map)) return "slot '" + n + "' must be an object";
            Map<?, ?> s = (Map<?, ?>) en.getValue();
            Object ty = s.get("type");
            if (!("string".equals(ty) || "integer".equals(ty) || "set".equals(ty))) return "slot '" + n + "'.type must be string, integer or set";
            if ("set".equals(ty) && !(s.get("values") instanceof List)) return "set slot '" + n + "' needs a closed values list";
            if (s.containsKey("values")) {
                Object vl = s.get("values");
                boolean ok = vl instanceof List && ((List<?>) vl).size() <= 64;
                if (ok) for (Object x : (List<?>) vl) if (!(x instanceof String)) ok = false;
                if (!ok) return "slot '" + n + "'.values must be a list of strings";
            }
            if ("integer".equals(ty)) {
                for (String k : new String[] {"min", "max"}) if (s.containsKey(k) && !IntentJs.isSafeInteger(s.get(k))) return "slot '" + n + "'." + k + " must be a safe integer";
            }
        }
        Object body = g(def, "body");
        if (!(body instanceof Map) || !(g(body, "predicates") instanceof List)) return "body.predicates must be an array";
        if (((Map<?, ?>) body).containsKey("caveats") && !(g(body, "caveats") instanceof List)) return "body.caveats must be an array";
        Set<String> used = new HashSet<>();
        String err = scan(body, slots, used);
        if (err != null) return err;
        for (Object n : slots.keySet()) if (!used.contains(n)) return "slot '" + n + "' is declared but never used";
        return null;
    }

    /** hashCanonical of the definition. */
    public static String templateDigest(Object def) { return Pca.hashCanonical(def); }

    private static byte[] message(String domain, String digest) {
        try {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(digest.getBytes(StandardCharsets.UTF_8));
            return Pca.concat(domain.getBytes(StandardCharsets.UTF_8), h);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Verify a signed template {@code {def, signer, sig}}: null when it verifies, else the reason. */
    public static String verifyTemplate(Object t, List<String> trusted) {
        try {
            String e = templateDefError(g(t, "def"));
            if (e != null) return e;
            Object signer = g(t, "signer");
            if (!(signer instanceof String) || !trusted.contains(signer)) return "template signer is not trusted";
            if (!IntentJs.verifyEd(signer, message(TEMPLATE_SIG_DOMAIN, templateDigest(g(t, "def"))), g(t, "sig"))) return "bad template signature";
            return null;
        } catch (RuntimeException e) {
            return "template verification error (fail closed)";
        }
    }

    /** null for a well-formed tighten overlay: it may only add {@code where} conditions and caveats. */
    public static String tightenOverlayError(Object o) {
        if (!(o instanceof Map)) return "overlay must be an object";
        Map<?, ?> m = (Map<?, ?>) o;
        if (!isOne(m.get("v")) || !"pca-template-tighten".equals(m.get("kind"))) return "overlay v / kind mismatch";
        for (Object k : m.keySet()) {
            if (!(k.equals("v") || k.equals("kind") || k.equals("template_id") || k.equals("version_digest") || k.equals("add_where") || k.equals("add_caveats"))) {
                return "overlay has unknown member '" + k + "' (an overlay can only add where conditions and caveats)";
            }
        }
        if (!nameOk(m.get("template_id"))) return "overlay template_id invalid";
        if (!(m.get("version_digest") instanceof String) || ((String) m.get("version_digest")).isEmpty()) return "overlay version_digest invalid";
        if (m.containsKey("add_where")) {
            boolean ok = m.get("add_where") instanceof List;
            if (ok) for (Object c : (List<?>) m.get("add_where")) if (!(c instanceof Map)) ok = false;
            if (!ok) return "overlay add_where must be a list of conditions";
        }
        if (m.containsKey("add_caveats")) {
            boolean ok = m.get("add_caveats") instanceof List;
            if (ok) for (Object c : (List<?>) m.get("add_caveats")) if (!(c instanceof Map) || !(g(c, "type") instanceof String)) ok = false;
            if (!ok) return "overlay add_caveats must be a list of caveats";
        }
        return null;
    }

    /** Verify a signed overlay {@code {overlay, signer, sig}}: null when it verifies, else the reason. */
    public static String verifyTighten(Object t, List<String> trusted) {
        try {
            String e = tightenOverlayError(g(t, "overlay"));
            if (e != null) return e;
            Object signer = g(t, "signer");
            if (!(signer instanceof String) || !trusted.contains(signer)) return "overlay signer is not trusted";
            if (!IntentJs.verifyEd(signer, message(TIGHTEN_SIG_DOMAIN, Pca.hashCanonical(g(t, "overlay"))), g(t, "sig"))) return "bad overlay signature";
            return null;
        } catch (RuntimeException e) {
            return "overlay verification error (fail closed)";
        }
    }

    private static String slotValueError(String name, Map<?, ?> d, Object v) {
        List<String> values = null;
        if (d.get("values") instanceof List) {
            values = new ArrayList<>();
            for (Object x : (List<?>) d.get("values")) if (x instanceof String) values.add((String) x);
        }
        Object ty = d.get("type");
        if ("string".equals(ty)) {
            if (!(v instanceof String) || ((String) v).isEmpty() || ((String) v).length() > 256) return "slot '" + name + "' must be a string of 1..256 characters";
            if (values != null && !values.contains(v)) return "slot '" + name + "' is outside its closed value set";
            return null;
        }
        if ("integer".equals(ty)) {
            if (!IntentJs.isSafeInteger(v)) return "slot '" + name + "' must be a safe integer";
            long n = IntentJs.lng(v);
            if (d.containsKey("min") && IntentJs.isSafeInteger(d.get("min")) && n < IntentJs.lng(d.get("min"))) return "slot '" + name + "' is below its minimum";
            if (d.containsKey("max") && IntentJs.isSafeInteger(d.get("max")) && n > IntentJs.lng(d.get("max"))) return "slot '" + name + "' is above its maximum";
            return null;
        }
        boolean ok = v instanceof List && !((List<?>) v).isEmpty() && ((List<?>) v).size() <= 64;
        if (ok) for (Object x : (List<?>) v) if (!(x instanceof String)) ok = false;
        if (!ok) return "slot '" + name + "' must be a non-empty list of strings";
        List<?> strs = (List<?>) v;
        if (new HashSet<>(strs).size() != strs.size()) return "slot '" + name + "' has duplicate members";
        if (values != null) for (Object x : strs) if (!values.contains(x)) return "slot '" + name + "' has a member outside its closed set";
        return null;
    }

    private static final class Refusal extends RuntimeException {
        Refusal(String m) { super(m, null, false, false); }
    }

    private static Object fill(Object v, Map<?, ?> slots, String key) {
        if (v instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object x : (List<?>) v) out.add(fill(x, slots, key));
            return out;
        }
        if (!(v instanceof Map)) return v;
        Map<?, ?> o = (Map<?, ?>) v;
        if (o.get("$slot") instanceof String) {
            String name = (String) o.get("$slot");
            Object val = slots.get(name);
            if ("verb".equals(key) || "resource".equals(key)) {
                List<?> items = val instanceof List ? (List<?>) val : java.util.Collections.singletonList(val);
                for (Object x : items) {
                    if (x instanceof String && (((String) x).contains("*") || ((String) x).startsWith("re:"))) {
                        throw new Refusal("slot '" + name + "' would inject a wildcard or regex matcher into a verb or resource");
                    }
                }
            }
            String pre = o.get("pre") instanceof String ? (String) o.get("pre") : "";
            String post = o.get("post") instanceof String ? (String) o.get("post") : "";
            if (pre.isEmpty() && post.isEmpty()) return val;
            if (!(val instanceof String) || ((String) val).contains("*") || ((String) val).contains("\0")) {
                throw new Refusal("slot '" + name + "' cannot be spliced into a string (wildcard or non-string)");
            }
            String out = pre + val + post;
            if (pre.isEmpty() && out.startsWith("re:")) throw new Refusal("slot '" + name + "' would inject a regex matcher");
            return out;
        }
        Map<String, Object> m = new LinkedHashMap<>();
        for (Map.Entry<?, ?> e : o.entrySet()) m.put((String) e.getKey(), fill(e.getValue(), slots, (String) e.getKey()));
        return m;
    }

    private static Map<String, Object> policyOf(Object predicates, Object caveats) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("predicates", predicates);
        m.put("caveats", caveats);
        return m;
    }

    /**
     * Fill a template's slots. Refuses unfilled, extra, mistyped and out-of-domain slots and any slot value that would inject a
     * wildcard or a regex into a verb or resource. On success {@code policy} is {@code {predicates, caveats}}, else {@code reason}.
     */
    public static Result instantiateTemplate(Object def, Object slots) {
        try {
            String e = templateDefError(def);
            if (e != null) return new Result(null, 0, e);
            if (!(slots instanceof Map)) return new Result(null, 0, "slots must be an object");
            Map<?, ?> sl = (Map<?, ?>) slots;
            Map<?, ?> decl = (Map<?, ?>) g(def, "slots");
            for (Object k : sl.keySet()) if (!decl.containsKey(k)) return new Result(null, 0, "slot '" + k + "' is not declared by the template");
            for (Map.Entry<?, ?> en : decl.entrySet()) {
                String n = (String) en.getKey();
                if (!sl.containsKey(n)) return new Result(null, 0, "slot '" + n + "' is not filled");
                String se = slotValueError(n, (Map<?, ?>) en.getValue(), sl.get(n));
                if (se != null) return new Result(null, 0, se);
            }
            Map<?, ?> body = (Map<?, ?>) fill(g(def, "body"), sl, null);
            return new Result(policyOf(body.get("predicates"), body.containsKey("caveats") ? body.get("caveats") : new ArrayList<>()), 0, null);
        } catch (Refusal r) {
            return new Result(null, 0, r.getMessage());
        } catch (RuntimeException e) {
            return new Result(null, 0, "instantiation error (fail closed)");
        }
    }

    /** null for a well-formed reference {@code {template_id, version_digest, slots}}. */
    public static String templateRefError(Object r) {
        if (!(r instanceof Map)) return "template_ref must be an object";
        Map<?, ?> m = (Map<?, ?>) r;
        for (Object k : m.keySet()) if (!(k.equals("template_id") || k.equals("version_digest") || k.equals("slots") || k.equals("bind_params_digest"))) return "template_ref has unknown member '" + k + "'";
        if (!nameOk(m.get("template_id"))) return "template_ref.template_id invalid";
        Object vd = m.get("version_digest");
        if (!(vd instanceof String) || ((String) vd).isEmpty() || ((String) vd).getBytes(StandardCharsets.UTF_8).length > 128) return "template_ref.version_digest invalid";
        if (m.containsKey("slots") && m.containsKey("bind_params_digest")) return "template_ref has both slots and bind_params_digest";
        if (m.containsKey("bind_params_digest")) {
            Object bd = m.get("bind_params_digest");
            return bd instanceof String && !((String) bd).isEmpty() && ((String) bd).length() <= 128 ? null : "template_ref.bind_params_digest invalid";
        }
        if (!(m.get("slots") instanceof Map)) return "template_ref.slots must be an object";
        return null;
    }

    /** Rebuild the policy a reference denotes from a registry {@code {templates, overlays?, trusted}}. */
    @SuppressWarnings("unchecked")
    public static Result resolveLink(Object ref, Object reg) {
        try {
            String e = templateRefError(ref);
            if (e != null) return new Result(null, 0, e);
            List<String> trusted = new ArrayList<>();
            if (g(reg, "trusted") instanceof List) for (Object x : (List<?>) g(reg, "trusted")) if (x instanceof String) trusted.add((String) x);
            String digest = (String) g(ref, "version_digest");
            Object templates = g(reg, "templates");
            if (!(templates instanceof Map) || !((Map<?, ?>) templates).containsKey(digest)) return new Result(null, 0, "template version is not in the registry");
            Object t = ((Map<?, ?>) templates).get(digest);
            String v = verifyTemplate(t, trusted);
            if (v != null) return new Result(null, 0, v);
            Object def = g(t, "def");
            if (!digest.equals(templateDigest(def))) return new Result(null, 0, "registry entry does not match its digest");
            if (!IntentJs.jsonEquals(g(def, "id"), g(ref, "template_id"))) return new Result(null, 0, "template id does not match the reference");
            Object slots = g(ref, "slots");
            if (((Map<?, ?>) ref).containsKey("bind_params_digest")) {
                String bd = (String) g(ref, "bind_params_digest");
                Object params = g(reg, "params");
                Object bound = params instanceof Map && ((Map<?, ?>) params).containsKey(bd) ? ((Map<?, ?>) params).get(bd) : null;
                if (!(bound instanceof Map)) return new Result(null, 0, "parameter object is not available");
                if (!Pca.hashCanonical(bound).equals(bd)) return new Result(null, 0, "parameter object does not match bind_params_digest");
                slots = bound;
            }
            Result inst = instantiateTemplate(def, slots);
            if (inst.policy == null) return inst;
            List<Object> predicates = new ArrayList<>((List<Object>) inst.policy.get("predicates"));
            List<Object> caveats = new ArrayList<>((List<Object>) inst.policy.get("caveats"));
            int applied = 0;
            Object overlays = g(reg, "overlays");
            if (overlays instanceof List) {
                for (Object o : (List<?>) overlays) {
                    Object ov = g(o, "overlay");
                    if (!(ov instanceof Map) || !IntentJs.jsonEquals(g(ov, "version_digest"), g(ref, "version_digest")) || !IntentJs.jsonEquals(g(ov, "template_id"), g(ref, "template_id"))) continue;
                    String vv = verifyTighten(o, trusted);
                    if (vv != null) return new Result(null, 0, vv);
                    List<Object> add = g(ov, "add_where") instanceof List ? (List<Object>) g(ov, "add_where") : new ArrayList<>();
                    List<Object> next = new ArrayList<>();
                    for (Object p : predicates) {
                        Map<String, Object> m = new LinkedHashMap<>((Map<String, Object>) p);
                        List<Object> w = new ArrayList<>(g(p, "where") instanceof List ? (List<Object>) g(p, "where") : new ArrayList<>());
                        w.addAll(add);
                        m.put("where", w);
                        next.add(m);
                    }
                    predicates = next;
                    if (g(ov, "add_caveats") instanceof List) caveats.addAll((List<Object>) g(ov, "add_caveats"));
                    applied++;
                }
            }
            return new Result(policyOf(predicates, caveats), applied, null);
        } catch (RuntimeException e) {
            return new Result(null, 0, "link resolution error (fail closed)");
        }
    }
}
