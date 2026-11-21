package net.atlasauth.pca.actions;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.BiFunction;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.EdStrict;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;

/**
 * The build step of an authoring pipeline: from loaded defs to the unsigned schema, the pack, the policy cards, the ontology fragment, the MCP tool map and
 * generated TypeScript declarations, plus the signing and consistency checks of the pack. Every output is a pure function of the defs and the trait registry.
 */
public final class ActionBuild {
    private ActionBuild() {}

    /** Domain of the pack signature; it differs from the schema's, so a signature of one is never valid for the other. */
    public static final String PACK_SIGN_DOMAIN = Actions.PACK_DIGEST_DOMAIN + "\0";
    private static final Pattern IDENT_RE = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*");

    private static int byVerb(Object a, Object b) { return ((String) J.get(a, "verb")).compareTo((String) J.get(b, "verb")); }

    /**
     * Build every output: {@code {schema, pack, cards, ontology, mcp: {tools}, types}}. {@code cfg}: {@code {ns, version, stability, site, aud}}. Throws on a pack
     * above the unsharded limit, a duplicate verb, or a unit conflict (never a partial build).
     */
    public static Map<String, Object> buildArtifacts(List<?> defsIn, Map<String, Object> cfg, Actions.Registry reg, Predicate<Map<String, Object>> attestationVerified) {
        List<Object> defs = new ArrayList<>(defsIn);
        defs.sort(ActionBuild::byVerb);
        if (defs.size() > ActionPacks.MAX_PACK_DEFS) throw new IllegalArgumentException("a pack above " + ActionPacks.MAX_PACK_DEFS + " defs must be sharded (" + defs.size() + " given)");
        for (int i = 1; i < defs.size(); i++) if (J.get(defs.get(i), "verb").equals(J.get(defs.get(i - 1), "verb"))) throw new IllegalArgumentException("verb '" + J.get(defs.get(i), "verb") + "' appears twice");
        List<String> digests = new ArrayList<>();
        for (Object d : defs) digests.add(Actions.defDigest(J.m(d)));
        String root = Actions.packRoot(digests);
        Map<String, Object> meta = J.obj("site", cfg.get("site"), "aud", cfg.get("aud"), "version", cfg.get("version"), "pack", J.obj("ns", cfg.get("ns"), "version", cfg.get("version"), "root", root));
        Map<String, Object> schema = ActionDerive.toSchemaDoc(defs, reg, meta, attestationVerified);
        Map<String, Object> pack = J.obj("v", J.n(1), "kind", "pca-action-pack", "ns", cfg.get("ns"), "version", cfg.get("version"), "stability", cfg.get("stability"),
            "traits_digest", Actions.traitsDigest(reg), "roles_digest", Actions.tablesDigest(), "rules_digest", ActionLint.lintRulesDigest(), "root", root, "defs", defs, "prev", null, "evolution", new ArrayList<Object>());
        List<Object> cards = new ArrayList<>();
        for (Object d : defs) cards.add(ActionDerive.cardOf(J.m(d), ActionEffective.effective(J.m(d), reg, attestationVerified), reg));
        Map<String, Object> tools = new LinkedHashMap<>();
        for (Object d : defs) {
            Object mcp = J.get(J.get(d, "bindings"), "mcp");
            if (mcp != null) tools.put((String) J.get(mcp, "tool"), J.obj("verb", J.get(d, "verb"), "annotations", ActionDerive.mcpAnnotationsOf(J.m(d), ActionEffective.effective(J.m(d), reg, attestationVerified))));
        }
        return J.obj("schema", schema, "pack", pack, "cards", cards, "ontology", ActionDerive.toOntology(defs, reg, attestationVerified), "mcp", J.obj("tools", tools), "types", generateTypes(defs));
    }

    /** The tool-to-action map of the defs' MCP bindings: {@code (tool, args) -> {verb, resource}}, or null when the tool is unknown or the call does not bind. */
    public static BiFunction<String, Map<String, Object>, Map<String, Object>> toolActionMapOf(List<?> defs) {
        Map<String, Map<String, Object>> m = new LinkedHashMap<>();
        for (Object d : defs) {
            Object mcp = J.get(J.get(d, "bindings"), "mcp");
            if (mcp != null) m.put((String) J.get(mcp, "tool"), J.m(d));
        }
        return (tool, args) -> {
            Map<String, Object> d = m.get(tool);
            if (d == null) return null;
            Map<String, Object> r = ActionDerive.operationOf(d, args);
            if (!Boolean.TRUE.equals(r.get("ok"))) return null;
            return J.obj("verb", J.get(r.get("op"), "verb"), "resource", J.get(r.get("op"), "resource"));
        };
    }

    // ---- generated types ---------------------------------------------------------------------------------------------------------

    private static String pascal(String s) {
        StringBuilder b = new StringBuilder();
        for (String x : s.split("[._]", -1)) b.append(x.isEmpty() ? "" : x.substring(0, 1).toUpperCase(Locale.ROOT) + x.substring(1));
        return b.toString();
    }

    private static String key(String k) { return IDENT_RE.matcher(k).matches() ? k : J.stringify(k); }

    private static String union(Object values) {
        List<String> out = new ArrayList<>();
        for (Object v : J.a(values)) out.add(J.stringify(v));
        return String.join(" | ", out);
    }

    private static String tsType(Map<String, Object> p) {
        Object t = p.get("type");
        if ("integer".equals(t) || "duration".equals(t)) return "number";
        if ("boolean".equals(t)) return "boolean";
        if ("set".equals(t)) {
            String u = p.get("values") instanceof List ? union(p.get("values")) : "";
            return "Array<" + (u.isEmpty() ? "string" : u) + ">";
        }
        if ("array".equals(t)) return "integer".equals(p.get("items")) ? "number[]" : "string[]";
        return p.get("values") != null ? union(p.get("values")) : "string";
    }

    private static final class Node {
        Map<String, Object> leaf;
        final TreeMap<String, Node> kids = new TreeMap<>();
    }

    private static String render(Node n, String indent) {
        List<String> lines = new ArrayList<>();
        for (Map.Entry<String, Node> e : n.kids.entrySet()) {
            Node c = e.getValue();
            if (c.leaf != null) lines.add(indent + key(e.getKey()) + (Boolean.FALSE.equals(c.leaf.get("required")) ? "?" : "") + ": " + tsType(c.leaf) + ";");
            else lines.add(indent + key(e.getKey()) + ": {\n" + render(c, indent + "  ") + "\n" + indent + "};");
        }
        return String.join("\n", lines);
    }

    /** TypeScript declarations for typed call sites: one params interface per verb, {@code ActionParams} and {@code ActionVerb}. */
    public static String generateTypes(List<?> defs) {
        List<String> out = new ArrayList<>();
        out.add("// Generated by `pca actions build`. Do not edit.");
        out.add("");
        List<String> names = new ArrayList<>();
        List<Object> sorted = new ArrayList<>(defs);
        sorted.sort(ActionBuild::byVerb);
        for (Object d : sorted) {
            Node root = new Node();
            Map<String, Object> ps = J.m(J.get(d, "params"));
            List<String> pn = new ArrayList<>(ps.keySet());
            pn.sort(null);
            for (String name : pn) {
                Node n = root;
                String[] segs = name.split("\\.", -1);
                for (int i = 0; i < segs.length; i++) {
                    n = n.kids.computeIfAbsent(segs[i], k -> new Node());
                    if (i == segs.length - 1) n.leaf = J.m(ps.get(name));
                }
            }
            String iface = pascal((String) J.get(d, "verb")) + "Params";
            names.add("  " + J.stringify(J.get(d, "verb")) + ": " + iface + ";");
            out.add("export interface " + iface + " {");
            out.add(render(root, "  "));
            out.add("}");
            out.add("");
        }
        out.add("export interface ActionParams {");
        out.addAll(names);
        out.add("}");
        out.add("");
        out.add("export type ActionVerb = keyof ActionParams;");
        out.add("");
        return String.join("\n", out);
    }

    // ---- pack signing and consistency ----------------------------------------------------------------------------------------------

    private static byte[] packMessage(Map<String, Object> body) {
        byte[] dom = PACK_SIGN_DOMAIN.getBytes(StandardCharsets.UTF_8), b = Json.canonicalizeStrict(body).getBytes(StandardCharsets.UTF_8);
        byte[] out = new byte[dom.length + b.length];
        System.arraycopy(dom, 0, out, 0, dom.length);
        System.arraycopy(b, 0, out, dom.length, b.length);
        return out;
    }

    private static boolean isOne(Object v) { Double d = J.num(v); return d != null && d == 1.0; }

    /** Null when the pack is internally consistent: every def valid and sorted-unique, the Merkle root and digests recomputed. */
    public static String packConsistencyError(Object p, Actions.Registry reg) {
        try {
            if (!(p instanceof Map)) return "the pack must be an object";
            Map<String, Object> q = J.m(p);
            if (!"pca-action-pack".equals(q.get("kind")) || !isOne(q.get("v"))) return "not a pca-action-pack v1";
            if (!(q.get("defs") instanceof List) || J.a(q.get("defs")).size() > ActionPacks.MAX_PACK_DEFS) return "defs must be a list within the unsharded limit";
            java.util.Set<Object> seen = new java.util.HashSet<>();
            List<String> digests = new ArrayList<>();
            for (Object d : J.a(q.get("defs"))) {
                String e = Actions.validateDef(d);
                if (e != null) return "def " + (J.get(d, "verb") != null ? J.jsStr(J.get(d, "verb")) : "?") + ": " + e;
                if (!seen.add(J.get(d, "verb"))) return "verb '" + J.get(d, "verb") + "' is defined twice";
            }
            for (Object d : J.a(q.get("defs"))) digests.add(Actions.defDigest(J.m(d)));
            if (!Actions.packRoot(digests).equals(q.get("root"))) return "the pack root does not match its defs";
            if (!Actions.traitsDigest(reg).equals(q.get("traits_digest"))) return "traits_digest does not match the trait registry";
            return null;
        } catch (RuntimeException e) {
            return "malformed pack: " + e.getMessage();
        }
    }

    /** Sign a pack as the registry (Ed25519; the 32-byte seed). Refuses an inconsistent pack. */
    public static Map<String, Object> signPack(Map<String, Object> pack, String kid, byte[] secret, Actions.Registry reg) {
        String bad = packConsistencyError(pack, reg);
        if (bad != null) throw new IllegalArgumentException("signPack: " + bad);
        Map<String, Object> body = new LinkedHashMap<>(pack);
        body.remove("sig");
        String sig = Keys.b64u(Keys.edFromSeed(secret).sign(packMessage(body)));
        Map<String, Object> out = new LinkedHashMap<>(body);
        out.put("sig", J.obj("alg", "ed25519", "kid", kid, "value", sig));
        return out;
    }

    /** The registry key entry for a signer: {@code {kid, alg, pk}}. */
    public static Map<String, Object> packKeyOf(String kid, byte[] secret) { return J.obj("kid", kid, "alg", "ed25519", "pk", Keys.edFromSeed(secret).id()); }

    /** Verify a signed pack against pinned registry keys: consistency, the key entry by kid, and the signature. Never throws. Returns {@code {ok}} or {@code {ok:false, reason}}. */
    public static Map<String, Object> verifyPack(Object pack, Object keys, Actions.Registry reg) {
        try {
            String bad = packConsistencyError(pack, reg);
            if (bad != null) return J.obj("ok", Boolean.FALSE, "reason", bad);
            Map<String, Object> body = new LinkedHashMap<>(J.m(pack));
            Object sig = body.remove("sig");
            if (!(sig instanceof Map) || !"ed25519".equals(J.get(sig, "alg")) || !(J.get(sig, "kid") instanceof String) || !(J.get(sig, "value") instanceof String)) return J.obj("ok", Boolean.FALSE, "reason", "missing or malformed signature");
            Object k = null;
            for (Object x : J.a(keys)) if (J.get(sig, "kid").equals(J.get(x, "kid"))) { k = x; break; }
            if (k == null) return J.obj("ok", Boolean.FALSE, "reason", "no registry key with kid '" + J.get(sig, "kid") + "'");
            byte[] pk = Pca.decodeB64uStrict(J.get(k, "pk"), 32);
            if (!"ed25519".equals(J.get(k, "alg")) || pk == null) return J.obj("ok", Boolean.FALSE, "reason", "the registry key entry is malformed");
            byte[] sg = Pca.decodeB64uStrict(J.get(sig, "value"), 64);
            return sg != null && EdStrict.verify(pk, packMessage(body), sg) ? J.obj("ok", Boolean.TRUE) : J.obj("ok", Boolean.FALSE, "reason", "pack signature invalid");
        } catch (RuntimeException e) {
            return J.obj("ok", Boolean.FALSE, "reason", "pack verification error: " + e.getMessage());
        }
    }
}
