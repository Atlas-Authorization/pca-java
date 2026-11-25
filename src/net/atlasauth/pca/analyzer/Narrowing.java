package net.atlasauth.pca.analyzer;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Catalog;
import net.atlasauth.pca.EdStrict;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.Predicates;
import net.atlasauth.pca.analyzer.Enumerate.PolicyModel;

/**
 * LEAST PRIVILEGE FROM OBSERVED BEHAVIOUR. {@code suggestNarrowing(policy, observed)} proposes a narrower replacement for a grant from what
 * its holder really did, plus the unused-permission findings ranked by blast radius and reversibility. It is a REVIEW artefact, never
 * applied: it only narrows (the proposal is "the original predicate AND extra conditions", then PROVEN subsumed by the original; if the proof
 * is not exact the proposal is withheld), only ledger-sourced observations count, a denied attempt never loosens a grant (it becomes an
 * access request for a human), and an optional decay appends an {@code expires} caveat.
 */
public final class Narrowing {
    private Narrowing() {}

    public static final String ACCESS_REQUEST_SIG_DOMAIN = "atlas-pca/access-request/v1\0";

    private static int revWeight(String r) { return Analyzer.REVERSIBILITY_ORDER.indexOf(r) + 1; }

    private static String commonPrefix(List<String> rs) {
        String p = rs.isEmpty() ? "" : rs.get(0);
        for (String r : rs) {
            int i = 0;
            while (i < p.length() && i < r.length() && p.charAt(i) == r.charAt(i)) i++;
            p = p.substring(0, i);
        }
        int cut = p.lastIndexOf('/');
        return cut >= 0 ? p.substring(0, cut + 1) : "";
    }

    private static double upperBoundOf(Object where, String path) {
        double ub = Double.POSITIVE_INFINITY;
        if (where instanceof List) {
            for (Object c : (List<?>) where) {
                Object op = Js.get(c, "op");
                if ((c instanceof Map) && Js.has(c, "field") && path.equals(Js.get(c, "field")) && ("lte".equals(op) || "lt".equals(op)) && Js.isNum(Js.get(c, "value"))) {
                    ub = Math.min(ub, Js.num(Js.get(c, "value")));
                }
            }
        }
        return ub;
    }

    private static Map<String, Object> ctxOf(Object a) {
        Object p = Js.get(a, "params");
        return Js.obj("action", Js.obj("verb", Js.get(a, "verb"), "resource", Js.get(a, "resource"), "params", p == null ? Js.obj() : p));
    }

    private static boolean matches(Object p, Object a) { return Predicates.predicateMatches(p, ctxOf(a)); }

    private static Catalog.Spec resolveAction(Catalog catalog, String verb) {
        Catalog.Spec s = catalog.get(verb);
        if (s != null) return s;
        // an unknown verb is treated as irreversible with maximum blast radius
        String[] parts = verb.split("\\.", -1);
        return new Catalog.Spec(parts[0], parts.length > 1 ? String.join(".", java.util.Arrays.copyOfRange(parts, 1, parts.length)) : verb, verb, "irreversible", 1, null, "(uncatalogued) " + verb, null, null);
    }

    private static Object paramOf(Object a, String name) {
        Object p = Js.get(a, "params");
        return p instanceof Map ? Js.map(p).get(name) : null;
    }

    private static boolean hasParam(Object a, String name) { return Js.get(a, "params") instanceof Map && Js.map(Js.get(a, "params")).containsKey(name); }

    private static List<Object> build(List<Object> base, List<Object> trusted, boolean narrowResources, double margin, double minSamples, double enumLimit) {
        List<Object> out = new ArrayList<>();
        for (Object p : base) {
            List<Object> hits = new ArrayList<>();
            for (Object a : trusted) if (matches(p, a)) hits.add(a);
            if (hits.isEmpty()) continue;
            Set<String> vs = new LinkedHashSet<>(), rs = new LinkedHashSet<>();
            for (Object h : hits) { vs.add((String) Js.get(h, "verb")); rs.add((String) Js.get(h, "resource")); }
            List<String> verbs = new ArrayList<>(vs), resources = new ArrayList<>(rs);
            Collections.sort(verbs);
            Collections.sort(resources);
            Map<String, Object> next = Js.obj("verb", verbs.size() == 1 ? (Object) verbs.get(0) : new ArrayList<Object>(verbs));
            if (narrowResources) {
                if (resources.size() == 1) next.put("resource", resources.get(0));
                else {
                    String pre = commonPrefix(resources);
                    if (pre.length() > 1) next.put("resource", pre + "*");
                    else if (Js.has(p, "resource")) next.put("resource", Js.get(p, "resource"));
                }
            } else if (Js.has(p, "resource")) next.put("resource", Js.get(p, "resource"));
            List<Object> where = new ArrayList<>();
            Object pw = Js.get(p, "where");
            if (pw instanceof List) where.addAll((List<?>) pw);
            Set<String> nameSet = new LinkedHashSet<>();
            for (Object h : hits) { Object hp = Js.get(h, "params"); if (hp instanceof Map) nameSet.addAll(Js.map(hp).keySet()); }
            List<String> names = new ArrayList<>(nameSet);
            Collections.sort(names);
            for (String name : names) {
                String path = "action.params." + name;
                List<Object> vals = new ArrayList<>();
                boolean anyUndef = false;
                for (Object h : hits) { vals.add(paramOf(h, name)); if (!hasParam(h, name)) anyUndef = true; }
                if (vals.size() < minSamples || anyUndef) continue;
                boolean allNum = true, allStr = true;
                for (Object v : vals) { if (!Js.isFin(v)) allNum = false; if (!(v instanceof String)) allStr = false; }
                if (allNum) {
                    double mx = Double.NEGATIVE_INFINITY;
                    boolean allInt = true;
                    for (Object v : vals) { double d = Js.num(v); mx = Math.max(mx, d); if (d != Math.rint(d)) allInt = false; }
                    double v2 = mx * (1 + margin);
                    double ceil = allInt ? Math.ceil(v2) : v2;
                    if (ceil < upperBoundOf(pw, path)) where.add(Js.obj("field", path, "op", "lte", "value", Js.n(ceil)));
                } else if (allStr) {
                    Set<String> set = new LinkedHashSet<>();
                    for (Object v : vals) set.add((String) v);
                    List<String> sorted = new ArrayList<>(set);
                    Collections.sort(sorted);
                    if (sorted.size() <= enumLimit) where.add(Js.obj("field", path, "op", "in", "value", new ArrayList<Object>(sorted)));
                }
            }
            if (!where.isEmpty()) next.put("where", where);
            out.add(next);
        }
        return out;
    }

    /**
     * Propose a narrower grant from what the holder did, and list what was never used. Never applies anything. {@code observed} items are
     * {verb, resource, params?, source: "ledger" | "agent", outcome?: "allowed" | "denied", entry?}. Options: margin (default 0.1), minSamples (5),
     * enumLimit (8), taskBinding, decay {nowSec, expiresInSecs}. {@code catalog} null = the built-in connector catalog.
     */
    public static Map<String, Object> suggestNarrowing(Object policy, List<Object> observed, Map<String, Object> o, Catalog catalog) {
        double margin = Js.get(o, "margin") == null ? 0.1 : Js.toNum(Js.get(o, "margin"));
        double minSamples = Js.get(o, "minSamples") == null ? 5 : Js.toNum(Js.get(o, "minSamples"));
        double enumLimit = Js.get(o, "enumLimit") == null ? 8 : Js.toNum(Js.get(o, "enumLimit"));
        Catalog cat = catalog == null ? Catalog.DEFAULT : catalog;
        PolicyModel model = Enumerate.toModel(policy);
        String digest = Residual.policyDigestOf(model);

        List<Object> trusted = new ArrayList<>(), refused = new ArrayList<>();
        int rejected = 0;
        for (Object x : observed) {
            boolean ledger = "ledger".equals(Js.get(Js.req(x), "source"));
            if (!ledger) rejected++;
            boolean denied = "denied".equals(Js.get(x, "outcome"));
            if (ledger && !denied) trusted.add(x);
            if (ledger && denied) refused.add(x);
        }
        List<Object> findings = new ArrayList<>();
        List<Object> base = Js.get(policy, "predicates") instanceof List ? Js.list(Js.get(policy, "predicates")) : new ArrayList<>();

        for (int i = 0; i < base.size(); i++) {
            Object p = base.get(i);
            boolean hit = false;
            for (Object a : trusted) if (matches(p, a)) { hit = true; break; }
            Object pv = Js.get(p, "verb");
            List<Object> verbs = pv instanceof String ? Js.arr(pv) : pv instanceof List ? Js.list(pv) : new ArrayList<>();
            if (!hit) {
                Object v = verbs.isEmpty() || verbs.get(0) == null ? "*" : verbs.get(0);
                Catalog.Spec s = resolveAction(cat, v.equals("*") ? "unknown.any" : (String) v);
                List<String> vj = new ArrayList<>();
                for (Object x : verbs) vj.add(String.valueOf(x));
                String joined = String.join(", ", vj);
                findings.add(Js.obj("kind", "unused-predicate", "predicate", Js.n(i), "verb", v, "detail", "no observed action used predicate " + i + " (" + (joined.isEmpty() ? "*" : joined) + ")",
                    "blastRadius", Js.n(s.blastRadius), "reversibility", s.reversibility, "rank", Js.n(s.blastRadius * revWeight(s.reversibility))));
                continue;
            }
            for (Object v : verbs) {
                if ("*".equals(v)) continue;
                boolean used = false;
                for (Object a : trusted) if (Js.strictEq(Js.get(a, "verb"), v) && matches(p, a)) { used = true; break; }
                if (!used) {
                    Catalog.Spec s = resolveAction(cat, (String) v);
                    findings.add(Js.obj("kind", "unused-verb", "predicate", Js.n(i), "verb", v, "detail", "verb " + v + " is granted by predicate " + i + " but never used",
                        "blastRadius", Js.n(s.blastRadius), "reversibility", s.reversibility, "rank", Js.n(s.blastRadius * revWeight(s.reversibility))));
                }
            }
            Object pw = Js.get(p, "where");
            if (pw instanceof List) for (Object c : (List<?>) pw) {
                Object f = Js.get(c, "field"), op = Js.get(c, "op");
                if (c instanceof Map && f instanceof String && ("lte".equals(op) || "lt".equals(op)) && Js.isNum(Js.get(c, "value")) && ((String) f).startsWith("action.params.")) {
                    String name = ((String) f).substring("action.params.".length());
                    List<Double> vals = new ArrayList<>();
                    for (Object a : trusted) if (matches(p, a)) { Object pv2 = paramOf(a, name); if (Js.isNum(pv2)) vals.add(Js.num(pv2)); }
                    double mx = Double.NEGATIVE_INFINITY;
                    for (double d : vals) mx = Math.max(mx, d);
                    double cv = Js.num(Js.get(c, "value"));
                    if (vals.size() >= minSamples && mx < cv / 2) {
                        Object v0 = verbs.isEmpty() ? null : verbs.get(0);
                        Catalog.Spec s = resolveAction(cat, Js.truthy(v0) || v0 != null ? (String) v0 : "unknown.any");
                        Map<String, Object> fd = Js.obj("kind", "unreached-cap", "predicate", Js.n(i));
                        if (Js.truthy(v0)) fd.put("verb", v0);
                        fd.put("detail", name + " <= " + Js.fmt(cv) + " but the largest observed value is " + Js.fmt(mx));
                        fd.put("blastRadius", Js.n(s.blastRadius));
                        fd.put("reversibility", s.reversibility);
                        fd.put("rank", Js.n(s.blastRadius * revWeight(s.reversibility)));
                        findings.add(fd);
                    }
                }
            }
        }
        // rank descending, then predicate ascending (stable)
        findings.sort((a, b) -> {
            double d = Js.num(Js.get(b, "rank")) - Js.num(Js.get(a, "rank"));
            if (d != 0 && !Double.isNaN(d)) return d < 0 ? -1 : 1;
            return Double.compare(Js.num(Js.get(a, "predicate")), Js.num(Js.get(b, "predicate")));
        });

        Map<String, Map<String, Object>> groups = new LinkedHashMap<>();
        for (Object a : refused) {
            String k = Js.get(a, "verb") + "\u0000" + Js.get(a, "resource");
            Map<String, Object> g = groups.get(k);
            if (g != null) g.put("denied_count", Js.n(Js.num(g.get("denied_count")) + 1));
            else {
                Map<String, Object> r = Js.obj("v", Js.n(1), "kind", "pca-access-request", "verb", Js.get(a, "verb"), "resource", Js.get(a, "resource"),
                    "example_params", Js.copy(Js.get(a, "params")), "denied_count", Js.n(1), "policy_digest", digest);
                if (Js.truthy(Js.get(o, "taskBinding"))) r.put("task_binding", Js.get(o, "taskBinding"));
                groups.put(k, r);
            }
        }
        List<Map<String, Object>> reqs = new ArrayList<>(groups.values());
        reqs.sort((a, b) -> {
            double d = Js.num(b.get("denied_count")) - Js.num(a.get("denied_count"));
            if (d != 0 && !Double.isNaN(d)) return d < 0 ? -1 : 1;
            return ((String) a.get("verb")).compareTo((String) b.get("verb")) < 0 ? -1 : 1;
        });

        Map<String, Object> res = Js.obj("used", Js.n(trusted.size()), "rejected", Js.n(rejected), "denied", Js.n(refused.size()), "coversObserved", false,
            "findings", findings, "accessRequests", new ArrayList<Object>(reqs));
        if (Js.truthy(Js.get(o, "taskBinding"))) res.put("taskBinding", Js.get(o, "taskBinding"));

        List<Object> caveats = new ArrayList<>(model.caveats);
        Object decay = Js.get(o, "decay");
        if (Js.truthy(decay)) caveats.add(Js.obj("type", "expires", "at", Js.n(Js.numOrNaN(decay, "nowSec") + Js.numOrNaN(decay, "expiresInSecs"))));
        for (boolean narrowResources : new boolean[] {true, false}) {
            Map<String, Object> proposal = Js.obj("predicates", build(base, trusted, narrowResources, margin, minSamples, enumLimit), "caveats", caveats, "vetoes", model.vetoes, "tighten", model.tighten);
            if (Js.list(proposal.get("predicates")).isEmpty()) {
                res.put("reason", "no ledger observation matches any predicate");
                return res;
            }
            Map<String, Object> proof = Analyzer.subsumes(policy, proposal);
            if (!Boolean.TRUE.equals(proof.get("subsumes")) || Boolean.TRUE.equals(proof.get("approximate"))) {
                res.put("reason", proof.containsKey("reason") ? proof.get("reason") : "the proposal could not be proven narrower than the original");
                continue;
            }
            res.remove("reason");
            res.put("proposal", proposal);
            boolean covers = true;
            for (Object a : trusted) {
                Map<String, Object> act = Js.obj("verb", Js.get(a, "verb"), "resource", Js.get(a, "resource"), "params", Js.copy(Js.get(a, "params")));
                if (!Analyzer.admitsConcrete(proposal, act)) { covers = false; break; }
            }
            res.put("coversObserved", covers);
            res.put("diff", Exposure.diffPolicies(policy, proposal, null));
            return res;
        }
        return res;
    }

    public static Map<String, Object> suggestNarrowing(Object policy, List<Object> observed, Map<String, Object> o) { return suggestNarrowing(policy, observed, o, null); }

    // ---- access requests ----

    private static byte[] requestMessage(Object r) {
        byte[] pre = ACCESS_REQUEST_SIG_DOMAIN.getBytes(StandardCharsets.UTF_8);
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(Pca.hashCanonical(r).getBytes(StandardCharsets.UTF_8));
            byte[] m = new byte[pre.length + d.length];
            System.arraycopy(pre, 0, m, 0, pre.length);
            System.arraycopy(d, 0, m, pre.length, d.length);
            return m;
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The agent's (or its holder's) signed ask: {request, signer, sig}. A request for a human to read; nothing here turns it into authority. */
    public static Map<String, Object> signAccessRequest(Map<String, Object> r, Keys.EdKey secret, String signerPublic) {
        return Js.obj("request", r, "signer", signerPublic, "sig", Keys.b64u(secret.sign(requestMessage(r))));
    }

    /** Is the signed request well formed and signed by the signer ({@code expectedSigner} null = any)? Never throws. */
    public static boolean verifyAccessRequest(Object s, String expectedSigner) {
        try {
            Object req = Js.get(s, "request");
            if (!(s instanceof Map) || !(req instanceof Map) || !"pca-access-request".equals(Js.get(req, "kind"))) return false;
            Object v = Js.get(req, "v");
            if (!Js.isNum(v) || Js.num(v) != 1) return false;
            if (expectedSigner != null && !expectedSigner.equals(Js.get(s, "signer"))) return false;
            Object sig = Js.get(s, "sig");
            Object signer = Js.get(s, "signer");
            if (!(sig instanceof String) || !(signer instanceof String)) return false;
            byte[] pk = Pca.decodeB64uStrict(signer, 32), sg = Pca.decodeB64uStrict(sig, 64);
            return pk != null && sg != null && EdStrict.verify(pk, requestMessage(req), sg);
        } catch (RuntimeException e) {
            return false;
        }
    }
}
