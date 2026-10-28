package net.atlasauth.pca;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Action-kit registry layer (native port): signed evolution records, principal re-approvals, the grant pin decision, signed packs (with shards),
 * the rollback tracker and rule 22 over a whole v2 document. Natives verify signatures, digests and pins; they do not recompute the semantic
 * diff. Pure and total: malformed input is a refusal.
 */
public final class ActionRegistry {
    private ActionRegistry() {}

    static final String ACTION_PACK_KIND = "pca-action-pack";
    static final String EVOLUTION_RECORD_KIND = "pca-evolution-record";
    static final String REAPPROVAL_KIND = "pca-reapproval";
    static final String EVOLUTION_DOMAIN = "atlas-pca/action-evolution/v1\0";
    static final String EVOLUTION_DIFF_DOMAIN = "atlas-pca/action-evolution-diff/v1";
    static final String REAPPROVAL_DOMAIN = "atlas-pca/action-reapproval/v1\0";
    static final int MAX_EVOLUTION_STEPS = 32;
    static final String PACK_SIG_DOMAIN = "atlas-pca/action-pack/v1\0";
    static final String PACK_REF_DOMAIN = "atlas-pca/action-pack-ref/v1";
    static final String PACK_SHARD_DOMAIN = "atlas-pca/action-pack-shard/v1";
    static final String RULES_DIGEST_DOMAIN = "atlas-pca/action-rules/v1";
    static final String PACK_SHARD_KIND = "pca-action-pack-shard";
    static final List<String> STABILITIES = List.of("draft", "beta", "stable");
    static final List<String> EVOLUTION_CLASSES = List.of("equal", "narrow", "widen", "incomparable", "added", "removed");
    static final int MAX_EVOLUTION_RECORDS = 65536;

    private static final Pattern B64U_43 = Pattern.compile("[A-Za-z0-9_-]{43}");
    private static final Pattern NS_RE = Pattern.compile("[a-z0-9_]+(?:\\.[a-z0-9_]+){0,5}");
    private static final Pattern VERB_RE = Pattern.compile("[a-z0-9_]+(?:\\.[a-z0-9_]+){1,5}");
    private static final Pattern SEMVER_RE = Pattern.compile("(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})");
    private static final Pattern SHARD_NAME_RE = Pattern.compile("[a-z0-9_]+(?:[.-][a-z0-9_]+){0,7}");

    @SuppressWarnings("unchecked") private static Map<String, Object> M(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> A(Object o) { return (List<Object>) o; }
    private static boolean isMap(Object o) { return o instanceof Map; }
    private static boolean isStrT(Object o) { return o instanceof String; }
    private static boolean sha(Object x) { return x instanceof String && B64U_43.matcher((String) x).matches(); }
    private static boolean isOne(Object o) { Double d = IntentJs.num(o); return d != null && d == 1.0; }
    private static Json.Num n(long v) { return IntentJs.ofLong(v); }
    private static boolean inS(Object x, Collection<String> xs) { return x instanceof String && xs.contains(x); }

    private static String closed(Map<String, Object> o, String... allowed) {
        List<String> al = Arrays.asList(allowed);
        for (String k : o.keySet()) if (!al.contains(k)) return "unknown member '" + k + "'";
        return null;
    }
    private static boolean tier(Object x) { return IntentJs.isInt(x) && IntentJs.lng(x) >= 0 && IntentJs.lng(x) <= 3; }
    private static Map<String, Object> without(Map<String, Object> m, String k) { Map<String, Object> b = new LinkedHashMap<>(m); b.remove(k); return b; }
    private static Map<String, Object> mapOf(Object... kv) { Map<String, Object> m = new LinkedHashMap<>(); for (int i = 0; i < kv.length; i += 2) m.put((String) kv[i], kv[i + 1]); return m; }

    // ---- evolution records ----------------------------------------------------------------------------------------------------

    public static String evolutionRecordError(Object xO, boolean signed) {
        if (!isMap(xO)) return "evolution record must be an object";
        Map<String, Object> x = M(xO);
        String u = signed ? closed(x, "v", "kind", "ns", "verb", "from", "to", "class", "reasons", "sig") : closed(x, "v", "kind", "ns", "verb", "from", "to", "class", "reasons");
        if (u != null) return "evolution record: " + u;
        if (!isOne(x.get("v")) || !EVOLUTION_RECORD_KIND.equals(x.get("kind"))) return "evolution record: bad v/kind";
        if (!(x.get("ns") instanceof String) || !NS_RE.matcher((String) x.get("ns")).matches()) return "evolution record: bad ns";
        if (!(x.get("verb") instanceof String) || !VERB_RE.matcher((String) x.get("verb")).matches()) return "evolution record: bad verb";
        if (x.get("from") != null && !sha(x.get("from"))) return "evolution record: bad from";
        if (x.get("to") != null && !sha(x.get("to"))) return "evolution record: bad to";
        Object c = x.get("class");
        if (!inS(c, EVOLUTION_CLASSES)) return "evolution record: bad class";
        if ("added".equals(c) != (x.get("from") == null) || "removed".equals(c) != (x.get("to") == null)) return "evolution record: endpoints do not match the class";
        Object r = x.get("reasons");
        if (!(r instanceof List) || ((List<?>) r).size() > 64) return "evolution record: bad reasons";
        for (Object e : (List<?>) r) if (!(e instanceof String) || ((String) e).length() > 512) return "evolution record: bad reasons";
        if (signed) {
            Object so = x.get("sig");
            if (!isMap(so) || closed(M(so), "alg", "kid", "value", "pq_value") != null) return "evolution record: bad sig";
            Map<String, Object> s = M(so);
            if (!(s.get("kid") instanceof String) || ((String) s.get("kid")).isEmpty() || ((String) s.get("kid")).length() > 128 || !isStrT(s.get("value")) || !isStrT(s.get("alg"))) return "evolution record: bad sig";
            if (s.containsKey("pq_value") && !isStrT(s.get("pq_value"))) return "evolution record: bad sig";
        }
        try { IntentJs.canonBytes(without(x, "sig")); } catch (RuntimeException e) { return "evolution record: " + e.getMessage(); }
        return null;
    }

    /** Throws when a member is absent or out of profile (the reference throws). */
    public static String evolutionDiffDigest(Map<String, Object> r) {
        for (String k : new String[] {"ns", "verb", "from", "to", "class", "reasons"}) if (!r.containsKey(k)) throw new IllegalArgumentException("record member missing: " + k);
        return Pca.hashCanonical(mapOf("d", EVOLUTION_DIFF_DOMAIN, "ns", r.get("ns"), "verb", r.get("verb"), "from", r.get("from"), "to", r.get("to"), "class", r.get("class"), "reasons", r.get("reasons")));
    }

    /** Null = valid; else the reason. */
    public static String verifyRegistrySig(String domain, Object body, Map<String, Object> sig, Object keys) {
        try {
            if (!(keys instanceof List)) return "the registry keys must be an array";
            Map<String, Object> key = null;
            for (Object k : (List<?>) keys) if (isMap(k) && M(k).get("kid") != null && M(k).get("kid").equals(sig.get("kid"))) { key = M(k); break; }
            if (key == null) return "no registry key with kid '" + sig.get("kid") + "'";
            if (key.containsKey("pq_pk") && !(key.get("pq_pk") instanceof String)) return "the registry key pq_pk must be a string";
            if (Pca.decodeB64uStrict(key.get("pk"), 32) == null) return "registry key pk is not canonical base64url (32 bytes)";
            String ka = IntentJs.suiteOf(key);
            if (ka == null || !ka.equals(IntentJs.suiteOf(sig))) return "sig.alg does not match the pinned key suite";
            String pk = (String) key.get("pk");
            Map<String, Object> pin = key.containsKey("pq_pk") ? IntentJs.pin(pk, key.get("pq_pk")) : null;
            if (!IntentJs.verifyPinnedSuite(ka, true, pk, key.get("pq_pk"), IntentJs.message(domain, body), sig.get("value"), sig.get("pq_value"), pin)) return "signature invalid";
            return null;
        } catch (RuntimeException e) {
            return "verification error: " + e.getMessage();
        }
    }

    /** Null = valid. */
    public static String verifyEvolutionRecord(Object rec, Object keys) {
        String bad = evolutionRecordError(rec, true);
        if (bad != null) return bad;
        return verifyRegistrySig(EVOLUTION_DOMAIN, without(M(rec), "sig"), M(M(rec).get("sig")), keys);
    }

    public static boolean reapprovalValid(Object rO, Object grantId, Object issuer, Object verb, Object diff) {
        try {
            if (!isMap(rO) || closed(M(rO), "v", "kind", "grant", "verb", "diff", "sig") != null) return false;
            Map<String, Object> r = M(rO);
            if (!isOne(r.get("v")) || !REAPPROVAL_KIND.equals(r.get("kind")) || !Objects.equals(r.get("grant"), grantId) || !Objects.equals(r.get("verb"), verb) || !Objects.equals(r.get("diff"), diff)) return false;
            if (!isMap(r.get("sig"))) return false;
            Map<String, Object> s = M(r.get("sig"));
            if (closed(s, "alg", "value") != null || !"ed25519".equals(s.get("alg")) || !isStrT(s.get("value"))) return false;
            return IntentJs.verifyPinnedSuite("ed25519", true, (String) issuer, null, IntentJs.message(REAPPROVAL_DOMAIN, without(r, "sig")), s.get("value"), null, null);
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ---- the pin ----------------------------------------------------------------------------------------------------------------

    public static String actionPinError(Object xO) {
        if (!isMap(xO)) return "actions must be an object";
        Map<String, Object> x = M(xO);
        String u = closed(x, "pack", "defs", "on_new_action", "max_esc", "preauth_esc", "caveats");
        if (u != null) return "actions: " + u;
        if (!isMap(x.get("pack")) || closed(M(x.get("pack")), "ns", "root") != null) return "actions.pack must be {ns, root}";
        Map<String, Object> p = M(x.get("pack"));
        if (!(p.get("ns") instanceof String) || !NS_RE.matcher((String) p.get("ns")).matches()) return "actions.pack.ns is not a namespace";
        if (!sha(p.get("root"))) return "actions.pack.root must be a base64url digest";
        if (!inS(x.get("on_new_action"), List.of("deny", "escalate"))) return "actions.on_new_action must be 'deny' or 'escalate'";
        if (x.containsKey("max_esc") && !tier(x.get("max_esc"))) return "actions.max_esc must be an integer tier 0..3";
        if (x.containsKey("preauth_esc") && !tier(x.get("preauth_esc"))) return "actions.preauth_esc must be an integer tier 0..3";
        if (tier(x.get("max_esc")) && tier(x.get("preauth_esc")) && IntentJs.lng(x.get("preauth_esc")) > IntentJs.lng(x.get("max_esc"))) return "actions.preauth_esc exceeds actions.max_esc";
        if (x.containsKey("caveats")) {
            Object c = x.get("caveats");
            if (!(c instanceof List)) return "actions.caveats must be distinct caveat kinds";
            for (Object k : (List<?>) c) if (!inS(k, Actions.CAVEAT_KINDS)) return "actions.caveats must be distinct caveat kinds";
            if (new HashSet<Object>((List<?>) c).size() != ((List<?>) c).size()) return "actions.caveats must be distinct caveat kinds";
        }
        if (x.containsKey("defs")) {
            if (!isMap(x.get("defs"))) return "actions.defs must be an object";
            for (Map.Entry<String, Object> e : M(x.get("defs")).entrySet()) {
                if (!VERB_RE.matcher(e.getKey()).matches()) return "actions.defs: '" + e.getKey() + "' is not a verb";
                if (!sha(e.getValue())) return "actions.defs." + e.getKey() + " must be a base64url digest";
            }
        }
        return null;
    }

    private static Map<String, Object> deny(String code, String reason, boolean escalate, String needs) {
        Map<String, Object> m = mapOf("ok", Boolean.FALSE, "code", code, "escalate", escalate, "reason", reason);
        if (needs != null) m.put("needs_reapproval", needs);
        return m;
    }

    private static Map<String, Object> search(Map<String, List<String[]>> edges, String pinned, String presented, boolean usableOnly) {
        Map<String, String[]> parent = new LinkedHashMap<>();
        Set<String> seen = new HashSet<>(List.of(pinned));
        List<String> frontier = new ArrayList<>(List.of(pinned));
        for (int step = 0; step < MAX_EVOLUTION_STEPS && !frontier.isEmpty() && !parent.containsKey(presented); step++) {
            List<String> next = new ArrayList<>();
            for (String f : frontier) for (String[] e : edges.getOrDefault(f, List.of())) {
                if (seen.contains(e[0]) || (usableOnly && e[1] != null)) continue;
                seen.add(e[0]);
                parent.put(e[0], new String[] {f, e[1]});
                next.add(e[0]);
            }
            frontier = next;
        }
        return new LinkedHashMap<String, Object>(parent);
    }

    /** input: pin, doc, verb, records, keys, reapprovals, grant{id, issuer}. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> decidePin(Map<String, Object> i) {
        try {
            String pe = actionPinError(i.get("pin"));
            if (pe != null) return deny("bad_pin", pe, false, null);
            Map<String, Object> pin = M(i.get("pin")), doc = M(i.get("doc")), packPin = M(pin.get("pack"));
            String verb = (String) i.get("verb");
            Map<String, Object> v = null;
            if (doc.get("verbs") instanceof List) for (Object x : (List<?>) doc.get("verbs")) if (isMap(x) && verb.equals(M(x).get("verb"))) { v = M(x); break; }
            if (v == null) return deny("unknown_verb", "the accepted schema does not declare '" + verb + "'", false, null);
            Object pk = doc.get("pack");
            if (!isMap(pk) || !Objects.equals(M(pk).get("ns"), packPin.get("ns"))) return deny("pack_mismatch", "the schema does not come from the pinned pack '" + packPin.get("ns") + "'", false, null);
            if (!pin.containsKey("defs")) {
                if (Objects.equals(M(pk).get("root"), packPin.get("root"))) return mapOf("ok", Boolean.TRUE, "via", "pack");
                return deny("pack_mismatch", "the pack root differs from the pinned root (the grant pins the pack as a whole)", false, null);
            }
            Map<String, Object> defs = M(pin.get("defs"));
            if (!defs.containsKey(verb)) return deny("new_action", "the grant does not name '" + verb + "' (on_new_action: " + pin.get("on_new_action") + ")", "escalate".equals(pin.get("on_new_action")), null);
            String pinned = (String) defs.get(verb);
            Object presentedO = v.get("def");
            if (!(presentedO instanceof String)) return deny("def_changed", "the schema verb carries no definition digest", false, null);
            String presented = (String) presentedO;
            if (presented.equals(pinned)) return mapOf("ok", Boolean.TRUE, "via", "exact");
            Map<String, List<String[]>> edges = new LinkedHashMap<>();
            Object keys = i.get("keys") == null ? new ArrayList<>() : i.get("keys");
            Map<String, Object> grant = M(i.get("grant"));
            List<Object> reapprovals = i.get("reapprovals") instanceof List ? A(i.get("reapprovals")) : List.of();
            if (i.get("records") instanceof List) for (Object ro : (List<?>) i.get("records")) {
                if (verifyEvolutionRecord(ro, keys) != null) continue;
                Map<String, Object> r = M(ro);
                if (!r.get("ns").equals(packPin.get("ns")) || !r.get("verb").equals(verb) || r.get("from") == null || r.get("to") == null) continue;
                String diff = evolutionDiffDigest(r);
                boolean free = "equal".equals(r.get("class")) || "narrow".equals(r.get("class"));
                boolean approved = free;
                if (!approved) for (Object a : reapprovals) if (reapprovalValid(a, grant.get("id"), grant.get("issuer"), verb, diff)) { approved = true; break; }
                edges.computeIfAbsent((String) r.get("from"), k -> new ArrayList<>()).add(new String[] {(String) r.get("to"), approved ? null : diff});
            }
            if (search(edges, pinned, presented, true).containsKey(presented)) return mapOf("ok", Boolean.TRUE, "via", "chain");
            Map<String, Object> all = search(edges, pinned, presented, false);
            if (all.containsKey(presented)) {
                String first = null;
                String cur = presented;
                while (!cur.equals(pinned)) {
                    String[] p = (String[]) (Object) all.get(cur);
                    if (p[1] != null) first = p[1];
                    cur = p[0];
                }
                return deny("def_changed", "the definition widened (or changed incomparably) since the grant pinned it: the principal must re-approve", false, first);
            }
            return deny("def_changed", "the definition differs from the pinned digest and no signed evolution record chains to it", false, null);
        } catch (RuntimeException e) {
            return deny("bad_pin", "pin evaluation error (fail closed): " + e.getMessage(), false, null);
        }
    }

    // ---- signed packs ----------------------------------------------------------------------------------------------------------

    public static int compareVersions(String a, String b) {
        java.util.regex.Matcher pa = SEMVER_RE.matcher(a), pb = SEMVER_RE.matcher(b);
        if (!pa.matches() || !pb.matches()) throw new Actions.ActionKitError("bad_version", "'" + (!pa.matches() ? a : b) + "' is not MAJOR.MINOR.PATCH");
        for (int k = 1; k <= 3; k++) {
            int d = Integer.compare(Integer.parseInt(pa.group(k)), Integer.parseInt(pb.group(k)));
            if (d != 0) return d;
        }
        return 0;
    }

    public static String rulesDigest() {
        return Pca.hashCanonical(mapOf("d", RULES_DIGEST_DOMAIN, "prules", new ArrayList<Object>(Actions.PARAM_RULE_IDS), "caveats", new ArrayList<Object>(Actions.CAVEAT_KINDS), "context", new ArrayList<Object>(Actions.CONTEXT_KEYS)));
    }
    public static String packDigest(Object p) { return Pca.hashCanonical(mapOf("d", PACK_REF_DOMAIN, "p", p)); }
    public static String shardDigest(Object s) { return Pca.hashCanonical(mapOf("d", PACK_SHARD_DOMAIN, "s", s)); }

    private static String sortedUniqueDefsError(List<Object> defs) {
        for (int i = 0; i < defs.size(); i++) {
            String e = Actions.validateDef(defs.get(i));
            if (e != null) return "def " + i + ": " + e;
            if (i > 0 && !(((String) M(defs.get(i - 1)).get("verb")).compareTo((String) M(defs.get(i)).get("verb")) < 0)) return "defs must be sorted by verb and unique (at '" + M(defs.get(i)).get("verb") + "')";
        }
        return null;
    }

    public static String packShapeError(Object xO, boolean signed) {
        try {
            if (!isMap(xO)) return "pack must be an object";
            Map<String, Object> x = M(xO);
            String e = signed ? closed(x, "v", "kind", "ns", "version", "stability", "traits_digest", "roles_digest", "rules_digest", "root", "defs", "source", "prev", "evolution", "sig")
                : closed(x, "v", "kind", "ns", "version", "stability", "traits_digest", "roles_digest", "rules_digest", "root", "defs", "source", "prev", "evolution");
            if (e != null) return "pack: " + e;
            if (!isOne(x.get("v")) || !ACTION_PACK_KIND.equals(x.get("kind"))) return "pack: bad v/kind";
            if (!(x.get("ns") instanceof String) || !NS_RE.matcher((String) x.get("ns")).matches()) return "pack: bad ns";
            if (!(x.get("version") instanceof String) || !SEMVER_RE.matcher((String) x.get("version")).matches()) return "pack: version must be MAJOR.MINOR.PATCH";
            if (!inS(x.get("stability"), STABILITIES)) return "pack: bad stability";
            for (String k : new String[] {"traits_digest", "roles_digest", "rules_digest", "root"}) if (!sha(x.get(k))) return "pack: " + k + " must be a base64url digest";
            if (x.get("prev") != null && !sha(x.get("prev"))) return "pack: bad prev";
            if (!isMap(x.get("source")) || closed(M(x.get("source")), "kind", "uri", "spec_digest", "licence", "licence_notes") != null) return "pack: source must be {kind, uri, spec_digest, licence, licence_notes}";
            Map<String, Object> s = M(x.get("source"));
            for (String k : new String[] {"kind", "uri", "spec_digest", "licence", "licence_notes"}) {
                Object v = s.get(k);
                if (!(v instanceof String) || (!k.equals("licence_notes") && ((String) v).isEmpty()) || ((String) v).length() > 2048) return "pack: source." + k + " is not a string of 1..2048 characters";
            }
            Object d = x.get("defs");
            if (d instanceof List) {
                if (((List<?>) d).isEmpty() || ((List<?>) d).size() > 4096) return "pack: inline defs must number 1..4096 (larger packs are sharded)";
                String de = sortedUniqueDefsError(A(d));
                if (de != null) return "pack: " + de;
            } else {
                if (!isMap(d) || closed(M(d), "shards") != null || !(M(d).get("shards") instanceof List) || ((List<?>) M(d).get("shards")).isEmpty() || ((List<?>) M(d).get("shards")).size() > 4096) return "pack: defs must be a list of defs or {shards}";
                Set<String> names = new HashSet<>();
                for (Object ro : (List<?>) M(d).get("shards")) {
                    if (!isMap(ro) || closed(M(ro), "name", "digest", "uri") != null) return "pack: bad shard ref";
                    Map<String, Object> r = M(ro);
                    if (!(r.get("name") instanceof String) || !SHARD_NAME_RE.matcher((String) r.get("name")).matches() || names.contains(r.get("name"))) return "pack: shard names must be distinct simple names";
                    names.add((String) r.get("name"));
                    if (!sha(r.get("digest")) || !(r.get("uri") instanceof String) || ((String) r.get("uri")).isEmpty() || ((String) r.get("uri")).length() > 2048) return "pack: bad shard digest or uri";
                }
            }
            Object ev = x.get("evolution");
            if (!(ev instanceof List) || ((List<?>) ev).size() > MAX_EVOLUTION_RECORDS) return "pack: evolution must be a list of records";
            for (Object r : (List<?>) ev) {
                String re = evolutionRecordError(r, true);
                if (re != null) return "pack: " + re;
            }
            if (signed) {
                Object g = x.get("sig");
                if (!isMap(g) || closed(M(g), "alg", "kid", "value", "pq_value") != null || !isStrT(M(g).get("kid")) || !isStrT(M(g).get("value")) || !isStrT(M(g).get("alg"))) return "pack: bad sig";
            }
            Pca.hashCanonical(without(x, "sig"));
            return null;
        } catch (RuntimeException err) {
            return "pack: " + err.getMessage();
        }
    }

    public static List<Object> packDefs(Map<String, Object> pack, Map<String, Object> shards) {
        if (pack.get("defs") instanceof List) return new ArrayList<>(A(pack.get("defs")));
        List<Object> all = new ArrayList<>();
        for (Object ro : A(M(pack.get("defs")).get("shards"))) {
            Map<String, Object> r = M(ro);
            Object s = shards == null ? null : shards.get(r.get("name"));
            if (s == null) throw new Actions.ActionKitError("missing_shard", "shard '" + r.get("name") + "' was not supplied");
            if (!shardDigest(s).equals(r.get("digest"))) throw new Actions.ActionKitError("shard_digest_mismatch", "shard '" + r.get("name") + "' does not match its digest");
            Map<String, Object> sm = M(s);
            if (!isOne(sm.get("v")) || !PACK_SHARD_KIND.equals(sm.get("kind")) || !Objects.equals(sm.get("ns"), pack.get("ns")) || !Objects.equals(sm.get("version"), pack.get("version")) || !Objects.equals(sm.get("name"), r.get("name")) || !(sm.get("defs") instanceof List))
                throw new Actions.ActionKitError("bad_shard", "shard '" + r.get("name") + "' is not a shard of this pack");
            all.addAll(A(sm.get("defs")));
        }
        all.sort((a, b) -> ((String) M(a).get("verb")).compareTo((String) M(b).get("verb")));
        return all;
    }

    /** Result: {ok:true, defs:List, digest} or {ok:false, reason}. */
    public static Map<String, Object> verifyPack(Object packO, Object keys, Map<String, Object> shards) {
        try {
            String se = packShapeError(packO, true);
            if (se != null) return mapOf("ok", Boolean.FALSE, "reason", se);
            Map<String, Object> pack = M(packO);
            String v = verifyRegistrySig(PACK_SIG_DOMAIN, without(pack, "sig"), M(pack.get("sig")), keys);
            if (v != null) return mapOf("ok", Boolean.FALSE, "reason", "pack signature: " + v);
            if (!pack.get("traits_digest").equals(Actions.traitsDigest(Actions.CORE_REGISTRY))) return mapOf("ok", Boolean.FALSE, "reason", "traits_digest does not match the trait registry");
            if (!pack.get("roles_digest").equals(Actions.tablesDigest())) return mapOf("ok", Boolean.FALSE, "reason", "roles_digest does not match the vocabulary tables");
            if (!pack.get("rules_digest").equals(rulesDigest())) return mapOf("ok", Boolean.FALSE, "reason", "rules_digest does not match the rule tables");
            List<Object> defs;
            try { defs = packDefs(pack, shards); } catch (Actions.ActionKitError e) { return mapOf("ok", Boolean.FALSE, "reason", e.getMessage()); }
            String de = sortedUniqueDefsError(defs);
            if (de != null) return mapOf("ok", Boolean.FALSE, "reason", de);
            if (defs.isEmpty() || defs.size() > 1_000_000) return mapOf("ok", Boolean.FALSE, "reason", "the pack lists no defs or too many");
            List<String> digests = new ArrayList<>();
            for (Object d : defs) digests.add(Actions.defDigest(M(d)));
            if (!Actions.packRoot(digests).equals(pack.get("root"))) return mapOf("ok", Boolean.FALSE, "reason", "the Merkle root does not match the defs");
            Set<String> have = new HashSet<>(digests);
            for (Object ro : A(pack.get("evolution"))) {
                Map<String, Object> r = M(ro);
                String rv = verifyEvolutionRecord(r, keys);
                if (rv != null) return mapOf("ok", Boolean.FALSE, "reason", "evolution record: " + rv);
                if (!r.get("ns").equals(pack.get("ns"))) return mapOf("ok", Boolean.FALSE, "reason", "evolution record of another namespace");
                if (r.get("to") != null && !have.contains(r.get("to"))) return mapOf("ok", Boolean.FALSE, "reason", "evolution record for '" + r.get("verb") + "' names a definition that is not in the pack");
            }
            return mapOf("ok", Boolean.TRUE, "defs", defs, "digest", packDigest(pack));
        } catch (RuntimeException e) {
            return mapOf("ok", Boolean.FALSE, "reason", "pack verification error: " + e.getMessage());
        }
    }

    public static boolean verifyPackProof(Object root, Object proof, String digest) {
        return root instanceof String && isMap(proof) && Pca.verifyInclusion((String) root, M(proof), Actions.packLeaf(digest));
    }

    /** Refuses rollback, fork and chain gap. The semantic diff of an upgrade is not recomputed natively. */
    public static final class PackTracker {
        private final Object keys;
        private final Map<String, String[]> seen = new LinkedHashMap<>();
        public PackTracker(Object keys) { this.keys = keys; }

        public Map<String, Object> accept(Object packO, Map<String, Object> shards) {
            Map<String, Object> v = verifyPack(packO, keys, shards);
            if (!Boolean.TRUE.equals(v.get("ok"))) return mapOf("ok", Boolean.FALSE, "code", "bad_pack", "reason", v.get("reason"));
            Map<String, Object> pack = M(packO);
            String ns = (String) pack.get("ns"), version = (String) pack.get("version"), digest = (String) v.get("digest");
            String[] cur = seen.get(ns);
            if (cur == null) { seen.put(ns, new String[] {version, digest}); return mapOf("ok", Boolean.TRUE, "status", "first"); }
            if (cur[1].equals(digest)) return mapOf("ok", Boolean.TRUE, "status", "same");
            int c = compareVersions(version, cur[0]);
            if (c < 0) return mapOf("ok", Boolean.FALSE, "code", "rollback", "reason", "older than the accepted version");
            if (c == 0) return mapOf("ok", Boolean.FALSE, "code", "fork", "reason", "two different packs claim one version");
            if (!Objects.equals(pack.get("prev"), cur[1])) return mapOf("ok", Boolean.FALSE, "code", "chain_gap", "reason", "prev does not name the accepted pack");
            seen.put(ns, new String[] {version, digest});
            return mapOf("ok", Boolean.TRUE, "status", "upgrade");
        }
    }

    // ---- rule 22 over a whole document ------------------------------------------------------------------------------------------

    private static final List<String> CODES = List.of("schema_floor_forged", "schema_traits_forged", "unknown_trait", "traits_digest_mismatch", "bad_registry");

    /** null = ok; else the stable code. */
    public static String rule22Integrity(Map<String, Object> doc) { return rule22Integrity(doc, null); }

    /** As above, with the verifier's pinned reviewer keys {@code {keys, traits_digests?}} (absent: nothing is confirmed, so every verb must carry every trait). */
    public static String rule22Integrity(Map<String, Object> doc, Map<String, Object> pins) {
        String e = Actions.schemaFloorError(doc, pins);
        if (e == null) return null;
        for (String c : CODES) if (e.contains(c)) return c;
        return "unknown";
    }

    public static String rule22Decide(Map<String, Object> doc, String verb, Map<String, Object> grant, List<Object> context) {
        try {
            Map<String, Object> v = null;
            for (Object x : A(doc.get("verbs"))) if (isMap(x) && verb.equals(M(x).get("verb"))) { v = M(x); break; }
            if (v == null || Actions.profileError(v.get("floors")) != null) return "deny";
            List<Object> kinds = new ArrayList<>(), ctx = new ArrayList<>();
            for (Object k : A(grant.get("caveats"))) if (inS(k, Actions.CAVEAT_KINDS)) kinds.add(k);
            for (Object k : context) if (Actions.isContextKey(k)) ctx.add(k);
            Map<String, Object> g = mapOf("caveats", kinds, "max_esc", grant.get("max_esc"), "preauth_esc", grant.get("preauth_esc"));
            return Actions.floorDecision(g, mapOf("context", ctx), Actions.Profile.fromMap(v.get("floors")));
        } catch (RuntimeException e) {
            return "deny";
        }
    }
}
