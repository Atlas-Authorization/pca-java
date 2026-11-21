package net.atlasauth.pca.actions;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.function.Predicate;
import net.atlasauth.pca.ActionRegistry;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;

/**
 * Building, chaining and signing action packs, and verifying an upgrade between two versions. The verify side of a single pack
 * ({@link ActionRegistry#verifyPack}, {@code packDigest}, {@code shardDigest}, {@code packShapeError}, {@code packDefs}) is in the core.
 */
public final class ActionPacks {
    private ActionPacks() {}

    public static final String PACK_SIG_DOMAIN = "atlas-pca/action-pack/v1\0";
    public static final String PACK_SHARD_KIND = "pca-action-pack-shard";
    /** Largest shard the builder writes by default. */
    public static final int DEFAULT_SHARD_DEFS = 512;
    /** Most defs an inline pack carries. */
    public static final int MAX_PACK_DEFS = 4096;

    /** Sign {@code body} under {@code domain} as the registry: {@code {alg, kid, value[, pq_value]}}. */
    public static Map<String, Object> signRegistryDoc(String domain, Object body, String kid, Keys.SuiteKey key) {
        byte[] dom = Json.utf8(domain), bd = Json.canonicalizeStrict(body).getBytes(StandardCharsets.UTF_8);
        byte[] msg = new byte[dom.length + bd.length];
        System.arraycopy(dom, 0, msg, 0, dom.length);
        System.arraycopy(bd, 0, msg, dom.length, bd.length);
        String[] parts = key.sign(msg);
        Map<String, Object> sig = J.obj("alg", key.alg, "kid", kid, "value", parts[0]);
        if (parts[1] != null) sig.put("pq_value", parts[1]);
        return sig;
    }

    private static int byVerb(Object a, Object b) { return ((String) J.get(a, "verb")).compareTo((String) J.get(b, "verb")); }

    /**
     * Shard names are the resource family (the first segment of {@code resource.type}) of the defs, split in order into chunks of {@code max}
     * (null = {@link #DEFAULT_SHARD_DEFS}). Returns a list of {@code {name, defs}}.
     */
    public static List<Object> shardDefs(List<?> defs, Object max) {
        double m = max == null ? DEFAULT_SHARD_DEFS : (J.isInt(max) ? J.num(max) : Double.NaN);
        if (Double.isNaN(m) || m < 1) throw new Actions.ActionKitError("bad_shard_size", "the shard size must be a positive integer");
        int mx = (int) Math.min(m, Integer.MAX_VALUE);
        TreeMap<String, List<Object>> fam = new TreeMap<>();
        for (Object d : defs) {
            String t = (String) J.get(J.get(d, "resource"), "type");
            int dot = t.indexOf('.');
            fam.computeIfAbsent(dot < 0 ? t : t.substring(0, dot), k -> new ArrayList<>()).add(d);
        }
        List<Object> out = new ArrayList<>();
        for (Map.Entry<String, List<Object>> e : fam.entrySet()) {
            List<Object> l = e.getValue();
            int n = 1;
            for (int i = 0; i < l.size(); i += mx, n++) {
                out.add(J.obj("name", l.size() > mx ? e.getKey() + "-" + n : e.getKey(), "defs", new ArrayList<>(l.subList(i, (int) Math.min((long) i + mx, l.size())))));
            }
        }
        return out;
    }

    private static String sortedUniqueDefsError(List<Object> defs) {
        for (int i = 0; i < defs.size(); i++) {
            String e = Actions.validateDef(defs.get(i));
            if (e != null) return "def " + i + ": " + e;
            if (i > 0 && byVerb(defs.get(i - 1), defs.get(i)) >= 0) return "defs must be sorted by verb and unique (at '" + J.get(defs.get(i), "verb") + "')";
        }
        return null;
    }

    /**
     * Build, chain and sign a pack. {@code a} holds {@code ns, version, stability, defs, source, kid} and optionally {@code prev: {pack, shards?}}
     * and {@code shard: true | {max?}}; {@code shardUri} names a shard's location (null = {@code shards/<name>.json}). Returns {@code {pack, shards}}.
     * Throws ActionKitError on any inconsistency.
     */
    public static Map<String, Object> buildPack(Map<String, Object> a, Keys.SuiteKey key, Actions.Registry reg, Predicate<Map<String, Object>> attestationVerified, Function<String, String> shardUri) {
        Actions.Registry r = reg == null ? Actions.CORE_REGISTRY : reg;
        List<Object> defs = new ArrayList<>(J.a(a.get("defs")));
        defs.sort(ActionPacks::byVerb);
        String de = sortedUniqueDefsError(defs);
        if (de != null) throw new Actions.ActionKitError("bad_pack", de);
        if (defs.isEmpty()) throw new Actions.ActionKitError("empty_pack", "a pack has at least one def");
        Map<String, Object> prev = a.get("prev") instanceof Map ? J.m(a.get("prev")) : null;
        List<Object> prevDefs = new ArrayList<>();
        if (prev != null) {
            Map<String, Object> pp = J.m(prev.get("pack"));
            prevDefs = ActionRegistry.packDefs(pp, prev.get("shards") instanceof Map ? J.m(prev.get("shards")) : null);
            if (!J.get(pp, "ns").equals(a.get("ns"))) throw new Actions.ActionKitError("bad_chain", "the previous pack is of another namespace");
            if (ActionRegistry.compareVersions((String) a.get("version"), (String) pp.get("version")) <= 0) throw new Actions.ActionKitError("bad_chain", "the version must increase");
        }
        List<Object> records = ActionEvolve.evolutionRecords((String) a.get("ns"), prevDefs, defs, r, attestationVerified);
        List<Object> evolution = ActionEvolve.signEvolution(records, (String) a.get("kid"), key);
        List<String> digests = new ArrayList<>();
        for (Object d : defs) digests.add(Actions.defDigest(J.m(d)));
        String root = Actions.packRoot(digests);
        boolean wantShards = a.containsKey("shard") && !Boolean.FALSE.equals(a.get("shard")) ? true : defs.size() > MAX_PACK_DEFS;
        Map<String, Object> shards = new LinkedHashMap<>();
        Object body = defs;
        if (wantShards) {
            Object opts = a.get("shard") instanceof Map ? a.get("shard") : new LinkedHashMap<String, Object>();
            List<Object> refs = new ArrayList<>();
            for (Object s0 : shardDefs(defs, J.get(opts, "max"))) {
                Map<String, Object> s = J.m(s0);
                String name = (String) s.get("name");
                Map<String, Object> doc = J.obj("v", J.n(1), "kind", PACK_SHARD_KIND, "ns", a.get("ns"), "version", a.get("version"), "name", name, "defs", s.get("defs"));
                shards.put(name, doc);
                refs.add(J.obj("name", name, "digest", ActionRegistry.shardDigest(doc), "uri", shardUri != null ? shardUri.apply(name) : "shards/" + name + ".json"));
            }
            body = J.obj("shards", refs);
        }
        Map<String, Object> unsigned = J.obj("v", J.n(1), "kind", "pca-action-pack", "ns", a.get("ns"), "version", a.get("version"), "stability", a.get("stability"),
            "traits_digest", Actions.traitsDigest(r), "roles_digest", Actions.tablesDigest(), "rules_digest", ActionRegistry.rulesDigest(),
            "root", root, "defs", body, "source", a.get("source"), "prev", prev != null ? ActionRegistry.packDigest(J.get(prev, "pack")) : null, "evolution", evolution);
        String pe = ActionRegistry.packShapeError(unsigned, false);
        if (pe != null) throw new Actions.ActionKitError("bad_pack", pe);
        Map<String, Object> pack = new LinkedHashMap<>(unsigned);
        pack.put("sig", signRegistryDoc(PACK_SIG_DOMAIN, unsigned, (String) a.get("kid"), key));
        return J.obj("pack", pack, "shards", shards);
    }

    /**
     * Verify {@code next} as the successor of {@code prev}: both verify, same namespace, {@code next.prev} is {@code prev}'s digest, the version
     * increases, and the signed evolution is EXACTLY the computed change. Returns {@code {ok}} or {@code {ok:false, reason}}. Shard maps may be null.
     * The vocabulary is the core trait registry (shortcut: a custom registry is not supported for verification here).
     */
    public static Map<String, Object> verifyUpgrade(Map<String, Object> prev, Map<String, Object> next, Object keys, Map<String, Object> prevShards, Map<String, Object> shards, Predicate<Map<String, Object>> attestationVerified) {
        Map<String, Object> a = ActionRegistry.verifyPack(prev, keys, prevShards);
        if (!Boolean.TRUE.equals(a.get("ok"))) return J.obj("ok", Boolean.FALSE, "reason", "previous pack: " + a.get("reason"));
        Map<String, Object> b = ActionRegistry.verifyPack(next, keys, shards);
        if (!Boolean.TRUE.equals(b.get("ok"))) return J.obj("ok", Boolean.FALSE, "reason", "pack: " + b.get("reason"));
        if (!next.get("ns").equals(prev.get("ns"))) return J.obj("ok", Boolean.FALSE, "reason", "the packs are of different namespaces");
        if (!a.get("digest").equals(next.get("prev"))) return J.obj("ok", Boolean.FALSE, "reason", "chain gap: prev does not name the previous pack");
        if (ActionRegistry.compareVersions((String) next.get("version"), (String) prev.get("version")) <= 0) return J.obj("ok", Boolean.FALSE, "reason", "the version does not increase");
        String ee = ActionEvolve.evolutionError((String) next.get("ns"), J.a(a.get("defs")), J.a(b.get("defs")), J.a(next.get("evolution")), J.a(keys), Actions.CORE_REGISTRY, attestationVerified);
        return ee == null ? J.obj("ok", Boolean.TRUE) : J.obj("ok", Boolean.FALSE, "reason", ee);
    }
}
