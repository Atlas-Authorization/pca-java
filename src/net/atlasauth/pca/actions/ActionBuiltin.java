package net.atlasauth.pca.actions;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import net.atlasauth.pca.Actions;
import net.atlasauth.pca.Json;

/**
 * The built-in connector actions and the domain vocabularies as hand-reviewed action definitions (the {@code core} seed of the catalog packs), the legacy
 * tables they were reconciled from, and the derivation of a domain's ontology terms. The data is the reference's, embedded verbatim. Every call returns a
 * fresh tree the caller may modify. The built-ins are UNCONFIRMED until a release attestation is attached ({@link #releasedBuiltinDefs}); this build carries
 * none, so they stay maximally dangerous when read here (the release signing step is {@link #signBuiltins}, with the reviewer key supplied by the caller).
 */
public final class ActionBuiltin {
    private ActionBuiltin() {}

    public static final List<String> DOMAIN_NAMES = List.of("payments", "email", "code_repos", "data_access", "calendar_travel");

    private static Object parse(String[] parts) { return Json.parse(ActionData.join(parts)); }

    /** The 21 built-in connector action definitions. */
    public static List<Object> builtinDefs() { return J.a(parse(ActionData.BUILTIN_DEFS)); }

    /** The defs the domain vocabularies add to the built-in pack. */
    public static List<Object> domainDefs() { return J.a(parse(ActionData.DOMAIN_DEFS)); }

    /** Every def the domain vocabularies and the connector catalog are built from: one pack, one alias namespace. */
    public static List<Object> corePackDefs() {
        List<Object> all = builtinDefs();
        all.addAll(domainDefs());
        return all;
    }

    /** What the old catalog said per built-in verb: {@code verb -> {reversibility, blastRadius}}. */
    public static Map<String, Object> legacyCatalog() { return J.m(parse(ActionData.LEGACY_CATALOG)); }

    /** What the old payments ontology said (effect class), for the verbs that exist in both models. */
    public static Map<String, Object> legacyOntologyEffect() { return J.m(parse(ActionData.LEGACY_ONTOLOGY_EFFECT)); }

    /** Every place the old models disagreed and how it was settled: a list of {@code {verb, field, was, now, reason}}. */
    public static List<Object> resolutions() { return J.a(parse(ActionData.RESOLUTIONS)); }

    /** The NL bindings per domain: {@code domain -> [{id, verb, resourceType, params, ccys?}]}. */
    public static Map<String, Object> domainVerbBindings() { return J.m(parse(ActionData.DOMAIN_VERBS)); }

    private static Map<String, Object> defOf(List<Object> pack, String verb) {
        for (Object d : pack) if (verb.equals(J.get(d, "verb"))) return J.m(d);
        throw new IllegalStateException("domain binding names unknown def '" + verb + "'");
    }

    private static List<Object> bindings(String domain) {
        Object b = domainVerbBindings().get(domain);
        if (b == null) throw new IllegalStateException("unknown domain '" + domain + "'");
        return J.a(b);
    }

    /**
     * The {@code verbs} and {@code aliases} of a domain ontology, derived from the defs (effect class derived, parameter kinds from the def parameters,
     * a money parameter listing the domain's accepted currencies when the binding names them). Returns {@code {verbs, aliases}}.
     */
    public static Map<String, Object> domainVerbs(String domain, Actions.Registry reg) {
        List<Object> pack = corePackDefs(), bs = bindings(domain), defs = new ArrayList<>();
        for (Object b : bs) defs.add(defOf(pack, (String) J.get(b, "verb")));
        Map<String, Object> onto = ActionDerive.toOntology(defs, reg == null ? Actions.CORE_REGISTRY : reg, (Predicate<Map<String, Object>>) null);
        List<Object> verbs = new ArrayList<>();
        Map<String, Object> aliases = new LinkedHashMap<>();
        for (Object b : bs) {
            Map<String, Object> d = defOf(pack, (String) J.get(b, "verb"));
            List<Object> dal = d.get("aliases") instanceof List ? J.a(d.get("aliases")) : new ArrayList<>();
            if (!dal.contains(J.get(b, "id"))) throw new IllegalStateException("domain binding '" + J.get(b, "id") + "' is not an alias of '" + J.get(b, "verb") + "'");
            Map<String, Object> ov = null;
            for (Object v : J.a(onto.get("verbs"))) if (J.get(b, "verb").equals(J.get(v, "id"))) { ov = J.m(v); break; }
            Map<String, Object> params = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : J.m(J.get(b, "params")).entrySet()) {
                Object p = J.m(ov.get("params")).get(e.getValue());
                if (p == null) throw new IllegalStateException("domain binding '" + J.get(b, "id") + "' surfaces unknown parameter '" + e.getValue() + "'");
                params.put(e.getKey(), "money".equals(J.get(p, "kind")) && J.get(b, "ccys") != null ? J.obj("kind", "money", "ccys", new ArrayList<>(J.a(J.get(b, "ccys")))) : p);
            }
            verbs.add(J.obj("id", J.get(b, "id"), "effect", ActionDerive.effectClass(d), "resource_type", J.get(b, "resourceType"), "params", params));
            for (Object a : dal) if (!a.equals(J.get(b, "id"))) aliases.put((String) a, J.get(b, "id"));
        }
        return J.obj("verbs", verbs, "aliases", aliases);
    }

    /** The role map of a domain verb for the selector layer: {@code id -> role -> [NL parameter names carrying it]}. */
    public static Map<String, Object> domainRoles(String domain) {
        List<Object> pack = corePackDefs();
        Map<String, Object> out = new LinkedHashMap<>();
        for (Object b : bindings(domain)) {
            Map<String, Object> d = defOf(pack, (String) J.get(b, "verb"));
            Map<String, Object> roles = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : J.m(J.get(b, "params")).entrySet()) {
                Object r = J.get(J.m(d.get("params")).get(e.getValue()), "role");
                if (r != null) J.a(roles.computeIfAbsent((String) r, k -> new ArrayList<Object>())).add(e.getKey());
            }
            out.put(J.get(b, "id").toString(), roles);
        }
        return out;
    }

    // ---- release attestation (none shipped in this build) -----------------------------------------------------------------------

    /** The release pins the built-in attestations verify against; null before the first release signing (always, in this build). */
    public static Object builtinReleasePins() { return null; }

    /** The built-in defs with their release attestation attached where the package carries one (none: returned unchanged and unconfirmed). */
    /**
     * The release pins and registry the built-in attestations verify against, or null before the first release signing (this build carries no release
     * attestation, so the built-in definitions stay unconfirmed and this is null).
     */
    public static Object builtinReleaseCtx() { return null; }

    public static List<Object> releasedBuiltinDefs(List<?> defs) { return new ArrayList<Object>(defs == null ? builtinDefs() : defs); }

    /** Release step: sign every built-in def (or {@code defs}) with the release reviewer key; the key is a parameter and is never stored. */
    public static List<Object> signBuiltins(Actions.Registry reg, String kid, byte[] secret, Object ts, List<?> defs) {
        return net.atlasauth.pca.actions.importers.ImportReview.signBuiltins(reg, kid, secret, ts, defs == null ? builtinDefs() : defs);
    }

    /** The attestation check under which released built-ins count as confirmed; null without pinned release keys (nothing confirmed). */
    public static Predicate<Map<String, Object>> builtinReviewOpts(Actions.Registry reg) {
        Object pins = builtinReleasePins();
        return pins == null ? null : ActionUndoEngine.attestationVerifier(pins, reg == null ? Actions.CORE_REGISTRY : reg);
    }
}
