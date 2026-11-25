package net.atlasauth.pca.grants;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import net.atlasauth.pca.Blueprint;
import net.atlasauth.pca.GrantSigning;
import net.atlasauth.pca.HardwareResult;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.Keys;

/**
 * Operator-side blueprint operations and attestation-gated admission. Record verification, the registry and the chain gate are
 * {@link Blueprint}; signing is {@link GrantSigning#signBlueprint}. A blueprint with {@code runtime_pins} admits an instance key only
 * after evidence for that key was verified and the MEASURED identity matched a pin; anything unverifiable is a deny.
 */
public final class Blueprints {
    private Blueprints() {}

    /** Anything with a revoke for an issuer key (a revocation registry). */
    @FunctionalInterface
    public interface IssuerRevoker { void revokeIssuer(String value, String reason, long revokedAt) throws Exception; }

    /** Group kill: sign the blueprint as {@code disabled} at the next epoch, accept it, revoke the key as an issuer and advance the freshness epoch. */
    public static Map<String, Object> groupKill(Keys.EdKey secret, Blueprint.Registry registry, String key, long now, String reason, IssuerRevoker revocation, FreshAt.Issuer freshAt) throws Exception {
        Map<String, Object> cur = GrantSigning.blueprintGet(registry, key);
        if (cur == null) return fail("unknown_blueprint");
        Map<String, Object> rest = new LinkedHashMap<>(cur);
        rest.remove("sig");
        rest.remove("operator");
        rest.remove("v");
        rest.put("status", "disabled");
        rest.put("epoch", Json.asLong(cur.get("epoch")) + 1);
        rest.put("issued_at", now);
        Map<String, Object> record = GrantSigning.signBlueprint(secret, rest);
        Blueprint.Accept r = registry.accept(record);
        if (r.code != null) return fail(r.code);
        if (revocation != null) revocation.revokeIssuer(key, reason != null ? reason : "blueprint disabled (group kill)", now);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("record", record);
        if (freshAt != null) {
            Map<String, Object> patch = new LinkedHashMap<>();
            patch.put("revocation_epoch", record.get("epoch"));
            out.put("freshAt", freshAt.advance(patch, now));
        }
        return out;
    }

    private static Map<String, Object> fail(String code) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("code", code);
        return m;
    }

    private static Map<String, Object> deny(String code, String reason) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("admitted", false);
        m.put("code", code);
        if (reason != null) m.put("reason", reason);
        return m;
    }

    private static boolean pinMatches(Map<String, Object> pin, Map<String, Object> id) {
        if (pin.isEmpty()) return false;
        for (Map.Entry<String, Object> e : pin.entrySet()) if (e.getValue() == null || !Objects.equals(id.get(e.getKey()), e.getValue())) return false;
        return true;
    }

    /**
     * Admit from adapter evidence: a parsed {ok, bound, identity?, reason?}. {@code ok} and {@code bound} must both be exactly true;
     * {@code identity} is what the adapter established, never what the instance claims. A thrown error or malformed result denies.
     * Returns {admitted:true, identity, pin} or {admitted:false, code, reason?}.
     */
    public static Map<String, Object> admitWithEvidence(Map<String, Object> blueprint, Callable<Object> getEvidence) {
        Object pins = blueprint.get("runtime_pins");
        if (!(pins instanceof List) || ((List<?>) pins).isEmpty()) return deny("no_pins", null);
        Object r;
        try {
            r = getEvidence.call();
        } catch (Exception e) {
            String n = e.getClass().getSimpleName(); // the reference reports the error's name: an adapter signals a TypeError / RangeError by a class of that name
            return deny("verifier_error", n.equals("TypeError") || n.equals("RangeError") || n.equals("SyntaxError") ? n : "Error");
        }
        Map<String, Object> ev = Sig.map(r);
        if (ev == null || !Boolean.TRUE.equals(ev.get("ok"))) return deny("not_ok", ev != null && ev.get("reason") instanceof String ? (String) ev.get("reason") : null);
        if (!Boolean.TRUE.equals(ev.get("bound"))) return deny("not_bound", null);
        if (ev.get("identity") instanceof List) return deny("no_matching_pin", null); // the reference's typeof check passes an array; no pin key is ever a member of one
        Map<String, Object> id = Sig.map(ev.get("identity"));
        if (id == null) return deny("no_identity", null);
        for (Object p : (List<?>) pins) {
            Map<String, Object> pin = Sig.map(p);
            if (pin != null && pinMatches(pin, id)) {
                Map<String, Object> ok = new LinkedHashMap<>();
                ok.put("admitted", true);
                ok.put("identity", id);
                ok.put("pin", pin);
                return ok;
            }
        }
        return deny("no_matching_pin", null);
    }

    /**
     * Admit through a hardware attestation verifier already bound to the document, context and expected binding ({@code verify}).
     * {@code hasDocument} false is a deny (no evidence).
     */
    public static Map<String, Object> admitBlueprintInstance(Map<String, Object> blueprint, boolean hasDocument, Callable<HardwareResult> verify) {
        Object pins = blueprint.get("runtime_pins");
        if (!(pins instanceof List) || ((List<?>) pins).isEmpty()) return deny("no_pins", null);
        if (!hasDocument) return deny("not_ok", "no evidence");
        return admitWithEvidence(blueprint, () -> {
            HardwareResult h = verify.call();
            Map<String, Object> ev = new LinkedHashMap<>();
            ev.put("ok", h != null && h.ok);
            ev.put("bound", h != null && h.bound);
            if (h != null && h.measured != null) ev.put("identity", h.measured);
            if (h != null && h.reason != null) ev.put("reason", h.reason);
            return ev;
        });
    }

    /** Holds admissions; plug {@link #checker} into {@link Blueprint#check}. */
    public static final class AdmissionRegistry {
        private final Map<String, long[]> m = new ConcurrentHashMap<>();

        private static String k(String bpKey, String instanceKey) { return bpKey + "\u0000" + instanceKey; }

        /** Record an admission made under {@code bp} (its epoch), valid until {@code until} (epoch ms). */
        public void admit(String instanceKey, Map<String, Object> bp, long until) { m.put(k((String) bp.get("key"), instanceKey), new long[] {Json.asLong(bp.get("epoch")), until}); }

        public boolean revoke(String instanceKey, String bpKey) { return m.remove(k(bpKey, instanceKey)) != null; }

        /** True only for an unexpired admission made under the record's current epoch. */
        public Blueprint.Admitted checker(long now) {
            return (instanceKey, bp) -> {
                long[] a = m.get(k((String) bp.get("key"), instanceKey));
                return a != null && a[0] == Json.asLong(bp.get("epoch")) && now < a[1];
            };
        }
    }
}
