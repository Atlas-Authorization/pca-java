package net.atlasauth.pca.revoke;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A live, mutable registry of revocations: a pluggable {@link RevocationStore} (in memory by default) keyed by capability id,
 * agent holder key, issuer key, or delegation-subtree prefix. A resource server holds one and consults
 * {@link Revoke#checkRevocation} / {@link Revoke#verifyWithRevocation} on every action, next to the core verifier.
 *
 * <p>Inputs are JSON objects (Map), as the reference takes them: {kind, value | prefix, reason?, revokedAt?, notBefore?}.
 */
public final class RevocationRegistry {
    private static final String PREFIX_SEP = ",";
    private final RevocationStore store;
    private final java.util.function.LongSupplier clock;

    public RevocationRegistry() { this(new InMemoryRevocationStore()); }

    public RevocationRegistry(RevocationStore store) { this(store, System::currentTimeMillis); }

    /** A registry that stamps an entry without a {@code revokedAt} from {@code clock} (epoch ms) instead of the system clock. */
    public RevocationRegistry(RevocationStore store, java.util.function.LongSupplier clock) { this.store = store; this.clock = clock; }

    /** The registry's clock reading (epoch ms). */
    double nowMs() { return (double) clock.getAsLong(); }

    static String serializePrefix(List<?> prefix) { return JsVal.join(prefix, PREFIX_SEP); }

    /** Revoke a capability id, holder key, issuer key, or subtree prefix. Returns the stored entry. Throws {@link JsVal.TypeError} on a malformed input. */
    public RevocationEntry revoke(Map<String, Object> input) {
        Object ra = JsVal.member(input, "revokedAt");
        double revokedAt;
        if (ra == null) revokedAt = nowMs();
        else if (!JsVal.isFinite(ra)) throw new JsVal.TypeError("revoke: revokedAt must be a finite number");
        else revokedAt = JsVal.num(ra);
        Double notBefore = null;
        if (JsVal.has(input, "notBefore")) {
            Object nb = input.get("notBefore");
            if (!JsVal.isFinite(nb)) throw new JsVal.TypeError("revoke: notBefore must be a finite number");
            notBefore = JsVal.num(nb);
        }
        Object reasonO = JsVal.or(input.get("reason"), "");
        if (!(reasonO instanceof String)) throw new JsVal.TypeError("revoke: reason must be a string");
        String reason = (String) reasonO;
        Object kind = input.get("kind");
        RevocationEntry entry;
        if ("prefix".equals(kind)) {
            Object p = input.get("prefix");
            if (!(p instanceof List) || ((List<?>) p).isEmpty()) throw new JsVal.TypeError("revoke: a prefix revocation requires a non-empty cap-id path");
            List<String> path = new ArrayList<>();
            for (Object id : (List<?>) p) {
                // The path is serialized with ',' as separator: an element holding one would alias a different path.
                if (!JsVal.nonEmpty(id) || ((String) id).contains(PREFIX_SEP)) throw new JsVal.TypeError("revoke: every prefix element must be a non-empty string without ','");
                path.add((String) id);
            }
            entry = new RevocationEntry("prefix", serializePrefix(path), path, reason, revokedAt, notBefore);
        } else {
            // The reference stores any kind, an absent one included (the entry then has no kind); a kind of another JSON type is still refused.
            if (kind != null && !(kind instanceof String)) throw new JsVal.TypeError("revoke: kind must be a string");
            Object v = input.get("value");
            if (!JsVal.nonEmpty(v)) throw new JsVal.TypeError("revoke: a " + kind + " revocation requires a non-empty value");
            entry = new RevocationEntry((String) kind, (String) v, null, reason, revokedAt, notBefore);
        }
        store.add(entry);
        return entry;
    }

    /**
     * Revoke an entire delegation subtree. A rootCapId (String) revokes every chain that passes through that capability (a cap
     * revocation); a chainPrefix (List of cap ids) revokes every chain whose hops begin with that path. opts: reason, revokedAt, notBefore.
     */
    public RevocationEntry revokeSubtree(Object target, Map<String, Object> opts) {
        Map<String, Object> in = new LinkedHashMap<>();
        if (target instanceof List) { in.put("kind", "prefix"); in.put("prefix", target); }
        else { in.put("kind", "cap"); in.put("value", target); }
        if (opts != null) in.putAll(opts);
        return revoke(in);
    }

    /** Remove a revocation. key: {kind, value} or {kind: 'prefix', prefix}. Returns true when one was removed. */
    public boolean unrevoke(Map<String, Object> key) {
        Object kind = JsVal.member(key, "kind");
        if ("prefix".equals(kind)) {
            Object p = key.get("prefix");
            if (!(p instanceof List) || ((List<?>) p).isEmpty()) return false;
            return store.remove("prefix", serializePrefix((List<?>) p));
        }
        return store.remove(JsVal.strMember(key, "kind"), JsVal.strMember(key, "value"));
    }

    /** Every active-or-scheduled revocation (a snapshot). */
    public List<RevocationEntry> list() { return store.all(); }

    /** Point lookup of a cap / holder / issuer revocation. */
    public RevocationEntry lookup(String kind, String value) { return store.get(kind, value); }

    /** Every subtree-prefix revocation. */
    public List<RevocationEntry> prefixes() {
        List<RevocationEntry> out = new ArrayList<>();
        for (RevocationEntry e : store.all()) if (e.kind.equals("prefix")) out.add(e);
        return out;
    }

    /** Drop every revocation. */
    public void clear() { store.clear(); }

    private RevocationEntry kill(String kind, Object value, Map<String, Object> opts, String dflt) {
        Map<String, Object> in = new LinkedHashMap<>();
        in.put("kind", kind);
        in.put("value", value);
        in.put("reason", JsVal.or(opts == null ? null : opts.get("reason"), dflt));
        if (opts != null && opts.containsKey("revokedAt")) in.put("revokedAt", opts.get("revokedAt"));
        return revoke(in);
    }

    /** KILL-SWITCH: instantly revoke an agent by its holder key; denies every in-flight action by it. */
    public RevocationEntry killAgent(Object holder, Map<String, Object> opts) { return kill("holder", holder, opts, "kill-switch: agent killed"); }

    /** KILL-SWITCH: instantly revoke an entire delegation subtree rooted at rootCapId. */
    public RevocationEntry killSubtree(Object rootCapId, Map<String, Object> opts) { return kill("cap", rootCapId, opts, "kill-switch: subtree killed"); }
}
