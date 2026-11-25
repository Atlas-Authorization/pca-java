package net.atlasauth.pca.rotate;

import java.util.LinkedHashMap;
import java.util.Map;
import net.atlasauth.pca.revoke.RevocationRegistry;

/** The part of a revocation registry that {@link Rotate#applyRotation} needs; {@link #of} adapts a {@link RevocationRegistry}. */
public interface RevocationSink {
    /** Revoke input = {kind: 'cap', value, reason?, revokedAt?}. */
    void revoke(Map<String, Object> input);

    /** Remove the cap revocation; true when one was removed. */
    boolean unrevoke(Map<String, Object> key);

    /** The cap revocation for value, or null when there is none. */
    Object lookup(String kind, String value);

    static RevocationSink of(RevocationRegistry registry) {
        return new RevocationSink() {
            @Override public void revoke(Map<String, Object> input) { registry.revoke(input); }
            @Override public boolean unrevoke(Map<String, Object> key) { return registry.unrevoke(key); }
            @Override public Object lookup(String kind, String value) { return registry.lookup(kind, value); }
        };
    }

    /** {kind: 'cap', value: id}. */
    static Map<String, Object> capKey(String id) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("kind", "cap");
        m.put("value", id);
        return m;
    }
}
