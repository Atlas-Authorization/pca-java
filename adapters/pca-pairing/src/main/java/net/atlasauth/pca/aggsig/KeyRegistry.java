package net.atlasauth.pca.aggsig;

import java.util.HashMap;
import java.util.Map;

/** A verifier's pinned set of admitted keys, indexed by key bytes: each was admitted with a verified proof of possession. */
public final class KeyRegistry {
    private final Map<String, RegisteredKey> keys = new HashMap<>();

    /** Verify the proof of possession and admit the key. Re-registering the same key is idempotent. */
    public synchronized Aggsig.RegisterResult register(byte[] publicKey, byte[] pop) {
        Aggsig.RegisterResult r = Aggsig.registerKey(publicKey, pop);
        if (r.ok) keys.put(Aggsig.hex(publicKey), r.key);
        return r;
    }

    /** The registered key for these bytes, or null if it was never admitted. */
    public synchronized RegisteredKey get(byte[] publicKey) {
        return publicKey != null && publicKey.length == AggsigCore.PUBLIC_KEY_LENGTH ? keys.get(Aggsig.hex(publicKey)) : null;
    }

    public boolean has(byte[] publicKey) { return get(publicKey) != null; }

    public synchronized int size() { return keys.size(); }
}
