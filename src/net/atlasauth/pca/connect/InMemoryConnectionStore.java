package net.atlasauth.pca.connect;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Process-local {@link ConnectionStore} (test double: tokens sit in plaintext in process memory, so a {@link TokenVault} accepts it only
 * with {@code strict = false}). Connections are cloned in and out so callers cannot mutate vault state through a held reference.
 */
public final class InMemoryConnectionStore implements ConnectionStore {
    private final Map<String, StoredConnection> map = new ConcurrentHashMap<>();

    @Override public StoredConnection get(Key key) {
        StoredConnection c = map.get(key.str());
        return c == null ? null : c.copy();
    }

    @Override public void set(StoredConnection c) { map.put(new Key(c.agentId, c.provider, c.connectionId).str(), c.copy()); }

    @Override public void delete(Key key) { map.remove(key.str()); }
}
