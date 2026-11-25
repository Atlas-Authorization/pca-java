package net.atlasauth.pca.connect;

/** CRUD over stored connections. Implementations must round-trip a {@link StoredConnection} by its key; any exception means the store failed. */
public interface ConnectionStore {
    /** The composite key identifying one stored connection. */
    final class Key {
        public final String agentId, provider, connectionId;
        public Key(String agentId, String provider, String connectionId) { this.agentId = agentId; this.provider = provider; this.connectionId = connectionId; }
        /** NUL-joined: provider / connectionId / agentId are b64u or opaque tokens, none of which contain NUL. */
        String str() { return agentId + "\u0000" + provider + "\u0000" + connectionId; }
    }

    /** The connection, or null. */
    StoredConnection get(Key key) throws Exception;

    void set(StoredConnection connection) throws Exception;

    void delete(Key key) throws Exception;

    /** Marks the store as encrypting at rest; {@link TokenVault} requires it in strict mode. */
    default boolean encrypted() { return false; }
}
