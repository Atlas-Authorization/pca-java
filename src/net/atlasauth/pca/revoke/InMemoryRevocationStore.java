package net.atlasauth.pca.revoke;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** In-memory {@link RevocationStore} (the default). Single process; swap in a shared store for a fleet. */
public final class InMemoryRevocationStore implements RevocationStore {
    private final Map<String, RevocationEntry> entries = new LinkedHashMap<>();

    static String key(String kind, String value) { return kind + "\u0000" + value; }

    @Override public synchronized void add(RevocationEntry e) { entries.put(key(e.kind, e.value), e); }

    @Override public synchronized boolean remove(String kind, String value) { return entries.remove(key(kind, value)) != null; }

    @Override public synchronized RevocationEntry get(String kind, String value) { return entries.get(key(kind, value)); }

    @Override public synchronized List<RevocationEntry> all() { return new ArrayList<>(entries.values()); }

    @Override public synchronized void clear() { entries.clear(); }
}
