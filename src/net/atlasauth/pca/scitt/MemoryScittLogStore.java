package net.atlasauth.pca.scitt;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** In-memory {@link ScittLogStore}: forgets everything on restart. For tests only. */
public final class MemoryScittLogStore implements ScittLogStore {
    private final List<byte[]> entries = new ArrayList<>();
    private final Map<String, byte[]> nodes = new HashMap<>();

    @Override public synchronized long size() { return entries.size(); }

    @Override public synchronized byte[] getEntry(long index) {
        if (index < 0 || index >= entries.size()) return null;
        return entries.get((int) index).clone();
    }

    @Override public synchronized byte[] getNode(long level, long index) {
        byte[] h = nodes.get(level + ":" + index);
        return h == null ? null : h.clone();
    }

    @Override public synchronized boolean append(long expectedSize, byte[] entry, List<StoredNode> nodeList) {
        if (entries.size() != expectedSize) return false;
        entries.add(entry.clone());
        for (StoredNode n : nodeList) nodes.put(n.level + ":" + n.index, n.hash.clone());
        return true;
    }
}
