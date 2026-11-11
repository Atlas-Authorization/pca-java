package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Read-only copies of List.of / Set.of / Map.of collections whose lookups accept null. The JDK's immutable collections throw
 * NullPointerException from contains(null) / containsKey(null) / get(null) / indexOf(null); fed a JSON null from untrusted
 * input, a check built on them refused by crashing (fail closed, but with the wrong reason / code) instead of by its own
 * rule. These copies answer false / null / -1, so the check's own refusal runs. Iteration keeps the declared order.
 */
final class NullSafe {
    private NullSafe() {}

    static <T> List<T> list(Collection<? extends T> xs) { return Collections.unmodifiableList(new ArrayList<>(xs)); }

    static <T> Set<T> set(Collection<? extends T> xs) { return Collections.unmodifiableSet(new LinkedHashSet<>(xs)); }

    static <K, V> Map<K, V> map(Map<? extends K, ? extends V> m) { return Collections.unmodifiableMap(new LinkedHashMap<>(m)); }
}
