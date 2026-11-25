package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The JDK's immutable collections (List.of / Set.of / Map.of / copyOf) throw NullPointerException from contains(null),
 * containsKey(null), get(null) and indexOf(null). A check built on one, fed a JSON null from untrusted input, refused by
 * crashing (fail closed, wrong reason / code) instead of by its own rule. Every lookup table in these classes is now a
 * {@link NullSafe} copy: this sweep fails if any static collection is still a JDK immutable one, and asserts null lookups
 * answer "absent" on every table, class by class.
 */
public class NullSafeLookupTest {
    static final Class<?>[] SWEPT = {
        A2a.class, ActionRegistry.class, ActionSchema.class, Actions.class, Approval.class, ArgProvenance.class, AttestMaa.class,
        Authorize.class, CaveatLang.class, Caveats.class, Decision.class, Escalation.class, IntentAcc.class, IntentArtifacts.class,
        IntentMap.class, IntentRevocation.class, IntentSession.class, IntentV2.class, MissingContext.class, Obligations.class,
        ParamProvenance.class, Passport.class, PcaGrant.class, PolicyClasses.class, Pq.class, Predicates.class, ReadVault.class,
        Sigstore.class, Undo.class, Workflow.class,
    };

    static void sweep(Class<?> c, List<String> bad, int[] tables) throws Exception {
        for (Field f : c.getDeclaredFields()) {
            if (!Modifier.isStatic(f.getModifiers()) || f.getType().isPrimitive()) continue;
            f.setAccessible(true);
            Object v = f.get(null);
            if (!(v instanceof Collection) && !(v instanceof Map)) continue;
            String at = c.getName() + "." + f.getName();
            if (v.getClass().getName().startsWith("java.util.ImmutableCollections")) { bad.add(at + " is a JDK immutable collection (null lookups throw)"); continue; }
            if (!v.getClass().getName().startsWith("java.util.Collections$Unmodifiable")) continue; // caches etc.: not lookup tables
            tables[0]++;
            try {
                if (v instanceof Collection) {
                    assertFalse(((Collection<?>) v).contains(null), at);
                    if (v instanceof List) assertEquals(-1, ((List<?>) v).indexOf(null), at);
                } else {
                    assertFalse(((Map<?, ?>) v).containsKey(null), at);
                    assertNull(((Map<?, ?>) v).get(null), at);
                }
            } catch (NullPointerException e) {
                bad.add(at + ": null lookup threw");
            }
        }
        for (Class<?> n : c.getDeclaredClasses()) sweep(n, bad, tables);
    }

    @Test void everyLookupTableAnswersNull() throws Exception {
        List<String> bad = new ArrayList<>();
        int[] tables = {0};
        for (Class<?> c : SWEPT) sweep(c, bad, tables);
        assertTrue(bad.isEmpty(), String.join("\n", bad));
        assertTrue(tables[0] >= 50, "swept only " + tables[0] + " lookup tables");
    }

    @Test void nullSafeCopiesKeepOrderAndRefuseWrites() {
        List<String> l = NullSafe.list(List.of("b", "a"));
        assertEquals(List.of("b", "a"), l);
        assertFalse(l.contains(null));
        assertThrows(UnsupportedOperationException.class, () -> l.add("c"));
        assertFalse(NullSafe.set(java.util.Set.of("x")).contains(null));
        Map<String, Integer> m = NullSafe.map(Map.of("k", 1));
        assertNull(m.get(null));
        assertEquals(1, m.get("k"));
        assertThrows(UnsupportedOperationException.class, () -> m.put("j", 2));
    }

    // a JSON null where a closed vocabulary is expected is refused by the check's own reason, not "evaluation error"
    @Test void argProvenanceNullOriginIsRefusedByTheRule() {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("origin", null);
        String why = ArgProvenance.receiptWireError(r);
        assertNotNull(why);
        assertFalse(why.contains("NullPointer"), why);
    }

    @Test void missingContextNotNullIsIllTyped() {
        Map<String, Object> not = new LinkedHashMap<>();
        not.put("not", null);
        Map<String, Object> bound = new LinkedHashMap<>();
        bound.put("action", new LinkedHashMap<String, Object>());
        Map<String, Object> d = MissingContext.decide(List.of(not), bound, null, null);
        assertEquals("deny", d.get("decision"));
        assertEquals("ill_typed_context", d.get("reason"));
    }
}
