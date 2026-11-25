package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * A catalog built in the test (the built-in one is made once, when the class loads): every spec member, the frozen lists, lookup by
 * verb (a later spec replaces an earlier one, as the reference's {@code buildCatalog}), and alias resolution (catalog.ts resolve:
 * the exact verb first, else exactly one action of that connector listing the alias).
 */
class CatalogPitKill1Test {
    static Catalog.Spec spec(String connector, String action, String... aliases) {
        return new Catalog.Spec(connector, action, connector + "." + action, "reversible", 0.25, null, action, new ArrayList<>(List.of(aliases)), null);
    }

    @Test void aSpecKeepsEveryMember() {
        Catalog.Spec s = new Catalog.Spec("acme", "pay", "acme.pay_v2", "irreversible", 0.75, "amt", "Pays a supplier.", List.of("send"), List.of("pca.money_moving"));
        assertEquals("acme", s.connector);
        assertEquals("pay", s.action);
        assertEquals("acme.pay_v2", s.verb);
        assertEquals("irreversible", s.reversibility);
        assertEquals(0.75, s.blastRadius);
        assertEquals("amt", s.amountField);
        assertEquals("Pays a supplier.", s.description);
        assertEquals(List.of("send"), s.aliases);
        assertEquals(List.of("pca.money_moving"), s.traits);
    }

    @Test void aSpecCopiesItsListsAndFreezesThem() {
        List<String> aliases = new ArrayList<>(List.of("send")), traits = new ArrayList<>(List.of("pca.bulk"));
        Catalog.Spec s = new Catalog.Spec("acme", "pay", "acme.pay", "reversible", 0.5, null, "d", aliases, traits);
        aliases.add("later");
        traits.add("later");
        assertEquals(List.of("send"), s.aliases);
        assertEquals(List.of("pca.bulk"), s.traits);
        assertThrows(UnsupportedOperationException.class, () -> s.aliases.add("x"));
        assertThrows(UnsupportedOperationException.class, () -> s.traits.add("x"));
    }

    @Test void absentListsAreEmptyAndFrozen() {
        Catalog.Spec s = new Catalog.Spec("acme", "pay", "acme.pay", "reversible", 0.5, null, "d", null, null);
        assertEquals(List.of(), s.aliases);
        assertEquals(List.of(), s.traits);
        assertThrows(UnsupportedOperationException.class, () -> s.aliases.add("x"));
        assertThrows(UnsupportedOperationException.class, () -> s.traits.add("x"));
    }

    @Test void eachVerbIsFoundAndALaterSpecReplacesAnEarlierOne() {
        Catalog.Spec first = spec("acme", "pay"), refund = spec("acme", "refund"), second = spec("acme", "pay", "send");
        Catalog c = new Catalog(List.of(first, refund, second));
        assertSame(second, c.get("acme.pay"));
        assertSame(refund, c.get("acme.refund"));
        assertNull(c.get("acme.nope"));
        List<Catalog.Spec> all = c.all();
        assertEquals(List.of(second, refund), all); // a replaced verb keeps its first position (Map.set)
        all.clear();
        assertEquals(2, c.all().size());
    }

    @Test void resolveTakesTheExactVerbElseTheOneActionOfThatConnectorWithTheAlias() {
        Catalog.Spec pay = spec("acme", "pay", "send"), send = spec("acme", "send"), refund = spec("acme", "refund", "give_back", "undo"),
            voidIt = spec("acme", "void", "undo"), give = spec("beta", "give", "give_back");
        Catalog c = new Catalog(List.of(pay, send, refund, voidIt, give));
        assertSame(pay, c.resolve("acme", "pay"));
        assertSame(send, c.resolve("acme", "send")); // the exact verb wins over pay's alias
        assertSame(refund, c.resolve("acme", "give_back")); // beta's give_back is another connector's
        assertSame(give, c.resolve("beta", "give_back"));
        assertNull(c.resolve("acme", "undo")); // two actions list it: none
        assertNull(c.resolve("acme", "nothing"));
        assertNull(c.resolve("gamma", "send"));
    }
}
