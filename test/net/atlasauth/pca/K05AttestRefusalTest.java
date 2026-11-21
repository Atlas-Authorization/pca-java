package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;

/**
 * Every explicit check in the signed confirmation ({@link Actions#attestRefusal}) names itself, so none of them rests on a later cast or null read
 * throwing into the catch: each row below would come back as "malformed attestation" (or another check's reason) if its guard were gone.
 */
public class K05AttestRefusalTest {
    static final String DEF = K05R4ActionsCKillTest.DEF, KID = K05R4ActionsCKillTest.KID;
    static final Predicate<List<String>> ANY = f -> true;

    static Map<String, Object> map(Object... kv) { return K05R4ActionsCKillTest.map(kv); }
    static List<Object> list(Object... xs) { return K05R4ActionsCKillTest.list(xs); }

    static Map<String, Object> good() {
        return K05R4ActionsCKillTest.signed(K05R4ActionsCKillTest.att(DEF, "facts", list("pca.write"), list(K05R4ActionsCKillTest.dismissal("pca.bulk", "not relevant"))));
    }

    static String refusal(Object a) { return Actions.attestRefusal(a, DEF, Actions.CORE_REGISTRY, K05R4ActionsCKillTest.pins(), null, ANY); }

    static String with(Consumer<Map<String, Object>> edit) { Map<String, Object> a = good(); edit.accept(a); return refusal(a); }

    @Test void theGoodAttestationIsAccepted() {
        assertNull(refusal(good()));
        assertNull(Actions.attestRefusal(good(), DEF, Actions.CORE_REGISTRY, K05R4ActionsCKillTest.pins(), "facts", ANY));
    }

    @Test void pinsAndArgumentsNameTheirCheck() {
        assertEquals("no reviewer pins", Actions.attestRefusal(good(), DEF, Actions.CORE_REGISTRY, null, null, ANY));
        assertEquals("reviewer pins: pins must be {keys: [...]}", Actions.attestRefusal(good(), DEF, Actions.CORE_REGISTRY, map("keys", "x"), null, ANY));
        assertEquals("attestation is not an object", refusal(null));
        assertEquals("attestation is not an object", refusal(list()));
        assertEquals("def digest is not a string", Actions.attestRefusal(good(), 7, Actions.CORE_REGISTRY, K05R4ActionsCKillTest.pins(), null, ANY));
        assertEquals("def digest is not a string", Actions.attestRefusal(good(), null, Actions.CORE_REGISTRY, K05R4ActionsCKillTest.pins(), null, ANY));
    }

    @Test void eachMemberNamesItsCheck() {
        assertEquals("sig is not a string", with(a -> a.put("sig", 1)));
        assertEquals("sig is not a string", with(a -> a.remove("sig")));
        assertEquals("def_digest does not match", with(a -> a.put("def_digest", "other")));
        assertEquals("def_digest does not match", with(a -> a.remove("def_digest")));
        assertEquals("traits_digest is not accepted", with(a -> a.put("traits_digest", "other")));
        assertEquals("facts_digest is not a string", with(a -> a.put("facts_digest", list())));
        assertEquals("facts_digest is not a string", with(a -> a.remove("facts_digest")));
        assertEquals("facts_digest does not match", Actions.attestRefusal(good(), DEF, Actions.CORE_REGISTRY, K05R4ActionsCKillTest.pins(), "other", ANY));
        assertEquals("final_traits is not an array", with(a -> a.put("final_traits", "pca.write")));
        assertEquals("final_traits is not an array", with(a -> a.remove("final_traits")));
        assertEquals("dismissed is not an array", with(a -> a.put("dismissed", map())));
        assertEquals("dismissed is not an array", with(a -> a.remove("dismissed")));
        assertEquals("ts is not an integer", with(a -> a.put("ts", "1000")));
        assertEquals("ts is not an integer", with(a -> a.remove("ts")));
        assertEquals("reviewer_kid is not a string", with(a -> a.put("reviewer_kid", list(KID))));
        assertEquals("reviewer_kid is not a string", with(a -> a.remove("reviewer_kid")));
        assertEquals("final_traits are not accepted", Actions.attestRefusal(good(), DEF, Actions.CORE_REGISTRY, K05R4ActionsCKillTest.pins(), null, f -> false));
    }

    @Test void eachDismissalNamesItsCheck() {
        assertEquals("a dismissal is not an object", with(a -> a.put("dismissed", list("pca.bulk"))));
        assertEquals("a dismissal is not an object", with(a -> a.put("dismissed", list((Object) null))));
        assertEquals("a dismissal trait is not a string", with(a -> a.put("dismissed", list(map("trait", 1, "reason", "r")))));
        assertEquals("a dismissal trait is not a string", with(a -> a.put("dismissed", list(map("reason", "r")))));
        assertEquals("a dismissal reason is not a string", with(a -> a.put("dismissed", list(map("trait", "pca.bulk", "reason", 1)))));
        assertEquals("a dismissal reason is not a string", with(a -> a.put("dismissed", list(map("trait", "pca.bulk")))));
        assertEquals("a dismissed trait is final", with(a -> a.put("dismissed", list(map("trait", "pca.write", "reason", "r")))));
        assertEquals("a dismissal reason is blank", with(a -> a.put("dismissed", list(map("trait", "pca.bulk", "reason", " \t")))));
    }

    @Test void theKeyAndSignatureNameTheirCheck() {
        assertEquals("reviewer_kid is not pinned", with(a -> a.put("reviewer_kid", "nobody")));
        Map<String, Object> importer = map("keys", list(map("kid", KID, "pk", IntentV2KillTest.pub(K05R4ActionsCKillTest.LABEL), "roles", list("publisher"))));
        assertEquals("the key lacks the reviewer role", Actions.attestRefusal(good(), DEF, Actions.CORE_REGISTRY, importer, null, ANY));
        assertEquals("ts is outside the key's validity", with(a -> a.put("ts", IntentJs.ofLong(99))));
        assertEquals("ts is outside the key's validity", with(a -> a.put("ts", IntentJs.ofLong(2000000001L))));
        assertEquals("bad signature", with(a -> a.put("facts_digest", "changed")));
        assertEquals("malformed attestation", with(a -> a.put("final_traits", list(IntentJs.ofLong(1)))));
    }
}
