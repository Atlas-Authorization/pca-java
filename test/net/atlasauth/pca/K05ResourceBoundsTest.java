package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.AbstractList;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Caps on attacker input that bound the work done before a refusal (they rarely change the answer, so each test observes
 * the early exit itself: an input part past the cap that would throw an Error if it were ever read).
 */
public class K05ResourceBoundsTest {
    /** A list of n elements that fails the test if any element is read. */
    static <T> List<T> untouchable(int n) {
        return new AbstractList<T>() {
            @Override public int size() { return n; }
            @Override public T get(int i) { throw new AssertionError("element " + i + " read"); }
        };
    }

    @Test
    void inclusionProofOver64IsRefusedUnread() {
        byte[] h = new byte[32];
        assertFalse(ProvenanceGate.verifyRfc9162Inclusion(h, 0, 1, untouchable(65), h));
        // 64 is within the cap (provenance-gate.ts:59), so the elements are read
        assertThrows(AssertionError.class, () -> ProvenanceGate.verifyRfc9162Inclusion(h, 0, 1, untouchable(64), h));
    }

    @Test
    void argLeavesStopBeforeWalkingAValuePastTheCap() {
        for (int before : new int[] {ArgProvenance.MAX_LEAVES, ArgProvenance.MAX_LEAVES - 1}) {
            List<Object> v = new ArrayList<>();
            for (int i = 0; i < before; i++) v.add("s" + i);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("k", untouchable(1));
            v.add(m);
            if (before == ArgProvenance.MAX_LEAVES) assertNull(ArgProvenance.leaves(v), "the key is leaf 4097: its value is never walked");
            else assertThrows(AssertionError.class, () -> ArgProvenance.leaves(v), "the key is leaf 4096: its value is walked");
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void cosignaturesStopOnceTheThresholdIsMet() throws Exception {
        int seen = 0;
        for (Map<String, Object> c : K05Oracle.of("k05-ledger", "verifyWitnessCosignatures")) {
            List<?> a = (List<?>) c.get("args");
            if (!Boolean.TRUE.equals(c.get("out")) || a.size() != 2 || !(a.get(0) instanceof Map) || !(a.get(1) instanceof Map)) continue;
            Map<String, Object> policy = (Map<String, Object>) a.get(1);
            Double t = IntentJs.num(policy.get("threshold")); // oracle numbers are Json.Num, not Number
            if (t == null || t < 1) continue;
            Map<String, Object> sth = new LinkedHashMap<>((Map<String, Object>) a.get(0));
            List<Object> ws = new ArrayList<>((List<?>) sth.get("witnesses"));
            ws.add(new LinkedHashMap<String, Object>() {
                @Override public Object get(Object k) { throw new AssertionError("a witness past the threshold was read"); }
            });
            sth.put("witnesses", ws);
            assertTrue(Ledger.verifyWitnessCosignatures(sth, policy), String.valueOf(c.get("name")));
            seen++;
        }
        assertTrue(seen > 0, "no met-threshold oracle case");
    }

    @Test
    void characterReferencesParseAtMostEightSignificantDigits() {
        assertEquals("A", AttestXml.xmlDecode("&#" + "0".repeat(200_000) + "65;"), "leading zeros are free");
        assertEquals(new String(Character.toChars(0x10ffff)), AttestXml.xmlDecode("&#x10FFFF;"));
        assertThrows(AttestException.class, () -> AttestXml.xmlDecode("&#x110000;"));
        assertThrows(AttestException.class, () -> AttestXml.xmlDecode("&#123456789;"));
        assertThrows(AttestException.class, () -> AttestXml.xmlDecode("&#" + "9".repeat(2_000_000) + ";"));
    }
}
