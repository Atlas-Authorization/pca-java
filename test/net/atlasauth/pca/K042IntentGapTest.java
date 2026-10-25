package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Gap kills for IntentJs / ActionSchema / IntentV2 context validation that the TS corpora do not reach. */
class K042IntentGapTest {
    static Map<String, Object> map(Object... kv) {
        Map<String, Object> r = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]);
        return r;
    }

    // ---- IntentJs.u8len: TextEncoder semantics (a lone surrogate encodes as U+FFFD = 3 bytes), exhaustive over short strings ----
    private static int refLen(String s) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x80) n += 1;
            else if (c < 0x800) n += 2;
            else if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) { n += 4; i++; }
            else n += 3;
        }
        return n;
    }

    @Test void u8lenAgreesWithTheReferenceOverAllShortStrings() {
        char[] alpha = {'a', 'é', '€', '\ud800', '\udbff', '\udc00', '\udfff', '\u007f', '\u0080', '߿', 'ࠀ', '￿'};
        List<String> all = new ArrayList<>();
        all.add("");
        List<String> prev = List.of("");
        for (int n = 1; n <= 4; n++) {
            List<String> next = new ArrayList<>();
            for (String p : prev) for (char c : alpha) next.add(p + c);
            all.addAll(next);
            prev = next;
        }
        for (String s : all) {
            assertEquals(refLen(s), IntentJs.u8len(s), "u8len");
            if (!s.contains("\ud800") && !s.contains("\udbff") && !s.contains("\udc00") && !s.contains("\udfff"))
                assertEquals(s.getBytes(StandardCharsets.UTF_8).length, IntentJs.u8len(s));
        }
        assertEquals(5, IntentJs.u8len("é\udc00"));
        assertEquals(4, IntentJs.u8len("a\udc00"));
        assertEquals(6, IntentJs.u8len("€\udbff") - 0);
        assertEquals(4, IntentJs.u8len("😀"));
        assertEquals(6, IntentJs.u8len("\ud83d\ud83d"));
    }

    // ---- ActionSchema.verify answers an internal error with a refusal that carries the cause ----
    static final class BoomMap extends AbstractMap<String, Object> {
        @Override public Set<Entry<String, Object>> entrySet() { throw new IllegalStateException("boom"); }
        @Override public boolean containsKey(Object key) { throw new IllegalStateException("boom"); }
        @Override public Object get(Object key) { throw new IllegalStateException("boom"); }
    }

    @Test void actionSchemaVerifyFailsClosedWithTheCause() throws Exception {
        Map<String, Object> data = K042ActionSchemaTest.data();
        Map<String, Object> ok = null;
        for (Map<String, Object> c : K042ActionSchemaTest.cases("verify")) if ("verify/valid".equals(c.get("name"))) ok = c;
        assertNotNull(ok);
        Object doc = K042ActionSchemaTest.j(ok.get("doc"));
        assertNull(ActionSchema.verify(doc, K042ActionSchemaTest.j(ok.get("keys"))));
        List<Object> keys = new ArrayList<>();
        keys.add(new BoomMap());
        assertEquals("schema verification error: boom", ActionSchema.verify(doc, keys));
        assertNotNull(data);
    }

    // ---- IntentV2.contextError: the policy members are optional ----
    private static String ctxErr(Object json) { return IntentV2.contextError(IntentV2.Context.fromJson(json)); }

    @Test void policyMembersAreOptionalAndTyped() {
        assertNull(ctxErr(map("policy", map("schema", map()))));
        assertNull(ctxErr(map("policy", map("session", map()))));
        assertNull(ctxErr(map("policy", map("acc", map()))));
        assertNull(ctxErr(map("policy", map("map", map()))));
        assertNull(ctxErr(map("policy", map("schema", map("closed_world", true)))));
        assertEquals("policy.schema.closed_world must be a boolean", ctxErr(map("policy", map("schema", map("closed_world", "x")))));
        assertEquals("policy.schema.closed_world must be a boolean", ctxErr(map("policy", map("schema", map("closed_world", (Object) null)))));
        assertEquals("policy.session.require must be a boolean", ctxErr(map("policy", map("session", map("require", "x")))));
        assertEquals("policy.map.require must be a boolean", ctxErr(map("policy", map("map", map("require", (Object) null)))));
        assertEquals("policy.acc.max_receipt_age_s must be a non-negative safe integer", ctxErr(map("policy", map("acc", map("max_receipt_age_s", "x")))));
        assertEquals("policy.acc.max_keyset_age_s must be a non-negative safe integer", ctxErr(map("policy", map("acc", map("max_keyset_age_s", new Json.Num("-1"))))));
        assertNull(ctxErr(map("policy", map("acc", map("max_receipt_age_s", new Json.Num("0"), "max_keyset_age_s", new Json.Num("5"))))));
        // optional context members
        assertNull(ctxErr(map("wb", map("artifacts", map()))));
        assertNull(ctxErr(map("wb", map("policy", map()))));
        assertNull(ctxErr(map("wb", map("artifacts", map("offer_set", map())))));
        assertNull(ctxErr(map("layers", map("site", map("predicates", new ArrayList<>())))));
        assertEquals("layers.site must be {predicates: [...]}", ctxErr(map("layers", map("site", "x"))));
        assertEquals("layers.site must be {predicates: [...]}", ctxErr(map("layers", map("site", map()))));
        assertEquals("layers.site must be {predicates: [...]}", ctxErr(map("layers", map("site", map("predicates", map())))));
        for (String k : new String[] {"facts", "labels", "verdicts"})
            assertEquals("wb.artifacts." + k + " must be an array", ctxErr(map("wb", map("artifacts", map(k, "x")))));
        assertEquals("wb.artifacts.offer_set must be an object", ctxErr(map("wb", map("artifacts", map("offer_set", new ArrayList<>())))));
        assertEquals("wb.policy.world / provenance must be objects", ctxErr(map("wb", map("policy", map("world", "x")))));
        assertEquals("wb.policy.world / provenance must be objects", ctxErr(map("wb", map("policy", map("provenance", "x")))));
        assertEquals("wb.policy.classifiers must be an array", ctxErr(map("wb", map("policy", map("classifiers", map())))));
        assertEquals("wb.artifacts must be an object", ctxErr(map("wb", map("artifacts", "x"))));
        assertEquals("wb.policy must be an object", ctxErr(map("wb", map("policy", "x"))));
        for (String k : new String[] {"schema", "session", "acc"}) assertEquals(k + " must be an object", ctxErr(map(k, "x")));
        assertEquals("params must be an object", ctxErr(map("params", "x")));
        assertEquals("map must be an object", ctxErr(map("map", "x")));
        assertEquals("map: unknown member 'zz'", ctxErr(map("map", map("zz", 1L))));
        assertEquals("policy: unknown member 'zz'", ctxErr(map("policy", map("zz", 1L))));
        assertEquals("layers: unknown member 'zz'", ctxErr(map("layers", map("zz", map("predicates", new ArrayList<>())))));
        assertNull(ctxErr(map("schema", map())));
    }
}
