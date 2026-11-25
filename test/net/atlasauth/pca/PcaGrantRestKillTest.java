package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** 0.5 mutation kills for {@link PcaGrant}: the https URL rule at every boundary and the exact parse / check results (code, details, index). */
public class PcaGrantRestKillTest {

    static String url(int len) {
        StringBuilder sb = new StringBuilder("https://a.b/");
        while (sb.length() < len) sb.append('x');
        return sb.toString();
    }

    @Test void httpsUrlBoundaries() {
        assertFalse(PcaGrant.isHttpsUrl(null));
        assertFalse(PcaGrant.isHttpsUrl(5L));
        assertFalse(PcaGrant.isHttpsUrl(List.of("https://a")));
        assertTrue(PcaGrant.isHttpsUrl("https://a"));
        assertTrue(PcaGrant.isHttpsUrl(url(2048)));
        assertEquals(2048, url(2048).length());
        assertFalse(PcaGrant.isHttpsUrl(url(2049)));
        assertFalse(PcaGrant.isHttpsUrl("http://a"));
        // the character range [0x21, 0x7e], checked from the first character after the scheme
        assertTrue(PcaGrant.isHttpsUrl("https://a!b"));
        assertTrue(PcaGrant.isHttpsUrl("https://!"));
        assertTrue(PcaGrant.isHttpsUrl("https://a~b"));
        assertTrue(PcaGrant.isHttpsUrl("https://~"));
        assertTrue(PcaGrant.isHttpsUrl("https://a\"b"));
        assertFalse(PcaGrant.isHttpsUrl("https:// a"));
        assertFalse(PcaGrant.isHttpsUrl("https://a b"));
        assertFalse(PcaGrant.isHttpsUrl("https://a\u007fb"));
        assertFalse(PcaGrant.isHttpsUrl("https://\u007fb"));
        assertFalse(PcaGrant.isHttpsUrl("https://a\u0080"));
        assertFalse(PcaGrant.isHttpsUrl("https://a\u0000"));
        assertFalse(PcaGrant.isHttpsUrl("https://a#b"));
        assertFalse(PcaGrant.isHttpsUrl("https://a\\b"));
        // the authority runs to the first '/' or '?' and must be non-empty without '@'
        assertFalse(PcaGrant.isHttpsUrl("https://"));
        assertFalse(PcaGrant.isHttpsUrl("https:///x"));
        assertFalse(PcaGrant.isHttpsUrl("https://?x"));
        assertFalse(PcaGrant.isHttpsUrl("https://@host"));
        assertFalse(PcaGrant.isHttpsUrl("https://u@host"));
        assertFalse(PcaGrant.isHttpsUrl("https://host@"));
        assertTrue(PcaGrant.isHttpsUrl("https://host/p@th"));
        assertTrue(PcaGrant.isHttpsUrl("https://host?q=a@b"));
        assertTrue(PcaGrant.isHttpsUrl("https://host/a?q=@"));
        assertFalse(PcaGrant.isHttpsUrl("https://u@host/x"));
        assertFalse(PcaGrant.isHttpsUrl("https://u@host?x"));
    }

    static Map<String, Object> detail(List<String> ids) {
        return Issue.obj("type", PcaGrant.TYPE, "chain_digest", PcaGrant.chainDigest(ids), "chain_len", (long) ids.size());
    }

    @Test void validateChainDigest() {
        Map<String, Object> d = detail(List.of("a"));
        assertNull(PcaGrant.validate(d));
        d.put("chain_digest", 5L);
        assertEquals("bad_chain_digest", PcaGrant.validate(d));
        d.put("chain_digest", List.of(PcaGrant.chainDigest(List.of("a"))));
        assertEquals("bad_chain_digest", PcaGrant.validate(d));
        d.put("chain_digest", null);
        assertEquals("bad_chain_digest", PcaGrant.validate(d));
        d.put("chain_digest", "abc");
        assertEquals("bad_chain_digest", PcaGrant.validate(d));
    }

    static void result(PcaGrant.Result r, String code, Integer details, int index) {
        assertEquals(code, r.code);
        if (details == null) assertNull(r.details); else assertEquals((int) details, r.details.size());
        assertEquals(index, r.index);
    }

    @Test void parseResultsAreExact() {
        result(PcaGrant.parse("x"), "not_an_array", null, -1);
        result(PcaGrant.parse(null), "not_an_array", null, -1);
        List<Object> many = new ArrayList<>();
        for (int i = 0; i < 17; i++) many.add(detail(List.of("a")));
        result(PcaGrant.parse(many), "too_many_details", null, -1);
        result(PcaGrant.parse(new ArrayList<Object>(many.subList(0, 16))), null, 16, -1);
        List<Object> bad = new ArrayList<>();
        bad.add(Issue.obj("x", 1L));
        result(PcaGrant.parse(bad), "bad_entry", null, -1);
        List<Object> invalid = new ArrayList<>();
        invalid.add(Issue.obj("type", PcaGrant.TYPE));
        result(PcaGrant.parse(invalid), "bad_chain_digest", null, -1);
        List<Object> mixed = new ArrayList<>();
        mixed.add(Issue.obj("type", "openid_credential"));
        mixed.add(detail(List.of("a")));
        PcaGrant.Result r = PcaGrant.parse(mixed);
        result(r, null, 1, -1);
        assertSame(mixed.get(1), r.details.get(0));
        result(PcaGrant.parse(new ArrayList<Object>()), null, 0, -1);
    }

    @Test void checkResultsAreExact() {
        List<String> chain = List.of("a", "b");
        List<Map<String, Object>> none = new ArrayList<>();
        result(PcaGrant.check(none, "https://rs", chain, true), "no_detail", null, -1);
        List<Map<String, Object>> one = new ArrayList<>();
        one.add(detail(List.of("a")));
        result(PcaGrant.check(one, "https://rs", chain, false), "proof_required", null, -1);
        result(PcaGrant.check(one, "https://rs", chain, true), null, null, 0);
        List<Map<String, Object>> mism = new ArrayList<>();
        mism.add(detail(List.of("z")));
        result(PcaGrant.check(mism, "https://rs", chain, true), "chain_mismatch", null, -1);
        List<Map<String, Object>> loc = new ArrayList<>();
        Map<String, Object> d = detail(List.of("a", "b"));
        d.put("locations", new ArrayList<Object>(List.of("https://other")));
        loc.add(d);
        result(PcaGrant.check(loc, "https://rs", chain, true), "wrong_location", null, -1);
        loc.add(detail(List.of("a", "b")));
        result(PcaGrant.check(loc, "https://rs", chain, true), null, null, 1);
    }
}
