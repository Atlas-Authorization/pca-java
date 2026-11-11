package net.atlasauth.pca;

import static net.atlasauth.pca.K3K05KillTest.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Round 3 mutation kills for {@link CaveatLang} (derive defs, caveat-lang.ts:619-624) and {@link K3} (a malformed stored authority). */
public class K05R3CaveatK3KillTest {
    static String countDefError(Object... def) {
        Map<String, Object> d = CaveatLangRestKillTest.m(def);
        return CaveatLang.deriveError(CaveatLangRestKillTest.m("type", "derive", "id", "d1", "defs", List.of(d),
            "check", CaveatLangRestKillTest.m("op", "gte", "a", CaveatLangRestKillTest.m("ref", "c"), "b", CaveatLangRestKillTest.m("const", CaveatLangRestKillTest.n(0)))));
    }

    /** The first failing member check of a count def wins. */
    @Test void countDefReportsTheFirstError() {
        Json.Num bad = CaveatLangRestKillTest.n(5), good = CaveatLangRestKillTest.n(1000), zero = CaveatLangRestKillTest.n(0);
        String unknown = "def 'c': unknown member 'count.extra'", window = "def 'c': window_ms out of range", verb = "def 'c': verb must be a non-empty string";
        assertEquals(unknown, countDefError("name", "c", "kind", "count", "window_ms", good, "extra", bad, "verb", bad));
        assertEquals(unknown, countDefError("name", "c", "kind", "count", "window_ms", good, "extra", bad, "resource_prefix", bad));
        assertEquals(window, countDefError("name", "c", "kind", "count", "window_ms", zero, "verb", bad));
        assertEquals(window, countDefError("name", "c", "kind", "count", "window_ms", zero, "resource_prefix", bad));
        assertEquals(verb, countDefError("name", "c", "kind", "count", "window_ms", good, "verb", bad, "resource_prefix", bad));
    }

    /**
     * The authority shape is refused ahead of the status. grant-resource.ts:201-202 shape-checks only the request's authority, so
     * there this input reads not_active; Java keeps the stricter check on the stored authority (K3K05KillTest pins the same order).
     */
    @Test void amendmentOnAMalformedStoredAuthorityIsABadRequest() {
        Map<String, Object> narrow = auth(l("read"), l("doc/a"));
        amendFail(K3.verifyAmendment(grant("status", "revoked", "authority", auth("x", l("a"))), amend("narrow", narrow, "holder", "agent"), true), "bad_request");
    }

    /** As above: grant-resource.ts:247 would read step_up_required. Java refuses the malformed stored authority first. */
    @Test void needApprovalOnAMalformedStoredAuthorityIsABadRequest() {
        needFail(approve(nreq(l(need())), ngrant("authority", auth("x", l("a"))), l(need()), false), "bad_request");
        needFail(approve(nreq(l(need())), ngrant("authority", auth("x", l("a"))), l(need("verb", "refund")), true), "bad_request");
    }
}
