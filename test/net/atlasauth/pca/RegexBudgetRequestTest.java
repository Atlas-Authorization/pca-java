package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** The request layer of the regex work budget, the ambient provider and the bounded per-source compiled-pattern cache. */
public class RegexBudgetRequestTest {
    @Test void documentBudgetCapsEvaluations() {
        SafeRegex.Budget b = new SafeRegex.Budget();
        for (int i = 0; i < SafeRegex.MAX_REGEX_EVALUATIONS_PER_DOCUMENT; i++) assertTrue(b.charge("a+", 3), "charge " + i);
        assertFalse(b.charge("a+", 3));
        assertFalse(b.charge("b", 1), "a poisoned budget refuses every later pattern");
        assertEquals(2, b.refusals());
    }

    @Test void requestBudgetAllowsScaleDocuments() {
        SafeRegex.Budget req = SafeRegex.Budget.request("client-1");
        int docs = SafeRegex.REGEX_REQUEST_SCALE;
        req.run(() -> {
            for (int d = 0; d < docs; d++) {
                final int doc = d;
                assertTrue(SafeRegex.withBudget(() -> {
                    boolean ok = true;
                    for (int i = 0; i < SafeRegex.MAX_REGEX_EVALUATIONS_PER_DOCUMENT; i++) ok &= SafeRegex.charge("x" + doc, 2);
                    return ok;
                }), "document " + d);
            }
            // the request is spent: a fresh document inside it is refused on its first charge
            assertFalse(SafeRegex.withBudget(() -> SafeRegex.charge("y", 1)));
            return null;
        });
        assertEquals(0, SafeRegex.refusals(), "no scope is open afterwards");
        assertEquals(1, req.refusals());
        assertSame(null, req.parentBudget());
    }

    @Test void ambientProviderChainsDocumentsToTheRequest() {
        SafeRegex.Budget req = SafeRegex.Budget.request(null);
        SafeRegex.setRegexBudgetProvider(() -> req);
        try {
            for (int d = 0; d < SafeRegex.REGEX_REQUEST_SCALE; d++) {
                assertTrue(SafeRegex.withBudget(() -> {
                    boolean ok = true;
                    for (int i = 0; i < SafeRegex.MAX_REGEX_EVALUATIONS_PER_DOCUMENT; i++) ok &= SafeRegex.charge("q", 1);
                    return ok;
                }));
            }
            assertFalse(SafeRegex.withBudget(() -> SafeRegex.charge("q", 1)));
        } finally {
            SafeRegex.setRegexBudgetProvider(null);
        }
        assertTrue(SafeRegex.withBudget(() -> SafeRegex.charge("q", 1)), "uninstalled: a fresh document is back to its own caps");
    }

    @Test void aThrowingProviderIsNoBudget() {
        SafeRegex.setRegexBudgetProvider(() -> { throw new IllegalStateException("boom"); });
        try {
            assertTrue(SafeRegex.withBudget(() -> SafeRegex.charge("z", 1)));
        } finally {
            SafeRegex.setRegexBudgetProvider(null);
        }
    }

    @Test void cacheReturnsTheSameProgramAndKeepsRefusals() {
        SafeRegex.Compiled a = SafeRegex.compileSafeRegexCached("ab+c");
        assertNotNull(a);
        assertSame(a, SafeRegex.compileSafeRegexCached("ab+c"));
        assertTrue(SafeRegex.regexCacheHas("ab+c"));
        assertNull(SafeRegex.compileSafeRegexCached("(a)\\1")); // a backreference is outside the subset; the verdict is cached too
        assertTrue(SafeRegex.regexCacheHas("(a)\\1"));
        assertNull(SafeRegex.compileSafeRegexCached(null));
    }

    @Test void oneSourceCannotFlushAnotherSourcesEntries() {
        SafeRegex.Budget mine = SafeRegex.Budget.request("tenant-a"), other = SafeRegex.Budget.request("tenant-b");
        other.run(() -> SafeRegex.compileSafeRegexCached("keep-me-[0-9]+"));
        mine.run(() -> {
            for (int i = 0; i < SafeRegex.REGEX_CACHE_MAX_PER_SOURCE + 20; i++) SafeRegex.compileSafeRegexCached("flood" + i + "x");
            return null;
        });
        assertTrue(SafeRegex.regexCacheHas("keep-me-[0-9]+"), "another tenant's pattern survives a flood");
        assertFalse(SafeRegex.regexCacheHas("flood0x"), "the flooding source replaced its OWN oldest entries");
        assertTrue(SafeRegex.regexCacheHas("flood" + (SafeRegex.REGEX_CACHE_MAX_PER_SOURCE + 19) + "x"));
    }
}
