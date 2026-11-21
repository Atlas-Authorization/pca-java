package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Round 2 (tag DA): inputs on which a mutant of a parser terminates with another result (instead of looping), asserted on the
 * smallest documents that show it. Every input here finishes in microseconds on the unmutated code.
 */
public class K05R6DAParseTest {
    // ---- Json: \\u escapes take ASCII hex digits only ----

    @Test void hexEscapesAreAsciiOnly() {
        assertEquals("A", Json.parse("\"\\u0041\""));
        assertEquals("a", Json.parseLenient("\"\\u0061\""));
        for (String h : new String[] {"\uFF10\uFF10\uFF10\uFF10", "\uFF41\uFF41\uFF41\uFF41", "\uFF21\uFF21\uFF21\uFF21"}) {
            String doc = "\"\\u" + h + "\"";
            assertThrows(IllegalArgumentException.class, () -> Json.parse(doc), "strict " + h);
            assertThrows(IllegalArgumentException.class, () -> Json.parseLenient(doc), "lenient " + h);
        }
        assertThrows(IllegalArgumentException.class, () -> Json.parse("\"\\u00g0\""));
    }

    // ---- AttestV8Json: the comma of an array is consumed, not backed over ----

    @Test void anArrayOfStringsIsValid() {
        assertEquals("", AttestV8Json.v8JsonError("[\"a\",\"b\"]"));
        assertEquals("", AttestV8Json.v8JsonError("[\"a\", \"b\" ,\"c\"]"));
    }

    // ---- AttestXml: text, comment and processing-instruction edges ----

    static String xmlError(String s) {
        AttestException e = assertThrows(AttestException.class, () -> AttestXml.parseXml(s), s);
        return e.getMessage();
    }

    @Test void textOutsideTheDocumentElementIsRefusedAsText() {
        assertTrue(xmlError("x").contains("text outside the document element"));
    }

    @Test void aCommentBeforeTheRootIsNotedAndSkipped() {
        assertDoesNotThrow(() -> AttestXml.parseXml("<!--x--><a/>"));
    }

    @Test void anUnterminatedCommentIsRefusedAsSuch() {
        assertTrue(xmlError("<!--x").contains("unterminated comment"));
    }

    @Test void anUnterminatedProcessingInstructionIsRefusedAsSuch() {
        assertTrue(xmlError("<?x").contains("unterminated processing instruction"));
    }

    // ---- SafeRegex ----

    @Test void aDotIsAnAtom() {
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch(".", "x"));
        assertEquals(Boolean.FALSE, SafeRegex.fullMatch(".", "\n"));
    }

    @Test void plainCharactersAndClassesPassTheGuard() {
        assertTrue(SafeRegex.isSafeSource("a"));
        assertTrue(SafeRegex.isSafeSource("[a]"));
        assertTrue(SafeRegex.isSafeSource("[a-c]"));
    }

    @Test void unsupportedEscapesAreRefused() {
        assertNull(SafeRegex.fullMatch("\\Q", "Q"));
        assertNull(SafeRegex.fullMatch("\\q", "q"));
        assertNull(SafeRegex.fullMatch("\\5", "5"));
        assertNull(SafeRegex.fullMatch("\\_", "_"));
        assertEquals(Boolean.TRUE, SafeRegex.fullMatch("\\.", "."));
    }
}
