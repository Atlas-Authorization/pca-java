package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/** The end-of-source context window bound of V8's unexpected-token message (expected texts from Node's JSON.parse). */
public class AttestV8JsonK05bKillTest {
    @Test
    void contextWindowAtTheEnd() {
        // token at n - 10: the end form (no trailing ...)
        assertEquals("Unexpected token 'x', ...\"1,1,1,1,1,x,1,1,1,1]\" is not valid JSON", AttestV8Json.v8JsonError("[1,1,1,1,1,x,1,1,1,1]"));
        // token at n - 11: still the surrounding form
        assertEquals("Unexpected token 'x', ...\"1,1,1,1,1,x,1,1,1,1 \"... is not valid JSON", AttestV8Json.v8JsonError("[1,1,1,1,1,x,1,1,1,1 ]"));
        assertEquals("Unexpected token 'x', ...\"1,1,1,1,1,x,1,1,1,1,\"... is not valid JSON", AttestV8Json.v8JsonError("[1,1,1,1,1,x,1,1,1,1,1]"));
    }
}
