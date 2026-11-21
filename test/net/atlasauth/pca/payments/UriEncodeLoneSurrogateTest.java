package net.atlasauth.pca.payments;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import net.atlasauth.pca.Budgets;
import org.junit.jupiter.api.Test;

/** encodeURIComponent throws (URIError) on a lone surrogate: two scope ids or token refs must never share one percent-encoded key. */
public class UriEncodeLoneSurrogateTest {
    @Test
    void budgetScopeKeyRefusesALoneSurrogate() {
        assertThrows(IllegalArgumentException.class, () -> Budgets.scopeKey("principal", "a\uD800b"));
        assertThrows(IllegalArgumentException.class, () -> Budgets.scopeKey("principal", "a\uDC00b"));
        assertEquals("principal/a%F0%9F%98%80", Budgets.scopeKey("principal", "a😀"));
    }

    @Test
    void networkTokenRefEncodingRefusesALoneSurrogate() {
        assertThrows(IllegalArgumentException.class, () -> NetworkToken.encodeUriComponent("tok\uD800"));
        assertThrows(IllegalArgumentException.class, () -> NetworkToken.encodeUriComponent("\uDFFFtok"));
        assertEquals("tok%20%C3%A9", NetworkToken.encodeUriComponent("tok é"));
    }
}
