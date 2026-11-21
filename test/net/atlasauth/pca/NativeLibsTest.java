package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class NativeLibsTest {
    @Test
    void explicitOverrideWinsOverEverything() {
        assertEquals("/x/libfoo.so", NativeLibs.resolve(NativeLibsTest.class, "foo", null, "", "/x/libfoo.so", "/y/other"));
    }

    @Test
    void firstNonEmptyOverrideWins() {
        assertEquals("/a", NativeLibs.resolve(NativeLibsTest.class, "foo", "/a", "/b"));
    }

    @Test
    void noOverrideAndNothingPackagedFallsThroughToSystemLookup() {
        assertNull(NativeLibs.resolve(NativeLibsTest.class, "no_such_lib"));
    }

    @Test
    void platformNameIsOsDashArch() {
        assertTrue(NativeLibs.platform().matches("(linux|macos|windows)-[a-z0-9_]+"), NativeLibs.platform());
    }
}
