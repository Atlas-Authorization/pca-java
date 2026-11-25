package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

/** A lone surrogate encodes as U+FFFD (EF BF BD), as the reference's TextEncoder writes it, not as '?'. */
public class Utf8LoneSurrogateTest {
    private static final byte[] FFFD = {(byte) 0xEF, (byte) 0xBF, (byte) 0xBD};

    @Test
    void loneHighAndLowSurrogateEncodeAsFffd() {
        assertArrayEquals(new byte[] {'a', FFFD[0], FFFD[1], FFFD[2], 'b'}, Json.utf8("a\uD800b"));
        assertArrayEquals(new byte[] {'a', FFFD[0], FFFD[1], FFFD[2], 'b'}, Json.utf8("a\uDC00b"));
        assertArrayEquals(new byte[] {FFFD[0], FFFD[1], FFFD[2], FFFD[0], FFFD[1], FFFD[2]}, Json.utf8("\uDC00\uD800"));
    }

    @Test
    void aValidPairStaysOneFourByteCodePoint() {
        assertArrayEquals(new byte[] {(byte) 0xF0, (byte) 0x9F, (byte) 0x98, (byte) 0x80}, Json.utf8("😀"));
    }
}
