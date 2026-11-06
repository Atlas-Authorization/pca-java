package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

/** 0.5 mutation kills for {@link LessNative}: the signature-length rule and the total, never-throwing verify. */
public class LessNativeK05KillTest {
    @Test void signatureLengths() {
        int[] yes = {1153, 1169, 1313, 1329};
        int[] no = {0, -16, 1137, 1152, 1154, 1328, 1330, 1345, 1361};
        for (int n : yes) assertEquals(true, LessNative.sigLenOk(n), "len " + n);
        for (int n : no) assertEquals(false, LessNative.sigLenOk(n), "len " + n);
    }

    @Test void verifyIsTotal() {
        byte[] pk = new byte[LessNative.PUBLIC_KEY_BYTES], sig = new byte[LessNative.SIGNATURE_MAX_BYTES], msg = {1};
        assertFalse(LessNative.verify(null, msg, sig));
        assertFalse(LessNative.verify(pk, null, sig));
        assertFalse(LessNative.verify(pk, msg, null));
        assertFalse(LessNative.verify(new byte[1], msg, sig));
        assertFalse(LessNative.verify(pk, msg, new byte[1330]));
        assertFalse(LessNative.verify(pk, msg, sig)); // an all-zero key and signature never verify
        assertFalse(LessNative.verify(pk, new byte[0], sig));
    }
}
