package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/** Null / length guards of the raw post-quantum verify entry points. */
class K042PqGapTest {
    @Test void pqVerifyRefusesNullsAndWrongLengthsWithoutThrowing() {
        Pq.Prim p = Pq.Prim.ML_DSA_65;
        byte[] pk = new byte[p.pkBytes], msg = new byte[] {1, 2, 3};
        byte[] sig = new byte[3309];
        assertFalse(Pq.pqVerify(null, pk, msg, sig));
        assertFalse(Pq.pqVerify(p, null, msg, sig));
        assertFalse(Pq.pqVerify(p, pk, null, sig));
        assertFalse(Pq.pqVerify(p, pk, msg, null));
        assertFalse(Pq.pqVerify(p, new byte[p.pkBytes - 1], msg, sig));
        assertFalse(Pq.pqVerify(p, new byte[p.pkBytes + 1], msg, sig));
        assertFalse(Pq.pqVerify(p, pk, msg, new byte[3308]));
        assertFalse(Pq.pqVerify(p, pk, msg, new byte[3310]));
        assertFalse(Pq.pqVerify(p, pk, msg, sig));   // right sizes, not a signature
        for (Pq.Prim q : Pq.Prim.values()) {
            if (q == Pq.Prim.LESS_CAT1) continue;
            assertFalse(Pq.pqVerify(q, new byte[q.pkBytes], new byte[0], new byte[1]), q.name());
        }
    }

    @Test void pqVerifyB64uRefusesUndecodableInputs() {
        Pq.Prim p = Pq.Prim.ML_DSA_65;
        String pk = "A".repeat(2603), sg = "A".repeat(4412);   // canonical-length base64url of 1952 / 3309 zero bytes
        assertFalse(Pq.pqVerifyB64u(p, null, new byte[1], sg));
        assertFalse(Pq.pqVerifyB64u(p, pk, new byte[1], null));
        assertFalse(Pq.pqVerifyB64u(p, 5, new byte[1], sg));
        assertFalse(Pq.pqVerifyB64u(p, pk, new byte[1], 5));
        assertFalse(Pq.pqVerifyB64u(p, "!!!", new byte[1], sg));
        assertFalse(Pq.pqVerifyB64u(p, pk, new byte[1], "AAAA"));   // a signature of the wrong length
        assertFalse(Pq.pqVerifyB64u(p, pk, new byte[1], sg));
    }
}
