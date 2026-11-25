package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Beacons.verify: hybrid-suite beacons under a pinned post-quantum key, the window field typing, and the hostile-input arms. */
class BeaconsPitKillTest {
    static final long ISSUED = 1_800_000_000_000L - 120_000L + 12_345L; // not a multiple of the epoch length
    static final long NOW = ISSUED + 60_000L;
    static final String HYBRID_ALG = "hybrid-ed25519-ml-dsa-65";

    static byte[] fill(int b) {
        byte[] x = new byte[32];
        Arrays.fill(x, (byte) b);
        return x;
    }

    static Keys.SuiteKey hybrid(int edSeed, int pqSeed) {
        return Keys.suite(HYBRID_ALG, Keys.edFromSeed(fill(edSeed)), Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(pqSeed)));
    }

    static Map<String, Object> fields(String issuer, long seq, long issued, long notAfter) {
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("v", IntentJs.ofLong(2));
        b.put("instance", "inst");
        b.put("scope", "*");
        b.put("epoch", IntentJs.ofLong(Math.floorDiv(issued, Beacons.EPOCH_MS)));
        b.put("seq", IntentJs.ofLong(seq));
        b.put("issued_at", IntentJs.ofLong(issued));
        b.put("not_after", IntentJs.ofLong(notAfter));
        b.put("issuer", issuer);
        return b;
    }

    /** Sign {@code b} (the bound fields) with {@code k}; {@code pqPk} is the key field bound into the message and shipped. */
    static Map<String, Object> sign(Map<String, Object> b, Keys.SuiteKey k, String pqPk) {
        boolean pq = !k.alg.equals("ed25519");
        Map<String, Object> bound = IntentJs.bindSuiteFields(b, pq ? k.alg : null, pq, pqPk, pqPk != null);
        byte[] msg = Pca.concat(Beacons.LIVENESS_DOMAIN.getBytes(StandardCharsets.UTF_8), IntentJs.canonBytes(bound));
        String[] s = k.sign(msg);
        Map<String, Object> out = new LinkedHashMap<>(b);
        if (pq) {
            out.put("alg", k.alg);
            if (pqPk != null) out.put("pq_pk", pqPk);
        }
        out.put("sig", s[0]);
        if (s[1] != null) out.put("pq_sig", s[1]);
        return out;
    }

    static String verify(Object beacon, String issuer, Map<String, Object> pins) {
        return Beacons.verify(beacon, List.of(issuer), NOW, "inst", null, pins);
    }

    @Test void aHybridBeaconVerifiesOnlyUnderTheVerifiersPinnedPostQuantumKey() {
        Keys.SuiteKey k = hybrid(7, 8);
        Map<String, Object> pins = Keys.pqPin(k);
        Map<String, Object> ok = sign(fields(k.id(), 5, ISSUED, ISSUED + 300_000L), k, k.pqPk());
        assertNull(verify(ok, k.id(), pins));
        assertEquals("bad signature", verify(ok, k.id(), null), "no pin: the artifact's own key is never enough");
        // a tampered body, a dropped half, a different pq key shipped than the one bound / pinned
        Map<String, Object> tampered = new LinkedHashMap<>(ok);
        tampered.put("seq", IntentJs.ofLong(6));
        assertEquals("bad signature", verify(tampered, k.id(), pins));
        Map<String, Object> noPqSig = new LinkedHashMap<>(ok);
        noPqSig.remove("pq_sig");
        assertEquals("bad signature", verify(noPqSig, k.id(), pins));
        Map<String, Object> noPk = new LinkedHashMap<>(ok);
        noPk.remove("pq_pk");
        assertEquals("bad signature", verify(noPk, k.id(), pins));
        // signed by the pinned pq key but over a body that names ANOTHER pq key: the artifact key must match the pin
        String otherPk = Keys.pqFromSeed(Pq.Prim.ML_DSA_65, fill(9)).pkB64u();
        Map<String, Object> foreign = sign(fields(k.id(), 5, ISSUED, ISSUED + 300_000L), k, otherPk);
        assertEquals("bad signature", verify(foreign, k.id(), pins));
        // a hybrid alg whose signed body omitted alg / pq_pk is not the signed body
        Map<String, Object> unbound = sign(fields(k.id(), 5, ISSUED, ISSUED + 300_000L), Keys.suite("ed25519", k.ed, null), null);
        unbound.put("alg", HYBRID_ALG);
        unbound.put("pq_pk", k.pqPk());
        unbound.put("pq_sig", ok.get("pq_sig"));
        assertEquals("bad signature", verify(unbound, k.id(), pins));
        // an explicit ed25519 alg verifies like an absent one
        Keys.SuiteKey ed = Keys.ed25519(Keys.edFromSeed(fill(3)));
        Map<String, Object> plain = sign(fields(ed.id(), 5, ISSUED, ISSUED + 300_000L), ed, null);
        assertNull(verify(plain, ed.id(), null));
        plain.put("alg", "ed25519");
        assertNull(verify(plain, ed.id(), null));
        plain.put("alg", 7L);
        assertEquals("malformed beacon", verify(plain, ed.id(), null));
    }

    @Test void theWindowFieldsMustBeIntegralNumbersAndSeqZeroIsValid() {
        Keys.SuiteKey ed = Keys.ed25519(Keys.edFromSeed(fill(3)));
        Map<String, Object> f = fields(ed.id(), 0, ISSUED, ISSUED + 300_000L);
        assertNull(verify(sign(f, ed, null), ed.id(), null), "seq 0 is the first beacon");
        for (String key : new String[] {"epoch", "seq", "issued_at", "not_after"}) {
            for (Object bad : new Object[] {new Json.Num("0.4"), new Json.Num("1.5"), "7"}) {
                Map<String, Object> g = new LinkedHashMap<>(f);
                g.put(key, bad);
                assertEquals("malformed window", verify(sign(g, ed, null), ed.id(), null), key + "=" + bad);
            }
        }
        // a missing signed field is malformed, whatever the signature says
        for (String key : new String[] {"epoch", "seq", "issued_at", "not_after", "scope"}) {
            Map<String, Object> g = sign(f, ed, null);
            g.remove(key);
            assertEquals("malformed beacon", verify(g, ed.id(), null), key);
        }
        // the epoch is the floor of issued_at / 60000: an issued_at off the boundary still verifies with the floor
        assertNull(verify(sign(fields(ed.id(), 3, ISSUED, ISSUED + 300_000L), ed, null), ed.id(), null));
    }

    /** A value that equals anything but is not a String. */
    static final class Chameleon {
        @Override public boolean equals(Object o) { return true; }
        @Override public int hashCode() { return 1; }
    }

    @Test void aNonStringInstanceOrIssuerIsRefusedByTypeNotByEquality() {
        Keys.SuiteKey ed = Keys.ed25519(Keys.edFromSeed(fill(3)));
        Map<String, Object> g = sign(fields(ed.id(), 5, ISSUED, ISSUED + 300_000L), ed, null);
        g.put("instance", new Chameleon());
        assertEquals("wrong instance", Beacons.verify(g, List.of(ed.id()), NOW, "inst", null, null));
        Map<String, Object> h = sign(fields(ed.id(), 5, ISSUED, ISSUED + 300_000L), ed, null);
        h.put("issuer", new Chameleon());
        List<String> issuers = new ArrayList<>(List.of(ed.id()));
        assertEquals("issuer not pinned", Beacons.verify(h, issuers, NOW, "inst", null, null));
    }

    @Test void aMapThatThrowsIsMalformedNotAnException() {
        Map<String, Object> boom = new HashMap<String, Object>() {
            @Override public Object get(Object k) { throw new IllegalStateException("boom"); }
        };
        assertEquals("malformed beacon", Beacons.verify(boom, List.of("i"), NOW, "inst", null, null));
        assertEquals("malformed beacon", Beacons.verify("x", List.of("i"), NOW, "inst", null, null));
        assertEquals("malformed beacon", Beacons.verify(null, List.of("i"), NOW, "inst", null, null));
    }
}
