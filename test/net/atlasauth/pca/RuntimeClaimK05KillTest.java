package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * 0.5 mutation kills for {@link RuntimeClaim#verifiedClass}: claims signed here (a fixed-seed attestor), each varied in one member
 * and re-signed, so the one check under test decides. Every expectation is the exact class (or "none").
 */
public class RuntimeClaimK05KillTest {
    static final Keys.EdKey A = Keys.edFromSeed(fill(32, 5));
    static final Object DROP = new Object();
    static final List<String> PINNED = List.of(A.id());
    static final List<String> EV = List.of("ev");

    static byte[] fill(int n, int v) { byte[] b = new byte[n]; Arrays.fill(b, (byte) v); return b; }
    static Json.Num n(long v) { return IntentJs.ofLong(v); }
    static String chars(int n) { char[] c = new char[n]; Arrays.fill(c, 'd'); return new String(c); }

    /** The base claim (os_confined, "pd", "ev", iat 100, exp 200, attestor A) with overrides, signed by A over the result. */
    static Map<String, Object> claim(Object... kv) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("v", n(1));
        c.put("class", "os_confined");
        c.put("passport_digest", "pd");
        c.put("evidence_digest", "ev");
        c.put("iat", n(100));
        c.put("exp", n(200));
        c.put("attestor", A.id());
        for (int i = 0; i + 1 < kv.length; i += 2) {
            if (kv[i + 1] == DROP) c.remove((String) kv[i]);
            else c.put((String) kv[i], kv[i + 1]);
        }
        String sig;
        try {
            sig = Keys.b64u(A.sign(Pca.concat(RuntimeClaim.DOMAIN.getBytes(StandardCharsets.UTF_8), Pca.canonBytes(c))));
        } catch (RuntimeException e) {
            sig = Keys.b64u(new byte[64]); // not strictly canonical: cannot be signed
        }
        c.put("sig", sig);
        return c;
    }

    static String at(Object claim, Object now) { return RuntimeClaim.verifiedClass(claim, PINNED, "pd", EV, now); }
    static String of(Object claim) { return at(claim, n(150)); }

    @Test void validClaimsYieldTheirClass() {
        for (String cls : new String[] {"none", "os_confined", "egress_default_deny", "wasi_no_ambient"}) assertEquals(cls, of(claim("class", cls)));
        assertEquals("os_confined", at(claim(), n(100))); // iat == now
        assertEquals("os_confined", at(claim(), n(199)));
        assertEquals("none", at(claim(), n(200))); // exp == now
        assertEquals("none", at(claim(), n(99)));
        assertEquals("os_confined", at(claim("iat", n(0)), n(0)));
        assertEquals("os_confined", at(claim("iat", n(0)), n(150)));
    }

    @Test void shapeAndVersion() {
        assertEquals("none", of(null));
        assertEquals("none", of("x"));
        assertEquals("none", of(List.of()));
        assertEquals("none", of(claim("x", n(1))));
        assertEquals("none", of(claim("iat", DROP)));
        assertEquals("none", of(claim("v", n(2))));
        assertEquals("none", of(claim("v", n(0))));
        assertEquals("none", of(claim("v", "1")));
        assertEquals("none", of(claim("v", 1.0d)));
        assertEquals("none", of(claim("v", Json.parseLenient("1.5"))));
        assertEquals("none", of(claim("class", "bogus")));
        assertEquals("none", of(claim("class", n(5))));
        assertEquals("none", of(claim("class", null)));
    }

    @Test void digests() {
        String d128 = chars(128), d129 = chars(129);
        assertEquals("os_confined", RuntimeClaim.verifiedClass(claim("passport_digest", d128), PINNED, d128, EV, n(150)));
        assertEquals("none", RuntimeClaim.verifiedClass(claim("passport_digest", d129), PINNED, d129, EV, n(150)));
        assertEquals("none", RuntimeClaim.verifiedClass(claim("passport_digest", ""), PINNED, "", EV, n(150)));
        assertEquals("none", of(claim("passport_digest", "other")));
        assertEquals("os_confined", RuntimeClaim.verifiedClass(claim("evidence_digest", d128), PINNED, "pd", List.of(d128), n(150)));
        assertEquals("none", RuntimeClaim.verifiedClass(claim("evidence_digest", d129), PINNED, "pd", List.of(d129), n(150)));
        assertEquals("none", RuntimeClaim.verifiedClass(claim("evidence_digest", ""), PINNED, "pd", List.of(""), n(150)));
        assertEquals("none", of(claim("evidence_digest", "unverified")));
    }

    @Test void attestor() {
        assertEquals("none", RuntimeClaim.verifiedClass(claim(), List.of(), "pd", EV, n(150)));
        assertEquals("none", of(claim("attestor", Keys.edFromSeed(fill(32, 6)).id())));
        String long129 = chars(129);
        assertEquals("none", RuntimeClaim.verifiedClass(claim("attestor", long129), List.of(long129), "pd", EV, n(150)));
        assertEquals("none", RuntimeClaim.verifiedClass(claim("attestor", ""), List.of(""), "pd", EV, n(150)));
        assertEquals("none", RuntimeClaim.verifiedClass(claim("attestor", n(5)), PINNED, "pd", EV, n(150)));
        Map<String, Object> c = claim();
        c.put("sig", Keys.b64u(new byte[64]));
        assertEquals("none", of(c));
    }

    @Test void times() {
        assertEquals("none", of(claim("iat", n(-1))));
        assertEquals("none", of(claim("iat", "100")));
        assertEquals("none", of(claim("exp", n(-1))));
        assertEquals("none", of(claim("exp", "200")));
        assertEquals("none", of(claim("exp", Json.parseLenient("2e2"))));
        assertEquals("none", of(claim("exp", 9007199254740993L)));
        assertEquals("none", at(claim(), 150.0d));
        assertEquals("none", at(claim(), "150"));
        assertEquals("none", at(claim(), null));
        assertEquals("none", at(claim("iat", n(0)), n(-1)));
        assertEquals("os_confined", at(claim(), 150L));
    }

    /** A thrown precondition (a null pinned list) is "none", never an exception. */
    @Test void totalOverCallerArguments() {
        assertEquals("none", RuntimeClaim.verifiedClass(claim(), null, "pd", EV, n(150)));
        assertEquals("none", RuntimeClaim.verifiedClass(claim(), PINNED, null, EV, n(150)));
        assertEquals("none", RuntimeClaim.verifiedClass(claim(), PINNED, "pd", null, n(150)));
    }
}
