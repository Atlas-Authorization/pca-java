package net.atlasauth.pca;

import java.util.List;
import net.atlasauth.pca.ciba.Ciba;
import net.atlasauth.pca.dpop.Dpop;
import net.atlasauth.pca.oauth.WhatwgUrl;
import org.junit.jupiter.api.Test;

/** The host parsers' domain-to-ASCII (UTS 46) replayed against the reference's URL parser: IDN mapping, validity, bidi, joiners, punycode, forbidden characters. */
class IdnaDiffTest {
    private static final String M = "ref-idna";

    @Test void whatwgUrlHost() throws Exception {
        OracleCases.each(M, "urlHost", a -> {
            WhatwgUrl u = WhatwgUrl.parse((String) a.get(0));
            if (u == null) throw new IllegalArgumentException("Invalid URL");
            return u.host;
        });
    }

    @Test void dpopUrlHost() throws Exception { OracleCases.each(M, "urlHost", (List<?> a) -> Dpop.urlHost((String) a.get(0))); }

    @Test void cibaDomainToAscii() throws Exception { OracleCases.each(M, "domainToAscii", a -> Ciba.domainToAscii((String) a.get(0))); }
}
