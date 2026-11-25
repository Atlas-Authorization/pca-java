package net.atlasauth.pca.oauth;

import com.ibm.icu.text.IDNA;
import java.util.EnumSet;
import java.util.Set;

/**
 * The URL standard's "domain to ASCII" (UTS 46 processing with CheckBidi, CheckJoiners and non-transitional processing; no STD3 rules, no hyphen check,
 * no DNS-length verification), over ICU4J's UTS 46 implementation: the reference reads hosts with WHATWG URL, and {@code java.net.IDN} is IDNA2003
 * (different mapping table, different validity rules), so it is not a substitute.
 */
public final class HostIdna {
    private HostIdna() {}

    private static final IDNA UTS46 = IDNA.getUTS46Instance(IDNA.CHECK_BIDI | IDNA.CHECK_CONTEXTJ | IDNA.NONTRANSITIONAL_TO_ASCII);

    /** What the URL standard does not treat as a failure when it is not strict: empty or over-long labels and hyphen placement. */
    private static final Set<IDNA.Error> TOLERATED = EnumSet.of(IDNA.Error.EMPTY_LABEL, IDNA.Error.LABEL_TOO_LONG, IDNA.Error.DOMAIN_NAME_TOO_LONG,
        IDNA.Error.LEADING_HYPHEN, IDNA.Error.TRAILING_HYPHEN, IDNA.Error.HYPHEN_3_4);

    /**
     * True when the domain needs UTS 46 processing: it has a non-ASCII character. An all-ASCII host is lower-cased only, as the reference's URL parser does
     * (it does not validate an {@code xn--} label of an ASCII host, so neither do we).
     */
    public static boolean needsProcessing(String domain) {
        for (int i = 0; i < domain.length(); i++) if (domain.charAt(i) > 0x7f) return true;
        return false;
    }

    /** The ASCII form of a domain, or null when UTS 46 refuses it (or it comes out empty). The input is mapped here: do not lower-case or normalise it first. */
    public static String toAscii(String domain) {
        StringBuilder out = new StringBuilder();
        IDNA.Info info = new IDNA.Info();
        UTS46.nameToASCII(domain, out, info);
        for (IDNA.Error e : info.getErrors()) if (!TOLERATED.contains(e)) return null;
        return out.length() == 0 ? null : out.toString();
    }
}
