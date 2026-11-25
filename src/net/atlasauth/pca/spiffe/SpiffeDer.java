package net.atlasauth.pca.spiffe;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.Json;

/**
 * Minimal, bounds-checked DER reader for the X.509 extensions the SPIFFE X.509-SVID rules depend on (basicConstraints, keyUsage,
 * subjectAltName) plus the list of critical extensions. No cryptography: signatures, names and validity are checked elsewhere.
 * Malformed DER throws {@link IllegalArgumentException}.
 */
public final class SpiffeDer {
    private SpiffeDer() {}

    private static final class Tlv {
        final int tag, start, end;
        Tlv(int tag, int start, int end) { this.tag = tag; this.start = start; this.end = end; }
    }

    private static Tlv readTlv(byte[] buf, int off, int limit) {
        if ((long) off + 2 > limit) throw new IllegalArgumentException("der: truncated header");
        int tag = buf[off] & 0xff;
        if ((tag & 0x1f) == 0x1f) throw new IllegalArgumentException("der: high-tag-number form is not supported");
        long len = buf[off + 1] & 0xff;
        long p = off + 2;
        if ((len & 0x80) != 0) {
            int n = (int) (len & 0x7f);
            if (n == 0 || n > 4) throw new IllegalArgumentException("der: unsupported length form");
            if (p + n > limit) throw new IllegalArgumentException("der: truncated length");
            len = 0;
            for (int i = 0; i < n; i++) len = len * 256 + (buf[(int) p + i] & 0xff);
            p += n;
        }
        if (p + len > limit) throw new IllegalArgumentException("der: content exceeds container");
        return new Tlv(tag, (int) p, (int) (p + len));
    }

    private static List<Tlv> children(byte[] buf, Tlv parent) {
        List<Tlv> out = new ArrayList<>();
        int off = parent.start;
        while (off < parent.end) {
            Tlv t = readTlv(buf, off, parent.end);
            out.add(t);
            off = t.end;
        }
        return out;
    }

    /** {@code der[i]} as JavaScript reads it: -1 (undefined) past the end. */
    private static int at(byte[] der, int i) { return i >= 0 && i < der.length ? der[i] & 0xff : -1; }

    private static String hex(byte[] buf, Tlv t) {
        StringBuilder sb = new StringBuilder();
        for (int i = t.start; i < t.end; i++) sb.append(String.format("%02x", buf[i] & 0xff));
        return sb.toString();
    }

    private static final String OID_KEY_USAGE = "551d0f";
    private static final String OID_SAN = "551d11";
    private static final String OID_BASIC_CONSTRAINTS = "551d13";
    private static final Set<String> KNOWN_CRITICAL = Set.of(OID_KEY_USAGE, OID_SAN, OID_BASIC_CONSTRAINTS, "551d25", "551d0e", "551d23");

    /** The X.509 facts the SVID rules need. */
    public static final class CertFacts {
        public boolean basicConstraintsPresent, isCa, keyUsagePresent, digitalSignature, keyCertSign, crlSign;
        /** pathLenConstraint, or null when absent (a JavaScript number: precision is lost above 2^53, as in the reference). */
        public Double pathLen;
        public final List<String> uriSans = new ArrayList<>();
        public final List<String> unknownCritical = new ArrayList<>();

        /** The facts as a JSON object. */
        public Map<String, Object> toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("basicConstraintsPresent", basicConstraintsPresent);
            m.put("isCa", isCa);
            m.put("pathLen", pathLen == null ? null : new Json.Num(pathLen == Math.rint(pathLen) && Math.abs(pathLen) < 9e15 ? Long.toString(pathLen.longValue()) : Double.toString(pathLen)));
            m.put("keyUsagePresent", keyUsagePresent);
            m.put("digitalSignature", digitalSignature);
            m.put("keyCertSign", keyCertSign);
            m.put("crlSign", crlSign);
            m.put("uriSans", new ArrayList<Object>(uriSans));
            m.put("unknownCritical", new ArrayList<Object>(unknownCritical));
            return m;
        }
    }

    /** Read the X.509 facts the SVID rules need from a DER certificate. Throws IllegalArgumentException on malformed DER. */
    public static CertFacts readCertFacts(byte[] der) {
        Tlv cert = readTlv(der, 0, der.length);
        if (cert.tag != 0x30 || cert.end != der.length) throw new IllegalArgumentException("der: certificate is not a single SEQUENCE");
        List<Tlv> top = children(der, cert);
        Tlv tbs = top.isEmpty() ? null : top.get(0);
        if (tbs == null || tbs.tag != 0x30) throw new IllegalArgumentException("der: missing tbsCertificate");
        Tlv extWrap = null;
        for (Tlv f : children(der, tbs)) if (f.tag == 0xa3) { extWrap = f; break; }
        CertFacts facts = new CertFacts();
        if (extWrap == null) return facts;
        List<Tlv> wrapKids = children(der, extWrap);
        Tlv extSeq = wrapKids.isEmpty() ? null : wrapKids.get(0);
        if (extSeq == null || extSeq.tag != 0x30) throw new IllegalArgumentException("der: malformed extensions");
        Set<String> seen = new HashSet<>();
        for (Tlv ext : children(der, extSeq)) {
            List<Tlv> parts = children(der, ext);
            Tlv oidT = parts.isEmpty() ? null : parts.get(0);
            if (oidT == null || oidT.tag != 0x06) throw new IllegalArgumentException("der: malformed extension");
            String oid = hex(der, oidT);
            if (!seen.add(oid)) throw new IllegalArgumentException("der: duplicate extension");
            boolean critical = parts.size() == 3 && parts.get(1).tag == 0x01 && at(der, parts.get(1).start) == 0xff;
            Tlv valueT = parts.get(parts.size() - 1);
            if (valueT.tag != 0x04) throw new IllegalArgumentException("der: malformed extension value");
            if (critical && !KNOWN_CRITICAL.contains(oid)) facts.unknownCritical.add(oid);
            Tlv inner = readTlv(der, valueT.start, valueT.end);
            if (oid.equals(OID_BASIC_CONSTRAINTS)) {
                facts.basicConstraintsPresent = true;
                for (Tlv c : children(der, inner)) {
                    if (c.tag == 0x01) facts.isCa = at(der, c.start) == 0xff;
                    else if (c.tag == 0x02) {
                        double n = 0;
                        for (int i = c.start; i < c.end; i++) n = n * 256 + (der[i] & 0xff);
                        facts.pathLen = n;
                    }
                }
            } else if (oid.equals(OID_KEY_USAGE)) {
                if (inner.tag != 0x03 || inner.end - inner.start < 2) throw new IllegalArgumentException("der: malformed keyUsage");
                int b0 = der[inner.start + 1] & 0xff;
                facts.keyUsagePresent = true;
                facts.digitalSignature = (b0 & 0x80) != 0;
                facts.keyCertSign = (b0 & 0x04) != 0;
                facts.crlSign = (b0 & 0x02) != 0;
            } else if (oid.equals(OID_SAN)) {
                for (Tlv gn : children(der, inner)) {
                    if (gn.tag == 0x86) facts.uriSans.add(new String(der, gn.start, gn.end - gn.start, StandardCharsets.ISO_8859_1));
                }
            }
        }
        return facts;
    }
}
