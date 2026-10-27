package net.atlasauth.pca;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Strict DER readers shared by the hardware-attestation chain verifiers (the native counterpart of the strict X.509 helpers
 * and the validity reader of the TypeScript package). The CA-role rules are enforced from a small, strict walk of the
 * certificate's own DER. Messages are the reference's, byte for byte. Port of the Go attest_der.go.
 */
public final class AttestDer {
    private AttestDer() {}

    /** One element: its tag and its content range [start, end). */
    public static final class Tlv {
        public final int tag;
        public final int start;
        public final int end;

        Tlv(int tag, int start, int end) {
            this.tag = tag;
            this.start = start;
            this.end = end;
        }
    }

    /** Reads one definite-length element at off (inside limit). Minimal lengths only, no multi-byte tags. */
    public static Tlv readTlvStrict(byte[] b, int off, int limit) {
        if (off + 2 > limit) throw new AttestException("DER: truncated header");
        int tag = b[off] & 0xff;
        if ((tag & 0x1f) == 0x1f) throw new AttestException("DER: multi-byte tags are not supported");
        int l = b[off + 1] & 0xff;
        int p = off + 2;
        if ((l & 0x80) != 0) {
            int n = l & 0x7f;
            if (n == 0 || n > 3) throw new AttestException("DER: unsupported length form");
            if (p + n > limit) throw new AttestException("DER: truncated length");
            l = 0;
            if (n > 1 && b[p] == 0) throw new AttestException("DER: non-minimal length (leading zero)");
            for (int i = 0; i < n; i++) l = (l << 8) | (b[p + i] & 0xff);
            if (l < 0x80) throw new AttestException("DER: non-minimal length (long form below 128)");
            p += n;
        }
        if (p + l > limit) throw new AttestException("DER: element overruns its parent");
        return new Tlv(tag, p, p + l);
    }

    /** The CA-role-relevant part of a certificate. */
    public static final class CertRoleInfo {
        public boolean hasBasicConstraints;
        public boolean ca;
        /** -1 when absent. */
        public int pathLen = -1;
        public boolean hasKeyUsage;
        public boolean keyCertSign;
    }

    private static final byte[] OID_BASIC_CONSTRAINTS = {0x55, 0x1d, 0x13};
    private static final byte[] OID_KEY_USAGE = {0x55, 0x1d, 0x0f};

    static boolean oidEqualsDer(byte[] b, Tlv t, byte[] want) {
        if (t.tag != 0x06 || t.end - t.start != want.length) return false;
        for (int i = 0; i < want.length; i++) if (b[t.start + i] != want[i]) return false;
        return true;
    }

    /** Reads BasicConstraints and keyUsage of a DER certificate; AttestException on a malformed or duplicated extension. */
    public static CertRoleInfo readCertRoleInfo(byte[] cert) {
        CertRoleInfo info = new CertRoleInfo();
        Tlv outer = readTlvStrict(cert, 0, cert.length);
        if (outer.tag != 0x30) throw new AttestException("certificate is not a DER SEQUENCE");
        if (outer.end != cert.length) throw new AttestException("trailing bytes after the certificate");
        Tlv tbs = readTlvStrict(cert, outer.start, outer.end);
        if (tbs.tag != 0x30) throw new AttestException("certificate has no tbsCertificate");
        int p = tbs.start;
        while (p < tbs.end) {
            Tlv el = readTlvStrict(cert, p, tbs.end);
            p = el.end;
            if (el.tag != 0xa3) continue;
            Tlv seq = readTlvStrict(cert, el.start, el.end);
            if (seq.tag != 0x30) throw new AttestException("extensions is not a SEQUENCE");
            int q = seq.start;
            while (q < seq.end) {
                Tlv ext = readTlvStrict(cert, q, seq.end);
                q = ext.end;
                if (ext.tag != 0x30) throw new AttestException("extension is not a SEQUENCE");
                Tlv id = readTlvStrict(cert, ext.start, ext.end);
                int r = id.end;
                Tlv next = readTlvStrict(cert, r, ext.end);
                if (next.tag == 0x01) {
                    r = next.end;
                    next = readTlvStrict(cert, r, ext.end);
                }
                if (next.tag != 0x04) throw new AttestException("extension value is not an OCTET STRING");
                if (oidEqualsDer(cert, id, OID_BASIC_CONSTRAINTS)) {
                    if (info.hasBasicConstraints) throw new AttestException("duplicate BasicConstraints extension");
                    info.hasBasicConstraints = true;
                    Tlv bc = readTlvStrict(cert, next.start, next.end);
                    if (bc.tag != 0x30) throw new AttestException("BasicConstraints is not a SEQUENCE");
                    int c = bc.start;
                    if (c < bc.end) {
                        Tlv first = readTlvStrict(cert, c, bc.end);
                        if (first.tag == 0x01) {
                            if (first.end - first.start != 1) throw new AttestException("BasicConstraints cA is not one byte");
                            info.ca = cert[first.start] != 0;
                            c = first.end;
                        }
                    }
                    if (c < bc.end) {
                        Tlv pl = readTlvStrict(cert, c, bc.end);
                        if (pl.tag != 0x02 || pl.end - pl.start < 1 || pl.end - pl.start > 2 || (cert[pl.start] & 0x80) != 0) {
                            throw new AttestException("BasicConstraints pathLenConstraint malformed");
                        }
                        int n = 0;
                        for (int i = pl.start; i < pl.end; i++) n = (n << 8) | (cert[i] & 0xff);
                        info.pathLen = n;
                        c = pl.end;
                    }
                    if (c != bc.end) throw new AttestException("BasicConstraints has trailing data");
                } else if (oidEqualsDer(cert, id, OID_KEY_USAGE)) {
                    if (info.hasKeyUsage) throw new AttestException("duplicate keyUsage extension");
                    info.hasKeyUsage = true;
                    Tlv bs = readTlvStrict(cert, next.start, next.end);
                    if (bs.tag != 0x03 || bs.end - bs.start < 2) throw new AttestException("keyUsage is not a BIT STRING");
                    if ((cert[bs.start] & 0xff) > 7) throw new AttestException("keyUsage BIT STRING has more than 7 unused bits");
                    info.keyCertSign = (cert[bs.start + 1] & 0x04) != 0;
                }
            }
        }
        return info;
    }

    /** One extension of a certificate: the critical flag and the extnValue OCTET STRING content. */
    public static final class CertExt {
        public final boolean critical;
        public final byte[] value;

        CertExt(boolean critical, byte[] value) {
            this.critical = critical;
            this.value = value;
        }
    }

    /** Extensions in encounter order (the reference iterates a Map). */
    public static final class ExtTable {
        public final List<String> oids = new ArrayList<>();
        public final Map<String, CertExt> m = new LinkedHashMap<>();

        public CertExt get(String oid) { return m.get(oid); }
    }

    /** A DER OBJECT IDENTIFIER element as dotted text; AttestException when malformed. */
    public static String oidToDotted(byte[] b, Tlv t) {
        if (t.tag != 0x06 || t.end <= t.start) throw new AttestException("extension OID is malformed");
        List<BigInteger> arcs = new ArrayList<>();
        BigInteger v = BigInteger.ZERO;
        boolean open = false;
        for (int i = t.start; i < t.end; i++) {
            int by = b[i] & 0xff;
            if (!open && by == 0x80) throw new AttestException("extension OID has a non-minimal arc");
            v = v.shiftLeft(7).or(BigInteger.valueOf(by & 0x7f));
            open = (by & 0x80) != 0;
            if (!open) {
                arcs.add(v);
                v = BigInteger.ZERO;
            }
        }
        if (open) throw new AttestException("extension OID is truncated");
        BigInteger first = arcs.get(0);
        StringBuilder sb = new StringBuilder();
        if (first.compareTo(BigInteger.valueOf(40)) < 0) sb.append("0.").append(first);
        else if (first.compareTo(BigInteger.valueOf(80)) < 0) sb.append("1.").append(first.subtract(BigInteger.valueOf(40)));
        else sb.append("2.").append(first.subtract(BigInteger.valueOf(80)));
        for (int i = 1; i < arcs.size(); i++) sb.append('.').append(arcs.get(i));
        return sb.toString();
    }

    /**
     * The strict extension table of a tbsCertificate (the DER SEQUENCE including its header), keyed by dotted OID. It fails
     * closed on a malformed element, a duplicate extension, more than one [3] block, a non-DER critical flag, trailing bytes,
     * or an empty Extensions block.
     */
    public static ExtTable parseTbsExtensions(byte[] tbsDer) {
        Tlv tbs = readTlvStrict(tbsDer, 0, tbsDer.length);
        if (tbs.tag != 0x30) throw new AttestException("tbsCertificate is not a SEQUENCE");
        if (tbs.end != tbsDer.length) throw new AttestException("trailing bytes after tbsCertificate");
        ExtTable out = new ExtTable();
        boolean seen = false;
        int blockEnd = -1;
        int p = tbs.start;
        while (p < tbs.end) {
            Tlv el = readTlvStrict(tbsDer, p, tbs.end);
            p = el.end;
            if (el.tag != 0xa3) continue;
            if (seen) throw new AttestException("duplicate [3] extensions block");
            seen = true;
            blockEnd = el.end;
            Tlv seq = readTlvStrict(tbsDer, el.start, el.end);
            if (seq.tag != 0x30) throw new AttestException("extensions is not a SEQUENCE");
            if (seq.end != el.end) throw new AttestException("trailing bytes after the Extensions SEQUENCE");
            if (seq.start == seq.end) throw new AttestException("empty Extensions SEQUENCE");
            int q = seq.start;
            while (q < seq.end) {
                Tlv ext = readTlvStrict(tbsDer, q, seq.end);
                q = ext.end;
                if (ext.tag != 0x30) throw new AttestException("extension is not a SEQUENCE");
                Tlv id = readTlvStrict(tbsDer, ext.start, ext.end);
                String dotted = oidToDotted(tbsDer, id);
                int r = id.end;
                Tlv next = readTlvStrict(tbsDer, r, ext.end);
                boolean critical = false;
                if (next.tag == 0x01) {
                    if (next.end - next.start != 1 || (tbsDer[next.start] & 0xff) != 0xff) {
                        throw new AttestException("extension " + dotted + " has a non-DER critical flag");
                    }
                    critical = true;
                    r = next.end;
                    next = readTlvStrict(tbsDer, r, ext.end);
                }
                if (next.tag != 0x04) throw new AttestException("extension " + dotted + " value is not an OCTET STRING");
                if (next.end != ext.end) throw new AttestException("extension " + dotted + " has trailing bytes");
                if (out.m.containsKey(dotted)) throw new AttestException("duplicate extension " + dotted);
                out.oids.add(dotted);
                out.m.put(dotted, new CertExt(critical, Arrays.copyOfRange(tbsDer, next.start, next.end)));
            }
        }
        if (seen && blockEnd != tbs.end) throw new AttestException("extensions block is not the last TBS element");
        return out;
    }

    /** The tbsCertificate bytes (header included) of a DER certificate; trailing bytes are refused. */
    public static byte[] tbsOfCertificate(byte[] cert) {
        Tlv outer = readTlvStrict(cert, 0, cert.length);
        if (outer.tag != 0x30) throw new AttestException("certificate is not a DER SEQUENCE");
        if (outer.end != cert.length) throw new AttestException("trailing bytes after the certificate");
        Tlv tbs = readTlvStrict(cert, outer.start, outer.end);
        if (tbs.tag != 0x30) throw new AttestException("certificate has no tbsCertificate");
        return Arrays.copyOfRange(cert, outer.start, tbs.end);
    }

    public static ExtTable parseCertExtensions(byte[] cert) { return parseTbsExtensions(tbsOfCertificate(cert)); }

    /** The only critical extensions the attestation chain verifiers understand (basicConstraints, keyUsage). */
    public static final Set<String> RECOGNISED_CRITICAL_EXTENSIONS = new HashSet<>(Arrays.asList("2.5.29.19", "2.5.29.15"));

    /** The first critical extension OID the verifier does not recognise (RFC 5280 4.2), or null; recognised null means the default set. */
    public static String unrecognisedCriticalExtension(byte[] cert, Set<String> recognised) {
        if (recognised == null) recognised = RECOGNISED_CRITICAL_EXTENSIONS;
        ExtTable t = parseCertExtensions(cert);
        for (String oid : t.oids) if (t.m.get(oid).critical && !recognised.contains(oid)) return oid;
        return null;
    }

    /** Enforces the CA roles over an ordered chain (index 0 = leaf ... last = self-signed root). The failure reason, or "" when the chain is fine. */
    public static String checkChainRoles(List<byte[]> ordered) {
        int n = ordered.size();
        for (int i = 0; i < n; i++) {
            CertRoleInfo info;
            try {
                info = readCertRoleInfo(ordered.get(i));
            } catch (AttestException e) {
                return "certificate extension parse failed: " + e.getMessage();
            }
            if (i == 0 && n > 1) {
                if (info.ca) return "leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)";
                continue;
            }
            if (i == 0) continue;
            if (!info.hasBasicConstraints) return "issuer certificate at depth " + i + " has no BasicConstraints (not a CA)";
            if (!info.ca) return "issuer certificate at depth " + i + " is not a CA (BasicConstraints CA:FALSE)";
            if (info.hasKeyUsage && !info.keyCertSign) return "issuer certificate at depth " + i + " keyUsage lacks keyCertSign";
            if (info.pathLen >= 0 && info.pathLen < i - 1) {
                return "issuer certificate at depth " + i + " pathLenConstraint " + info.pathLen + " is exceeded (" + (i - 1) + " intermediate(s) below)";
            }
        }
        return "";
    }

    // ------------------------------------------------------------- validity (read from the certificate's own DER)

    /** An epoch-millisecond instant, or not ok (the reference's NaN). */
    public static final class DerInstant {
        public final long ms;
        public final boolean ok;

        DerInstant(long ms, boolean ok) {
            this.ms = ms;
            this.ok = ok;
        }
    }

    static final DerInstant NO_INSTANT = new DerInstant(0, false);

    /** A lenient element reader (long forms up to 4 length bytes, not minimal-checked) bounded by limit. */
    static Tlv tlvAt(byte[] der, int off, int limit) {
        if (off + 2 > limit) throw new AttestException("truncated");
        int tag = der[off] & 0xff;
        long l = der[off + 1] & 0xff;
        int start = off + 2;
        if ((l & 0x80) != 0) {
            int n = (int) (l & 0x7f);
            if (n == 0 || n > 4 || start + n > limit) throw new AttestException("bad length");
            l = 0;
            for (int i = 0; i < n; i++) l = l * 256 + (der[start + i] & 0xff);
            start += n;
        }
        long end = start + l;
        if (end > limit) throw new AttestException("truncated");
        return new Tlv(tag, start, (int) end);
    }

    static Tlv tlvAt(byte[] der, int off) { return tlvAt(der, off, der.length); }

    private static boolean allAsciiDigits(String s) {
        if (s.isEmpty()) return false;
        for (int i = 0; i < s.length(); i++) if (s.charAt(i) < '0' || s.charAt(i) > '9') return false;
        return true;
    }

    /**
     * The strict RFC 5280 Time: tag 0x17 UTCTime YYMMDDHHMMSSZ (YY &gt;= 50 is 19YY) or tag 0x18 GeneralizedTime
     * YYYYMMDDHHMMSSZ, every field in range, no roll-over.
     */
    public static DerInstant parseDerTime(int tag, String text) {
        int y;
        String rest;
        if (tag == 0x17 && text.length() == 13) {
            if (!allAsciiDigits(text.substring(0, 12)) || text.charAt(12) != 'Z') return NO_INSTANT;
            int yy = Integer.parseInt(text.substring(0, 2));
            y = yy >= 50 ? 1900 + yy : 2000 + yy;
            rest = text.substring(2);
        } else if (tag == 0x18 && text.length() == 15) {
            if (!allAsciiDigits(text.substring(0, 14)) || text.charAt(14) != 'Z') return NO_INSTANT;
            y = Integer.parseInt(text.substring(0, 4));
            rest = text.substring(4);
        } else {
            return NO_INSTANT;
        }
        int mon = Integer.parseInt(rest.substring(0, 2));
        int day = Integer.parseInt(rest.substring(2, 4));
        int h = Integer.parseInt(rest.substring(4, 6));
        int mi = Integer.parseInt(rest.substring(6, 8));
        int sec = Integer.parseInt(rest.substring(8, 10));
        if (mon < 1 || mon > 12 || day < 1 || h > 23 || mi > 59 || sec > 59) return NO_INSTANT;
        try {
            LocalDateTime d = LocalDateTime.of(y, mon, day, h, mi, sec);
            return new DerInstant(d.toEpochSecond(ZoneOffset.UTC) * 1000L, true);
        } catch (DateTimeException e) {
            return NO_INSTANT; // a day the month does not have (no roll-over)
        }
    }

    /** The validity window {from, to} of a DER certificate (Certificate, tbsCertificate, validity); both not ok when malformed. */
    public static DerInstant[] derValidity(byte[] der) {
        DerInstant[] bad = {NO_INSTANT, NO_INSTANT};
        try {
            Tlv cert = tlvAt(der, 0);
            if (cert.tag != 0x30) return bad;
            Tlv tbs = tlvAt(der, cert.start);
            if (tbs.tag != 0x30) return bad;
            int off = tbs.start;
            Tlv el = tlvAt(der, off);
            if (el.tag == 0xa0) {
                off = el.end;
                el = tlvAt(der, off);
            }
            if (el.tag != 0x02) return bad; // serialNumber
            el = tlvAt(der, el.end);
            if (el.tag != 0x30) return bad; // signature
            el = tlvAt(der, el.end);
            if (el.tag != 0x30) return bad; // issuer
            Tlv validity = tlvAt(der, el.end);
            if (validity.tag != 0x30 || validity.end > tbs.end) return bad;
            Tlv nb = tlvAt(der, validity.start);
            Tlv na = tlvAt(der, nb.end);
            if (na.end != validity.end) return bad;
            return new DerInstant[] {
                parseDerTime(nb.tag, new String(der, nb.start, nb.end - nb.start, StandardCharsets.ISO_8859_1)),
                parseDerTime(na.tag, new String(der, na.start, na.end - na.start, StandardCharsets.ISO_8859_1)),
            };
        } catch (AttestException e) {
            return bad;
        }
    }

    /** True iff both bounds parse and from - skew &lt;= nowMs &lt;= to + skew (fail closed on an unparseable bound). */
    public static boolean derValidAt(byte[] der, long nowMs, long skewMs) {
        DerInstant[] v = derValidity(der);
        if (!v[0].ok || !v[1].ok) return false;
        return nowMs + skewMs >= v[0].ms && nowMs - skewMs <= v[1].ms;
    }

    /** {@link #derValidAt} with a fractional skew (milliseconds). */
    public static boolean derValidAtF(byte[] der, long nowMs, double skewMs) {
        DerInstant[] v = derValidity(der);
        if (!v[0].ok || !v[1].ok) return false;
        return (double) nowMs + skewMs >= (double) v[0].ms && (double) nowMs - skewMs <= (double) v[1].ms;
    }
}
