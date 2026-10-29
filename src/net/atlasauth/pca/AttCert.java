package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** A parsed certificate: the raw parts the verifiers compare, and the parameters of its signature (see {@link AttestCert}). */
public final class AttCert {
    /** The certificate as DER (outer length in minimal form). */
    public byte[] raw;
    /** tbsCertificate, header included. */
    public byte[] rawTbs;
    public byte[] rawIssuer;
    public byte[] rawSubject;
    public byte[] rawSpki;
    /** The INTEGER content. */
    public byte[] serial;
    public String sigOid;
    /** The parameters element of the signature algorithm, header included (null: absent). */
    public byte[] sigParams;
    /** The signature BIT STRING content without the unused-bits octet. */
    public byte[] signature;
    final List<LenientExt> exts = new ArrayList<>();

    /** An extension as the OpenSSL decoder reads it (lenient: the strict readers judge the table). */
    static final class LenientExt {
        String oid;
        boolean critical;
        byte[] value;
    }

    /** The extnValue of the first extension with this OID, or null. */
    public byte[] extValue(String oid) {
        for (LenientExt e : exts) if (e.oid.equals(oid)) return e.value;
        return null;
    }

    /** The OCSP responder URLs of the Authority Information Access extension. */
    public List<String> ocspServers() {
        List<String> out = new ArrayList<>();
        byte[] v = extValue("1.3.6.1.5.5.7.1.1");
        if (v == null) return out;
        try {
            AttestCert.Elem seq = AttestCert.readCertElem(v, 0, v.length, 0x30);
            for (AttestCert.Elem d : AttestCert.certKids(v, seq)) {
                try {
                    List<AttestCert.Elem> parts = AttestCert.certKids(v, d);
                    if (parts.size() != 2 || parts.get(0).tag != 0x06) continue;
                    String method = AttestDer.oidToDotted(v, new AttestDer.Tlv(parts.get(0).tag, parts.get(0).start, parts.get(0).end));
                    if (!method.equals("1.3.6.1.5.5.7.48.1") || parts.get(1).tag != 0x86) continue;
                    out.add(new String(Arrays.copyOfRange(v, parts.get(1).start, parts.get(1).end), java.nio.charset.StandardCharsets.UTF_8));
                } catch (AttestException e) {
                    // a malformed access description is skipped
                }
            }
        } catch (AttestException e) {
            return new ArrayList<>();
        }
        return out;
    }

    /** True iff the extended key usage extension lists id-kp-OCSPSigning. */
    public boolean hasOcspSigningEku() {
        byte[] v = extValue("2.5.29.37");
        if (v == null) return false;
        try {
            AttestCert.Elem seq = AttestCert.readCertElem(v, 0, v.length, 0x30);
            for (AttestCert.Elem p : AttestCert.certKids(v, seq)) {
                try {
                    if (AttestDer.oidToDotted(v, new AttestDer.Tlv(p.tag, p.start, p.end)).equals("1.3.6.1.5.5.7.3.9")) return true;
                } catch (AttestException e) {
                    // not an OID: skipped
                }
            }
        } catch (AttestException e) {
            return false;
        }
        return false;
    }

    public boolean selfIssued() { return Arrays.equals(rawSubject, rawIssuer); }

    /** The serial number as lowercase hex without leading zeros. */
    public String serialHex() {
        String h = AttestCommon.toHexLower(serial);
        int i = 0;
        while (i < h.length() && h.charAt(i) == '0') i++;
        return h.substring(i);
    }
}
