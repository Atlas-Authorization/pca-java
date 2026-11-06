package net.atlasauth.pca;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

/** A certificate's public key with the details the rules ask about (Node's asymmetricKeyType / namedCurve). */
public final class CertKey {
    public final PublicKey pub;
    /** "ec", "rsa", "rsa-pss", "ed25519" or "unknown". */
    public final String typ;
    /** OpenSSL curve name for "ec" (prime256v1, secp384r1, ...), else "". */
    public final String curve;
    /** DER SubjectPublicKeyInfo. */
    public final byte[] spki;

    CertKey(PublicKey pub, String typ, String curve, byte[] spki) {
        this.pub = pub;
        this.typ = typ;
        this.curve = curve;
        this.spki = spki;
    }

    /** keyInfoOf: classify a JDK public key. */
    static CertKey of(PublicKey pub, byte[] spki) {
        if (pub instanceof ECPublicKey) {
            return new CertKey(pub, "ec", AttestCommon.curveOpenSslName(((ECPublicKey) pub).getParams()), spki);
        }
        if (pub instanceof RSAPublicKey) return new CertKey(pub, "rsa", "", spki);
        String alg = pub.getAlgorithm();
        if ("Ed25519".equalsIgnoreCase(alg) || "EdDSA".equalsIgnoreCase(alg)) return new CertKey(pub, "ed25519", "", spki);
        return new CertKey(pub, "unknown", "", spki);
    }

    CertKey withType(String typ) { return new CertKey(pub, typ, curve, spki); }

    public String spkiSha256() { return AttestCommon.toHexLower(AttestCommon.sha256Sum(spki)); }

    public String spkiSha384() { return AttestCommon.toHexLower(AttestCommon.sha384Sum(spki)); }
}
