package net.atlasauth.pca;

/**
 * What a vendor quote's bound value must equal: the server-known holder key, grant, epoch and nonce. {@code epoch} is a
 * double because the wire form carries a JSON number; only a non-negative safe integer is constructible into bytes.
 */
public final class AttestationBinding {
    public final String holderPub;
    public final String grantRef;
    public final double epoch;
    public final String nonce;

    public AttestationBinding(String holderPub, String grantRef, double epoch, String nonce) {
        this.holderPub = holderPub == null ? "" : holderPub;
        this.grantRef = grantRef == null ? "" : grantRef;
        this.epoch = epoch;
        this.nonce = nonce == null ? "" : nonce;
    }
}
