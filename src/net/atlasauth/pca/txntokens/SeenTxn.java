package net.atlasauth.pca.txntokens;

/** The replay hook: called with the token's txn (draft-11) or jti (legacy) and its exp; a truthy result means "already seen" and refuses the token. */
@FunctionalInterface
public interface SeenTxn {
    Object seen(String id, double exp) throws Exception;
}
