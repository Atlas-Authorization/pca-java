package net.atlasauth.pca.ai;

import java.util.Map;

/** A built proof-carrying action: the PCActn, its encoded form (the {@code PCA-Action} header value) and the request headers to forward. */
public final class Proof {
    public final Map<String, Object> pcactn;
    public final String encoded;
    public final Map<String, String> headers;

    public Proof(Map<String, Object> pcactn, String encoded, Map<String, String> headers) {
        this.pcactn = pcactn;
        this.encoded = encoded;
        this.headers = headers;
    }
}
