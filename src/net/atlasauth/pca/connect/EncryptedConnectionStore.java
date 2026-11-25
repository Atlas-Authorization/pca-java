package net.atlasauth.pca.connect;

import net.atlasauth.pca.Json;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;
import net.atlasauth.pca.connect.VaultError.StoreError;

/**
 * Wraps any {@link ConnectionStore} so {@code accessToken} and {@code refreshToken} are encrypted before they reach it (envelope encryption:
 * a random data key per secret, wrapped by a {@link KeyWrapper}, the aad binding it to the exact connection and field). Everything else in
 * a record stays readable so the inner store can index and expire it. Fails closed: a stored token that is not an envelope, fails
 * authentication, or was sealed under an unknown key makes {@code get} throw a {@link StoreError} that carries no detail.
 */
public final class EncryptedConnectionStore implements ConnectionStore {
    private static final String PREFIX = "pca1";
    private static final SecureRandom RNG = new SecureRandom();
    private static final Pattern B64U = Pattern.compile("[A-Za-z0-9_-]*");
    private final ConnectionStore inner;
    private final KeyWrapper wrapper;

    public EncryptedConnectionStore(ConnectionStore inner, KeyWrapper wrapper) {
        this.inner = inner;
        this.wrapper = wrapper;
    }

    @Override public boolean encrypted() { return true; }

    private static String b64u(byte[] b) { return Base64.getUrlEncoder().withoutPadding().encodeToString(b); }

    private static byte[] unb64u(String s) {
        if (!B64U.matcher(s).matches()) throw new IllegalArgumentException("bad encoding");
        return Base64.getUrlDecoder().decode(s);
    }

    private static int utf8Len(String s) { return Json.utf8(s).length; }

    /** The additional authenticated data: length-prefixed (version, field, agent, provider, connection). */
    static byte[] aadFor(Key key, String field) {
        String[] parts = {"pca-connect/v1", field, key.agentId, key.provider, key.connectionId};
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) sb.append('|');
            sb.append(utf8Len(parts[i])).append(':').append(parts[i]);
        }
        return Json.utf8(sb.toString());
    }

    private String encryptField(Key key, String field, String plain) throws Exception {
        byte[] aad = aadFor(key, field);
        byte[] dek = new byte[32];
        RNG.nextBytes(dek);
        try {
            KeyWrapper.Wrapped w = wrapper.wrap(dek, aad);
            byte[] sealed = LocalKeyWrapper.seal(dek, aad, Json.utf8(plain));
            return String.join(".", PREFIX, b64u(Json.utf8(w.keyId)), b64u(w.wrapped), b64u(sealed));
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    private String decryptField(Key key, String field, String value) throws Exception {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4 || !parts[0].equals(PREFIX)) throw new IllegalArgumentException("not an envelope");
        byte[] aad = aadFor(key, field);
        byte[] dek = wrapper.unwrap(new String(unb64u(parts[1]), StandardCharsets.UTF_8), unb64u(parts[2]), aad);
        try {
            return new String(LocalKeyWrapper.open(dek, aad, unb64u(parts[3])), StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    @Override public StoredConnection get(Key key) throws Exception {
        StoredConnection raw = inner.get(key);
        if (raw == null) return null;
        try {
            StoredConnection out = raw.copy();
            Key k = new Key(raw.agentId, raw.provider, raw.connectionId);
            if (!k.agentId.equals(key.agentId) || !k.provider.equals(key.provider) || !k.connectionId.equals(key.connectionId)) throw new IllegalStateException("record key mismatch");
            out.accessToken = decryptField(k, "access", raw.accessToken);
            if (raw.refreshToken != null) out.refreshToken = decryptField(k, "refresh", raw.refreshToken);
            return out;
        } catch (Exception e) {
            throw new StoreError("a stored token could not be decrypted");
        }
    }

    @Override public void set(StoredConnection connection) throws Exception {
        Key k = new Key(connection.agentId, connection.provider, connection.connectionId);
        StoredConnection sealed = connection.copy();
        try {
            sealed.accessToken = encryptField(k, "access", connection.accessToken);
            if (connection.refreshToken != null) sealed.refreshToken = encryptField(k, "refresh", connection.refreshToken);
        } catch (Exception e) {
            throw new StoreError("a token could not be encrypted; nothing was stored");
        }
        inner.set(sealed);
    }

    @Override public void delete(Key key) throws Exception { inner.delete(key); }

    /** Re-encrypt one record under the wrapper's active key (run after rotating the key ring). */
    public boolean reencrypt(Key key) throws Exception {
        StoredConnection c = get(key);
        if (c == null) return false;
        set(c);
        return true;
    }
}
