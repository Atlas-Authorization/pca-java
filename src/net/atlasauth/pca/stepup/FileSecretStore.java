package net.atlasauth.pca.stepup;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Base64;

import net.atlasauth.pca.Pca;

/**
 * A {@link SecretStore} in a file holding the seed as base64url, created with mode 0600 where the file system has POSIX
 * permissions. For a phone or desktop app back the key with the platform keystore instead and gate approvals behind user presence.
 */
public final class FileSecretStore implements SecretStore {
    private final Path path;

    public FileSecretStore(Path path) {
        if (path == null) throw new IllegalArgumentException("path");
        this.path = path;
    }

    @Override
    public byte[] load() {
        try {
            if (!Files.exists(path)) return null;
            return Pca.decodeB64uStrict(new String(Files.readAllBytes(path), StandardCharsets.US_ASCII).trim(), -1);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void save(byte[] secret) {
        try {
            Files.deleteIfExists(path);
            try {
                Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            } catch (UnsupportedOperationException e) {
                Files.createFile(path); // not a POSIX file system
            }
            Files.write(path, Base64.getUrlEncoder().withoutPadding().encodeToString(secret).getBytes(StandardCharsets.US_ASCII));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void delete() {
        try {
            Files.deleteIfExists(path);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
