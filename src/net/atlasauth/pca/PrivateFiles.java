package net.atlasauth.pca;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * The one way the library creates a file or directory that holds private state (approval, key, revocation, witness and durable
 * state, conformance harness files): owner-only AT CREATION, never restricted afterwards, so no other process can open the object
 * in the gap and keep the handle. On POSIX the mode is 0600 (file) or 0700 (directory); on Windows, where a mode does nothing,
 * the object is created with a security descriptor whose only entry grants the current user full rights (no other principal; a directory's entry is inheritable so its children are owner-only as well). A platform with neither view refuses (an {@link IOException}) instead of writing a readable file.
 */
public final class PrivateFiles {
    private PrivateFiles() {}

    private static final Set<String> VIEWS = FileSystems.getDefault().supportedFileAttributeViews();

    private static volatile UserPrincipal owner;

    private static UserPrincipal owner() throws IOException {
        UserPrincipal o = owner;
        if (o == null) {
            // the account the process runs as (not the owner of a probe file: a created file can be owned by an administrators group)
            o = FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByName(System.getProperty("user.name"));
            owner = o;
        }
        return o;
    }

    /**
     * The single ACL entry that grants {@code who} full rights. A file's entry is not inheritable; a directory's carries FILE_INHERIT
     * and DIRECTORY_INHERIT, so what a third party creates inside it (openssl output, SQLite journal and WAL files) is owner-only too.
     */
    static List<AclEntry> ownerOnlyAcl(UserPrincipal who, boolean directory) {
        AclEntry.Builder b = AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(who).setPermissions(EnumSet.allOf(AclEntryPermission.class));
        if (directory) b.setFlags(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT);
        return List.of(b.build());
    }

    private static FileAttribute<?>[] attrs(boolean dir) throws IOException {
        if (VIEWS.contains("posix")) return new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(dir ? "rwx------" : "rw-------"))};
        if (VIEWS.contains("acl")) {
            final List<AclEntry> acl = ownerOnlyAcl(owner(), dir);
            return new FileAttribute<?>[] {new FileAttribute<List<AclEntry>>() {
                @Override public String name() { return "acl:acl"; }
                @Override public List<AclEntry> value() { return acl; }
            }};
        }
        throw new IOException("this file system has neither POSIX permissions nor ACLs: refusing to create a private file that others could read");
    }

    /** Attributes for a private file (for APIs that take them directly). */
    public static FileAttribute<?>[] fileAttributes() throws IOException { return attrs(false); }

    /** Attributes for a private directory. */
    public static FileAttribute<?>[] directoryAttributes() throws IOException { return attrs(true); }

    /** Create {@code path} exclusively and owner-only (throws FileAlreadyExistsException when it exists). */
    public static Path createFile(Path path) throws IOException { return Files.createFile(path, attrs(false)); }

    /** Create {@code dir} and any missing parents, each owner-only (an existing directory is left as it is). */
    public static Path createDirectories(Path dir) throws IOException { return Files.createDirectories(dir, attrs(true)); }

    /** A new owner-only temporary directory. */
    public static Path createTempDirectory(String prefix) throws IOException { return Files.createTempDirectory(prefix, attrs(true)); }

    /** A new owner-only temporary file. */
    public static Path createTempFile(String prefix, String suffix) throws IOException { return Files.createTempFile(prefix, suffix, attrs(false)); }

    /** {@link FileChannel#open} whose file, when it is created by these options, is owner-only. */
    public static FileChannel openChannel(Path path, Set<? extends OpenOption> options) throws IOException { return FileChannel.open(path, options, attrs(false)); }

    /** {@link Files#newByteChannel} whose file, when it is created by these options, is owner-only. */
    public static SeekableByteChannel openByteChannel(Path path, Set<? extends OpenOption> options) throws IOException { return Files.newByteChannel(path, options, attrs(false)); }

    /** Create (or truncate) {@code path} owner-only and write {@code data}; an existing file keeps its descriptor. */
    public static void write(Path path, byte[] data) throws IOException {
        try (SeekableByteChannel ch = openByteChannel(path, Set.of(StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE))) {
            java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(data);
            while (buf.hasRemaining()) ch.write(buf);
        }
    }

    /** Create {@code path} owner-only when it does not exist yet (the call that follows opens it with a plain handle). */
    public static void ensureFile(Path path) throws IOException {
        try {
            createFile(path);
        } catch (java.nio.file.FileAlreadyExistsException ignored) {
            // already there: created by an earlier open
        }
    }
}
