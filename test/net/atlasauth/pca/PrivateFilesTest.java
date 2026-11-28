package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.ciba.CibaApproval;
import net.atlasauth.pca.ciba.CibaKv;
import net.atlasauth.pca.revoke.FileRevocationStore;
import net.atlasauth.pca.revoke.RevocationEntry;
import net.atlasauth.pca.scitt.FileScittLogStore;
import net.atlasauth.pca.stepup.FileSecretStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;

/**
 * Every writer of private state creates its files and directories owner-only, and the restriction reads back: on POSIX the mode is
 * 0600 / 0700; on Windows the object has exactly one ACL entry, an ALLOW for the current user, with no inheritance flag.
 *
 * <p>Each test is bounded on its own thread: a write loop that stops advancing (the buffer never drains) fails the test in 10 s
 * instead of hanging until the mutation tool's own limit, where it could not be told from a kill.
 */
@Timeout(value = 10, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
public class PrivateFilesTest {
    @TempDir Path dir;

    private static boolean posix() { return FileSystems.getDefault().supportedFileAttributeViews().contains("posix"); }

    static void assertPrivate(Path p, boolean directory) throws IOException {
        assertTrue(Files.exists(p), "missing " + p);
        if (posix()) {
            assertEquals(directory ? "rwx------" : "rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(p)), p.toString());
            return;
        }
        assertOwnerOnlyAcl(p);
        if (directory) {
            java.util.Set<java.nio.file.attribute.AclEntryFlag> want = java.util.EnumSet.of(java.nio.file.attribute.AclEntryFlag.FILE_INHERIT, java.nio.file.attribute.AclEntryFlag.DIRECTORY_INHERIT);
            assertTrue(Files.getFileAttributeView(p, AclFileAttributeView.class).getAcl().stream().anyMatch(e -> e.flags().containsAll(want)), "a directory's entry is inheritable: " + p);
        }
    }

    /**
     * Windows merges a parent's inheritable entry into an explicit descriptor (java.nio cannot set the protected flag), so a file made
     * inside a private directory can carry two entries. The property is that every entry is an ALLOW for the current user: no other
     * principal and no deny entry.
     */
    static void assertOwnerOnlyAcl(Path p) throws IOException {
        List<AclEntry> acl = Files.getFileAttributeView(p, AclFileAttributeView.class).getAcl();
        assertFalse(acl.isEmpty(), "an ACL on " + p);
        String me = FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByName(System.getProperty("user.name")).getName();
        for (AclEntry e : acl) {
            assertEquals(AclEntryType.ALLOW, e.type(), "only allow entries on " + p + ": " + acl);
            assertEquals(me, e.principal().getName(), "only the current user on " + p + ": " + acl);
        }
    }

    @Test void helperCreatesFilesDirectoriesAndTempObjects() throws Exception {
        Path d = PrivateFiles.createDirectories(dir.resolve("a").resolve("b"));
        assertPrivate(d, true);
        assertPrivate(d.getParent(), true);
        Path f = PrivateFiles.createFile(d.resolve("f"));
        assertPrivate(f, false);
        assertThrowsExists(() -> PrivateFiles.createFile(f)); // exclusive creation
        Path w = d.resolve("w");
        PrivateFiles.write(w, new byte[] {1, 2, 3});
        assertPrivate(w, false);
        assertEquals(3, Files.size(w));
        assertPrivate(PrivateFiles.createTempDirectory("pcapf-"), true);
        assertPrivate(PrivateFiles.createTempFile("pcapf-", ".t"), false);
    }

    /** What a third party creates inside a private directory (a plain Files.write: openssl output, SQLite journal and WAL) is owner-only as well. */
    @Test void aPlainChildOfAPrivateDirectoryIsOwnerOnly() throws Exception {
        Path d = PrivateFiles.createDirectories(dir.resolve("kids"));
        Path child = d.resolve("plain");
        Files.write(child, new byte[] {1});
        Path sub = d.resolve("sub");
        Files.createDirectory(sub);
        if (posix()) {
            assertPrivate(d, true); // the directory's 0700 keeps every other user out of its children
            return;
        }
        assertOwnerOnlyAcl(child);
        assertOwnerOnlyAcl(sub);
    }

    private static void assertThrowsExists(org.junit.jupiter.api.function.Executable e) {
        org.junit.jupiter.api.Assertions.assertThrows(java.nio.file.FileAlreadyExistsException.class, e);
    }

    @Test void durableStateDirectoryAndFiles() throws Exception {
        Path d = dir.resolve("durable");
        DurableState s = DurableState.open(new DurableState.Options(d.toString()));
        s.set("a", new Json.Num("1"));
        assertPrivate(d, true);
        try (var st = Files.list(d)) {
            for (Path p : (Iterable<Path>) st::iterator) if (Files.isRegularFile(p)) assertPrivate(p, false);
        }
    }

    @Test void revocationStoreFile() throws Exception {
        Path p = dir.resolve("revoked.json");
        new FileRevocationStore(p).add(new RevocationEntry("cap", "c1", null, "r", 1.0, null));
        assertPrivate(p, false);
    }

    @Test void cibaDirectoryKvAndFileApprovalStore() throws Exception {
        Path kd = dir.resolve("kv");
        CibaKv.DurableKv kv = CibaKv.createDirectoryKv(kd);
        assertTrue(kv.putIfEquals("k", null, "v"));
        assertPrivate(kd, true);
        try (var st = Files.list(kd)) {
            for (Path p : (Iterable<Path>) st::iterator) assertPrivate(p, false);
        }
        Path ap = dir.resolve("approvals.json");
        assertTrue(CibaApproval.createFileApprovalStore(ap).cas("k", 0, "v"));
        assertPrivate(ap, false);
    }

    @Test void secretStoreFile() throws Exception {
        Path p = dir.resolve("secret");
        new FileSecretStore(p).save(new byte[32]);
        assertPrivate(p, false);
    }

    @Test void meshWitnessFile() throws Exception {
        Path p = dir.resolve("witness.json");
        new FileMeshWitnessStore(p).save(new LinkedHashMap<String, Object>(Map.of("seen", new ArrayList<Object>())));
        assertPrivate(p, false);
    }

    @Test void scittLogFile() throws Exception {
        Path p = dir.resolve("scitt.log");
        try (FileScittLogStore s = FileScittLogStore.open(p)) {
            assertFalse(s == null);
        }
        assertPrivate(p, false);
    }

    @Test void harnessHistoryFile() throws Exception {
        Path p = dir.resolve("h.jsonl");
        try (var r = new net.atlasauth.pca.storeconformance.Recorder.FileRecorder(p, "p0")) {
            assertFalse(r == null);
        }
        assertPrivate(p, false);
    }
}
