package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.DriverManager;
import java.sql.SQLException;

import org.junit.jupiter.api.Test;
import org.sqlite.SQLiteDataSource;

/**
 * The SQLite file is created BEFORE the driver opens it (so xerial's create-then-delete open probe never runs), the URL forms
 * are parsed like the driver and SQLite read them, and an in-memory SQLite database is refused.
 */
public class SqliteFileTest {
    private final Path dir;

    public SqliteFileTest() throws Exception {
        dir = Files.createTempDirectory("pca-sqlite");
    }

    @Test
    void urlFormsNameTheDatabaseFile() {
        Path a = dir.resolve("a.db");
        assertEquals(a.toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:" + a));
        assertEquals(a.toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:" + a + "?journal_mode=WAL&busy_timeout=5"));
        assertEquals(Paths.get("rel.db").toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:rel.db"));
        Path spaced = dir.resolve("a b.db");
        String uri = spaced.toUri().toString(); // file:///... with %20 (and /C:/ on Windows)
        assertEquals(spaced.toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:" + uri));
        assertEquals(spaced.toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:" + uri + "?cache=shared"));
        assertEquals(spaced.toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:" + uri.replaceFirst("file:///", "file://localhost/")));
        assertEquals(spaced.toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:" + uri.replaceFirst("file:///", "file:/")));
    }

    @Test
    void nothingToCreateForMemoryReadOnlyResourceRemoteOrOtherDatabases() {
        for (String url : new String[] {
            "jdbc:sqlite:", "jdbc:sqlite::memory:", "jdbc:sqlite:file::memory:?cache=shared", "jdbc:sqlite:file:x?mode=memory&cache=shared",
            "jdbc:sqlite:" + dir.resolve("r.db") + "?mode=ro", "jdbc:sqlite::resource:x.db", "jdbc:sqlite:file://remote/x.db",
            "jdbc:sqlite:file:", "jdbc:postgresql://h/db", null,
        }) assertNull(PcaJdbcStateStore.sqliteFile(url), url);
    }

    @Test
    void ensureCreatesTheFileAndItsDirectoriesOnceAndKeepsAnExistingOne() throws Exception {
        Path f = dir.resolve("x").resolve("y").resolve("kv.db");
        assertEquals(f.toAbsolutePath(), PcaJdbcStateStore.ensureSqliteFile("jdbc:sqlite:" + f));
        assertTrue(Files.isRegularFile(f));
        Files.write(f, new byte[] {1, 2, 3});
        PcaJdbcStateStore.ensureSqliteFile("jdbc:sqlite:" + f);
        assertEquals(3L, Files.size(f));
        assertNull(PcaJdbcStateStore.ensureSqliteFile("jdbc:sqlite::memory:"));
    }

    @Test
    void theFactoryCreatesTheFileBeforeTheDriverOpensIt() throws Exception {
        Path f = dir.resolve("new").resolve("replay.db");
        PcaJdbcStateStore store = new PcaJdbcStateStore(PcaJdbcStateStore.sqliteConnections("jdbc:sqlite:" + f)).createTable();
        assertTrue(Files.isRegularFile(f));
        assertTrue(store.claim("k", 1).ok);
        assertFalse(new PcaJdbcStateStore(PcaJdbcStateStore.sqliteConnections("jdbc:sqlite:" + f)).claim("k", 1).ok);
        assertThrows(IllegalArgumentException.class, () -> PcaJdbcStateStore.sqliteConnections("jdbc:postgresql://h/db"));
    }

    @Test
    void aSqliteDataSourceHasItsFileCreatedAtConstruction() {
        Path f1 = dir.resolve("ds1.db");
        Path f2 = dir.resolve("ds2.db");
        SQLiteDataSource ds1 = new SQLiteDataSource();
        ds1.setUrl("jdbc:sqlite:" + f1);
        SQLiteDataSource ds2 = new SQLiteDataSource();
        ds2.setUrl("jdbc:sqlite:" + f2);
        new PcaJdbcStateStore(ds1);
        new PcaJdbcAtomicKv(ds2);
        assertTrue(Files.isRegularFile(f1)); // no connection was opened: the store created it
        assertTrue(Files.isRegularFile(f2));
        assertEquals("jdbc:sqlite:" + f1, PcaJdbcStateStore.jdbcUrlOf(ds1));
        assertNull(PcaJdbcStateStore.jdbcUrlOf(new Object()));
    }

    @Test
    void anInMemorySqliteDatabaseIsRefused() {
        PcaJdbcStateStore.ConnectionFactory mem = () -> DriverManager.getConnection("jdbc:sqlite::memory:");
        SQLException e = assertThrows(SQLException.class, () -> new PcaJdbcStateStore(mem).createTable());
        assertTrue(e.getMessage().contains("in memory"));
        IllegalStateException claim = assertThrows(IllegalStateException.class, () -> new PcaJdbcStateStore(mem).claim("k", 1));
        assertTrue(claim.getMessage().contains("in memory"));
        assertThrows(SQLException.class, () -> new PcaJdbcAtomicKv(mem).createTable());
        assertThrows(IllegalStateException.class, () -> new PcaJdbcAtomicKv(mem).update("k", prev -> "v"));
    }
}
