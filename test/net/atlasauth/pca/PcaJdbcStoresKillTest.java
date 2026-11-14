package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.sqlite.SQLiteDataSource;

/**
 * The JDBC stores against a recording, strictly-JDBC proxy over SQLite: every connection is put in auto-commit, the file
 * check runs once per store, a failed check closes the connection, a missing row is never read, the compare-and-set loop
 * gives up after exactly MAX_ATTEMPTS, and every SQL error surfaces with the store's message. Also the SQLite URL parser.
 */
public class PcaJdbcStoresKillTest {
    private final Path dir;

    public PcaJdbcStoresKillTest() throws IOException {
        dir = Files.createTempDirectory("pca-jdbc-kill");
    }

    /** What the proxied connections did. */
    static final class Rec {
        final List<String> log = Collections.synchronizedList(new ArrayList<>());
        volatile boolean loseCas;
        volatile String product;

        long count(String entry) { synchronized (log) { return log.stream().filter(entry::equals).count(); } }
    }

    static Object wrap(Object target, Class<?> iface, Rec rec, String sql) {
        InvocationHandler h = (proxy, m, args) -> handle(target, iface, rec, sql, m, args);
        return Proxy.newProxyInstance(PcaJdbcStoresKillTest.class.getClassLoader(), new Class<?>[] {iface}, h);
    }

    private static Object call(Object target, Method m, Object[] args) throws Throwable {
        try {
            return m.invoke(target, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private static Object handle(Object target, Class<?> iface, Rec rec, String sql, Method m, Object[] args) throws Throwable {
        String name = m.getName();
        if (iface == Connection.class) {
            if (name.equals("setAutoCommit")) rec.log.add("setAutoCommit:" + args[0]);
            if (name.equals("close")) rec.log.add("close");
            if (name.equals("getMetaData")) {
                rec.log.add("getMetaData");
                DatabaseMetaData md = (DatabaseMetaData) call(target, m, args);
                if (rec.product == null) return md;
                return Proxy.newProxyInstance(PcaJdbcStoresKillTest.class.getClassLoader(), new Class<?>[] {DatabaseMetaData.class},
                    (p, mm, a) -> mm.getName().equals("getDatabaseProductName") ? rec.product : call(md, mm, a));
            }
            if (name.equals("prepareStatement")) return wrap(call(target, m, args), PreparedStatement.class, rec, (String) args[0]);
            if (name.equals("createStatement")) return wrap(call(target, m, args), Statement.class, rec, null);
            return call(target, m, args);
        }
        if (iface == PreparedStatement.class || iface == Statement.class) {
            if (name.equals("executeUpdate") && rec.loseCas && sql != null && (sql.startsWith("UPDATE ") || sql.contains("DO NOTHING")))
                return 0;
            if (name.equals("executeQuery")) return strictResultSet((ResultSet) call(target, m, args));
            return call(target, m, args);
        }
        return call(target, m, args);
    }

    /** A ResultSet that refuses to read a column when next() said there is no row (the JDBC contract, strictly). */
    static ResultSet strictResultSet(ResultSet rs) {
        boolean[] onRow = {false};
        return (ResultSet) Proxy.newProxyInstance(PcaJdbcStoresKillTest.class.getClassLoader(), new Class<?>[] {ResultSet.class}, (p, m, a) -> {
            String n = m.getName();
            if (n.equals("next")) {
                Object r = call(rs, m, a);
                onRow[0] = Boolean.TRUE.equals(r);
                return r;
            }
            if ((n.equals("getString") || n.equals("getLong")) && !onRow[0]) throw new SQLException("no current row");
            return call(rs, m, a);
        });
    }

    static PcaJdbcStateStore.ConnectionFactory recording(Path f, Rec rec) {
        return () -> (Connection) wrap(AuthorizeFixtures.sqliteConnection(f), Connection.class, rec, null);
    }

    Path db(String name) { return dir.resolve(name); }

    // ---- constructors --------------------------------------------------------------------------------------------------

    @Test void constructorsRefuseMissingParts() {
        assertEquals("dataSource", assertThrows(NullPointerException.class, () -> new PcaJdbcStateStore((javax.sql.DataSource) null)).getMessage());
        assertEquals("dataSource", assertThrows(NullPointerException.class, () -> new PcaJdbcAtomicKv((javax.sql.DataSource) null)).getMessage());
        assertEquals("connections", assertThrows(NullPointerException.class, () -> new PcaJdbcStateStore((PcaJdbcStateStore.ConnectionFactory) null)).getMessage());
        assertEquals("connections", assertThrows(NullPointerException.class, () -> new PcaJdbcAtomicKv((PcaJdbcStateStore.ConnectionFactory) null)).getMessage());
        PcaJdbcStateStore.ConnectionFactory cf = () -> AuthorizeFixtures.sqliteConnection(db("c.db"));
        for (String bad : new String[] {null, "", "1x", "a-b", "x".repeat(64)}) {
            assertEquals("invalid table name", assertThrows(IllegalArgumentException.class, () -> new PcaJdbcStateStore(cf, bad)).getMessage(), bad);
            assertEquals("invalid table name", assertThrows(IllegalArgumentException.class, () -> new PcaJdbcAtomicKv(cf, bad)).getMessage(), bad);
        }
        new PcaJdbcStateStore(cf, "x".repeat(63));
        new PcaJdbcAtomicKv(cf, "_x9");
    }

    // ---- PcaJdbcStateStore ---------------------------------------------------------------------------------------------

    @Test void stateStoreAutoCommitsAndChecksTheFileOnce() throws Exception {
        Rec rec = new Rec();
        PcaJdbcStateStore s = new PcaJdbcStateStore(recording(db("s.db"), rec)).createTable();
        assertTrue(s.claim("k", 4).ok);
        assertEquals(StateStore.ClaimResult.replay(4L), s.claim("k", 4));
        assertTrue(s.consumeOnce("once", 20, 10));
        assertFalse(s.consumeOnce("once", 30, 10));
        assertEquals(Long.valueOf(4L), s.last("k"));
        assertNull(s.last("missing"));
        assertNull(s.last(null));
        // createTable + 2 claims + 2 consumeOnce set auto-commit (last only reads); never false
        assertEquals(5, rec.count("setAutoCommit:true"), rec.log.toString());
        assertEquals(0, rec.count("setAutoCommit:false"), rec.log.toString());
        assertEquals(1, rec.count("getMetaData"), "the file check runs on the first open only");
        assertEquals(7, rec.count("close"), "every borrowed connection is closed");

        StateStore.ClaimResult nul = s.claim(null, 1);
        assertFalse(nul.ok);
        assertNull(nul.lastCounter);
        assertEquals("consumeOnce: invalid key or retention horizon",
            assertThrows(IllegalArgumentException.class, () -> s.consumeOnce(null, 20, 10)).getMessage());
        assertEquals(7, rec.count("close"), "a refused argument opens nothing");
    }

    @Test void stateStoreWithoutAutoCommitStillPersists() throws Exception {
        // a pool may hand out connections with auto-commit off: the store switches it on, so a claim survives the close
        Path f = db("ac.db");
        PcaJdbcStateStore.ConnectionFactory off = () -> {
            Connection c = AuthorizeFixtures.sqliteConnection(f);
            c.setAutoCommit(false);
            return c;
        };
        PcaJdbcStateStore s = new PcaJdbcStateStore(off).createTable();
        assertTrue(s.claim("k", 2).ok);
        assertTrue(s.consumeOnce("o", 50, 10));
        PcaJdbcStateStore fresh = new PcaJdbcStateStore(() -> AuthorizeFixtures.sqliteConnection(f));
        assertEquals(Long.valueOf(2L), fresh.last("k"));
        assertFalse(fresh.consumeOnce("o", 50, 10));
        PcaJdbcAtomicKv kv = new PcaJdbcAtomicKv(off).createTable();
        kv.set("a", "x");
        assertEquals("y", kv.update("b", p -> "y"));
        PcaJdbcAtomicKv kv2 = new PcaJdbcAtomicKv(() -> AuthorizeFixtures.sqliteConnection(f));
        assertEquals("x", kv2.get("a"));
        assertEquals("y", kv2.get("b"));
    }

    @Test void aFailedFileCheckClosesTheConnectionAndIsRetried() {
        Rec rec = new Rec();
        PcaJdbcStateStore.ConnectionFactory mem = () -> (Connection) wrap(DriverManager.getConnection("jdbc:sqlite::memory:"), Connection.class, rec, null);
        PcaJdbcStateStore s = new PcaJdbcStateStore(mem);
        assertThrows(SQLException.class, s::createTable);
        assertThrows(IllegalStateException.class, () -> s.claim("k", 1));
        assertEquals(2, rec.count("getMetaData"), "a failed check is not remembered as passed");
        assertEquals(2, rec.count("close"));
        Rec rec2 = new Rec();
        PcaJdbcAtomicKv kv = new PcaJdbcAtomicKv(() -> (Connection) wrap(DriverManager.getConnection("jdbc:sqlite::memory:"), Connection.class, rec2, null));
        assertThrows(SQLException.class, kv::createTable);
        assertThrows(IllegalStateException.class, () -> kv.get("k"));
        assertEquals(2, rec2.count("getMetaData"));
        assertEquals(2, rec2.count("close"));
    }

    @Test void stateStoreErrorsCarryTheDatabaseMessage() {
        // no table: every statement fails
        PcaJdbcStateStore s = new PcaJdbcStateStore(() -> AuthorizeFixtures.sqliteConnection(db("none.db")));
        for (Runnable r : new Runnable[] {() -> s.claim("k", 1), () -> s.consumeOnce("k", 2, 1), () -> s.last("k")}) {
            IllegalStateException e = assertThrows(IllegalStateException.class, r::run);
            assertTrue(e.getCause() instanceof SQLException);
            assertEquals("replay store: " + e.getCause().getMessage(), e.getMessage());
        }
    }

    @Test void requireSqliteFileDatabase() throws Exception {
        // not SQLite: nothing to check (even over an in-memory SQLite underneath)
        Rec other = new Rec();
        other.product = "PostgreSQL";
        try (Connection c = (Connection) wrap(DriverManager.getConnection("jdbc:sqlite::memory:"), Connection.class, other, null)) {
            PcaJdbcStateStore.requireSqliteFileDatabase(c);
        }
        // the product name is compared case-insensitively
        Rec lower = new Rec();
        lower.product = "sqlite";
        try (Connection c = (Connection) wrap(DriverManager.getConnection("jdbc:sqlite::memory:"), Connection.class, lower, null)) {
            assertThrows(SQLException.class, () -> PcaJdbcStateStore.requireSqliteFileDatabase(c));
        }
        // a file database with an attached in-memory one: only the main database counts
        try (Connection c = AuthorizeFixtures.sqliteConnection(db("main.db")); Statement st = c.createStatement()) {
            st.executeUpdate("ATTACH DATABASE ':memory:' AS aux");
            PcaJdbcStateStore.requireSqliteFileDatabase(c);
        }
    }

    // ---- PcaJdbcAtomicKv -----------------------------------------------------------------------------------------------

    @Test void kvGetSetUpdate() throws Exception {
        Rec rec = new Rec();
        PcaJdbcAtomicKv kv = new PcaJdbcAtomicKv(recording(db("kv.db"), rec)).createTable();
        assertNull(kv.get("missing"));
        kv.set("a", AuthorizeFixtures.j("{'n':1}"));
        assertEquals("{\"n\":1}", Json.canonicalize(kv.get("a")));
        kv.set("a", "two");
        assertEquals("two", kv.get("a"));
        kv.set("b", "keep");
        kv.set("a", null);
        assertNull(kv.get("a"));
        assertEquals("keep", kv.get("b"));
        kv.set("never", null);
        assertNull(kv.get("never"));
        // update: fn null keeps (and returns) the stored value; an absent key stays absent
        assertEquals("keep", kv.update("b", p -> null));
        assertNull(kv.update("absent", p -> null));
        assertNull(kv.get("absent"));
        List<Object> seen = new ArrayList<>();
        assertEquals("keep!", kv.update("b", p -> { seen.add(p); return p + "!"; }));
        assertEquals("c", kv.update("c", p -> { seen.add(p); return "c"; }));
        assertEquals(java.util.Arrays.asList("keep", null), seen);
        assertEquals("keep!", kv.get("b"));
        assertEquals(0, rec.count("setAutoCommit:false"));
        // createTable, 5 gets... every call borrows one auto-commit connection, the file check ran once
        assertEquals(1, rec.count("getMetaData"));
        assertEquals(rec.count("close"), rec.count("setAutoCommit:true"), rec.log.toString());
    }

    @Test void kvCompareAndSetGivesUpAfterExactlyMaxAttempts() throws Exception {
        Rec rec = new Rec();
        PcaJdbcAtomicKv kv = new PcaJdbcAtomicKv(recording(db("cas.db"), rec)).createTable();
        kv.set("held", "v0");
        rec.loseCas = true;
        for (String key : new String[] {"held", "fresh"}) {
            AtomicInteger calls = new AtomicInteger();
            IllegalStateException e = assertThrows(IllegalStateException.class, () -> kv.update(key, p -> { calls.incrementAndGet(); return "v1"; }));
            assertEquals("kv store: compare-and-set kept losing (2000 attempts)", e.getMessage());
            assertEquals(PcaJdbcAtomicKv.MAX_ATTEMPTS, calls.get(), key);
        }
        rec.loseCas = false;
        assertEquals("v0", kv.get("held"));
        assertNull(kv.get("fresh"));
    }

    @Test void kvErrorsCarryTheDatabaseMessage() {
        PcaJdbcAtomicKv kv = new PcaJdbcAtomicKv(() -> AuthorizeFixtures.sqliteConnection(db("nokv.db")));
        for (Runnable r : new Runnable[] {() -> kv.get("k"), () -> kv.set("k", "v"), () -> kv.set("k", null), () -> kv.update("k", p -> "v")}) {
            IllegalStateException e = assertThrows(IllegalStateException.class, r::run);
            assertTrue(e.getCause() instanceof SQLException);
            assertEquals("kv store: " + e.getCause().getMessage(), e.getMessage());
        }
    }

    // ---- SQLite URLs, files and factories ------------------------------------------------------------------------------

    @Test void sqliteFileEdgeForms() {
        assertNull(PcaJdbcStateStore.sqliteFile("jdbc:sqlite:?cache=shared"));
        assertNull(PcaJdbcStateStore.sqliteFile("jdbc:sqlite:?"));
        assertNull(PcaJdbcStateStore.sqliteFile("jdbc:sqlite:x.db?MODE=MEMORY"));
        assertNull(PcaJdbcStateStore.sqliteFile("jdbc:sqlite:x.db?a=1& Mode=Ro "));
        assertNull(PcaJdbcStateStore.sqliteFile("jdbc:sqlite:x.db?a?b&mode=memory"), "only the first '?' starts the query");
        assertEquals(Paths.get("x.db").toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:x.db?"));
        assertEquals(Paths.get("x.db").toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:x.db?mode=rwc"));
        // without a '?' nothing is a parameter
        assertEquals(Paths.get("a&mode=ro").toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:a&mode=ro"));
        assertNull(PcaJdbcStateStore.sqliteFile("jdbc:sqlite:file://remote"));
        assertNull(PcaJdbcStateStore.sqliteFile("jdbc:sqlite:file://localhost"));
        assertEquals(Paths.get("/pca-h/x.db").toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:file://LocalHost/pca-h/x.db"));
        assertEquals(Paths.get("rel.db").toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:file:rel.db"));
        assertEquals(Paths.get("C:/x.db").toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:file:///C:/x.db"));
        assertEquals(Paths.get("/C/x.db").toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:file:///C/x.db"));
        assertNull(PcaJdbcStateStore.sqliteFile("jdbc:sqlite:file::memory:"));
        // percent-decoding: only %XX with two hex digits, anywhere including the very end
        if (java.io.File.separatorChar == '/') // a TAB (high digit 0) is not a legal Windows path character
            assertEquals(Paths.get("/pca-pd/A%g1%1g%4z\tx%4").toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:file:/pca-pd/%41%g1%1g%4z%09x%4"));
        assertEquals(Paths.get("/pca-pd/bA").toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:file:/pca-pd/b%41"));
        assertEquals(Paths.get("/pca-pd/b%").toAbsolutePath(), PcaJdbcStateStore.sqliteFile("jdbc:sqlite:file:/pca-pd/b%"));
    }

    @Test void ensureSqliteFileAtTheRootAndUnderAFile() throws Exception {
        // the root has no parent: nothing to create, the existing "file" is kept
        // (on Windows "/" is the current drive's root, which createFile refuses with NoSuchFileException)
        if (java.io.File.separatorChar == '/') assertEquals(Paths.get("/"), PcaJdbcStateStore.ensureSqliteFile("jdbc:sqlite:/"));
        else assertThrows(IOException.class, () -> PcaJdbcStateStore.ensureSqliteFile("jdbc:sqlite:/"));
        Path plain = Files.createFile(db("plain"));
        String under = "jdbc:sqlite:" + plain.resolve("sub").resolve("x.db");
        assertThrows(IOException.class, () -> PcaJdbcStateStore.ensureSqliteFile(under));
        SQLException e = assertThrows(SQLException.class, () -> PcaJdbcStateStore.sqliteConnections(under).get());
        assertTrue(e.getCause() instanceof IOException);
        assertEquals("cannot create the SQLite database file: " + e.getCause().getMessage(), e.getMessage());
        SQLiteDataSource ds = new SQLiteDataSource();
        ds.setUrl(under);
        IllegalStateException ise = assertThrows(IllegalStateException.class, () -> new PcaJdbcStateStore(ds));
        assertTrue(ise.getCause() instanceof IOException);
        assertEquals("cannot create the SQLite database file: " + ise.getCause().getMessage(), ise.getMessage());
        // a data source without a URL is used as it is
        new PcaJdbcStateStore(new SQLiteDataSource());
    }

    static int busyTimeout(Connection c) throws SQLException {
        try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery("PRAGMA busy_timeout")) {
            assertTrue(rs.next());
            return rs.getInt(1);
        }
    }

    @Test void sqliteConnectionsCarryTheProperties() throws Exception {
        String url = "jdbc:sqlite:" + db("props.db");
        try (Connection c = PcaJdbcStateStore.sqliteConnections(url).get()) {
            assertEquals(30000, busyTimeout(c));
        }
        Properties p = new Properties();
        p.setProperty("busy_timeout", "1234");
        try (Connection c = PcaJdbcStateStore.sqliteConnections(url, p).get()) {
            assertEquals(1234, busyTimeout(c));
        }
        try (Connection c = PcaJdbcStateStore.sqliteConnections(url, null).get()) {
            assertFalse(c.isClosed());
        }
        assertEquals("sqliteConnections needs a jdbc:sqlite: URL",
            assertThrows(IllegalArgumentException.class, () -> PcaJdbcStateStore.sqliteConnections(null)).getMessage());
        assertThrows(IllegalArgumentException.class, () -> PcaJdbcStateStore.sqliteConnections(null, p));
    }

    public static final class NonStringUrl {
        public Integer getUrl() { return 1; }
        public String getJdbcUrl() { return "jdbc:sqlite:from-jdbc-url"; }
    }

    public static final class ThrowingUrl {
        public String getUrl() { throw new IllegalStateException("no"); }
    }

    public static final class UpperUrl {
        public String getURL() { return "jdbc:sqlite:upper"; }
    }

    @Test void jdbcUrlOf() {
        assertEquals("jdbc:sqlite:from-jdbc-url", PcaJdbcStateStore.jdbcUrlOf(new NonStringUrl()));
        assertNull(PcaJdbcStateStore.jdbcUrlOf(new ThrowingUrl()));
        assertEquals("jdbc:sqlite:upper", PcaJdbcStateStore.jdbcUrlOf(new UpperUrl()));
    }
}
