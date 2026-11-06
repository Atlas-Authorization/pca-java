package net.atlasauth.pca;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Locale;
import java.util.Objects;
import java.util.Properties;
import java.util.regex.Pattern;

import javax.sql.DataSource;

/**
 * Durable {@link StateStore} over plain JDBC: one row per counter stream, {@code key} is the PRIMARY KEY.
 *
 * <p>The claim is ONE statement, {@code INSERT ... ON CONFLICT(key) DO UPDATE SET last_counter = excluded.last_counter
 * WHERE excluded.last_counter > <table>.last_counter}; one affected row means this call consumed the counter. The
 * database runs it atomically, so concurrent threads, connections and processes can never both consume the same
 * counter. The dialect is the SQLite (3.24+) / PostgreSQL (9.5+) upsert. No driver is bundled: pass the
 * {@link DataSource} (or connection factory) of the database you already use. Each claim borrows one connection in
 * auto-commit mode and closes it afterwards (a pooled data source gets it back).
 *
 * <p>SQLite: open it with {@link #sqliteConnections(String)} (or a {@link DataSource} whose {@code getUrl()}/{@code getJdbcUrl()}
 * is the {@code jdbc:sqlite:} URL). Both create the database file atomically BEFORE the driver opens it: on a missing path,
 * org.xerial:sqlite-jdbc's open probe ({@code createNewFile()} then {@code delete()}) can unlink a file another connection already
 * opened and wrote claims to (a replay would then be admitted). A bare {@link ConnectionFactory} cannot be checked before its
 * first open (the probe runs inside it), so it is checked on first use to be a database FILE: an in-memory or temporary SQLite
 * database is refused (each connection would see its own empty database).
 */
public final class PcaJdbcStateStore implements StateStore, LastStore {
    /** The default table name. */
    public static final String TABLE = "pca_replay";
    private static final Pattern NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}");

    /** Opens a connection; {@code DataSource::getConnection} is one. */
    @FunctionalInterface
    public interface ConnectionFactory {
        Connection get() throws SQLException;
    }

    private final ConnectionFactory connections;
    private final String table;
    private final String upsert;
    private final String select;
    private final String ttlTable;
    private volatile boolean fileChecked;

    /** A store on {@code dataSource}, table {@value #TABLE}. Call {@link #createTable()} once (or create it yourself). */
    public PcaJdbcStateStore(DataSource dataSource) {
        this(sqliteReady(Objects.requireNonNull(dataSource, "dataSource"))::getConnection, TABLE);
    }

    /** A store on connections from {@code connections}, table {@value #TABLE}. */
    public PcaJdbcStateStore(ConnectionFactory connections) {
        this(connections, TABLE);
    }

    /** A store on connections from {@code connections} and the given table name (letters, digits, underscore). */
    public PcaJdbcStateStore(ConnectionFactory connections, String table) {
        this.connections = Objects.requireNonNull(connections, "connections");
        if (table == null || !NAME.matcher(table).matches()) throw new IllegalArgumentException("invalid table name");
        this.table = table;
        this.upsert = "INSERT INTO " + table + " (key, last_counter) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET "
            + "last_counter = excluded.last_counter WHERE excluded.last_counter > " + table + ".last_counter";
        this.ttlTable = table + "_ttl";
        this.select = "SELECT last_counter FROM " + table + " WHERE key = ?";
    }

    private Connection open() throws SQLException {
        Connection c = connections.get();
        if (!fileChecked) {
            try {
                requireSqliteFileDatabase(c);
            } catch (SQLException e) {
                c.close();
                throw e;
            }
            fileChecked = true;
        }
        return c;
    }

    private static final String SQLITE_URL = "jdbc:sqlite:";
    private static final Pattern WINDOWS_DRIVE = Pattern.compile("^/[A-Za-z]:");

    /**
     * The database file a {@code jdbc:sqlite:} URL names (a plain path, relative to the working directory, or a {@code file:}
     * URI), or null when there is none to create: not a SQLite URL, in memory ({@code :memory:}, empty, {@code mode=memory}),
     * read-only ({@code mode=ro}), a classpath {@code :resource:}, or a {@code file:} URI with a remote authority.
     */
    public static Path sqliteFile(String jdbcUrl) {
        if (jdbcUrl == null || !jdbcUrl.startsWith(SQLITE_URL)) return null;
        String rest = jdbcUrl.substring(SQLITE_URL.length());
        String[] parts = rest.split("\\?", 2); // name ? query (the first '?' separates them)
        String name = parts[0];
        if (parts.length > 1) {
            for (String p : parts[1].split("&")) {
                String param = p.trim().toLowerCase(Locale.ROOT);
                if (param.equals("mode=memory") || param.equals("mode=ro")) return null;
            }
        }
        if (name.isEmpty() || name.equals(":memory:") || name.startsWith(":resource:")) return null;
        if (!name.startsWith("file:")) return Paths.get(name).toAbsolutePath();
        String p = name.substring("file:".length());
        if (p.startsWith("//")) { // file://[localhost]/path
            int slash = p.indexOf('/', 2);
            if (slash == -1) return null;
            String host = p.substring(2, slash);
            if (!host.isEmpty() && !host.equalsIgnoreCase("localhost")) return null;
            p = p.substring(slash);
        }
        p = percentDecode(p);
        if (WINDOWS_DRIVE.matcher(p).find()) p = p.substring(1); // file:///C:/x on Windows
        return p.isEmpty() || p.equals(":memory:") ? null : Paths.get(p).toAbsolutePath();
    }

    /** Create the database file of a {@code jdbc:sqlite:} URL (and its directories) if absent, atomically (CREATE_NEW); the file, or null (see {@link #sqliteFile}). */
    public static Path ensureSqliteFile(String jdbcUrl) throws IOException {
        Path f = sqliteFile(jdbcUrl);
        if (f == null) return null;
        if (f.getParent() != null) Files.createDirectories(f.getParent());
        try {
            Files.createFile(f);
        } catch (FileAlreadyExistsException ignored) {
            // another opener (or an earlier run) created it: exactly what we need
        }
        return f;
    }

    /** {@link #sqliteConnections(String, Properties)} with {@code busy_timeout} 30 s. */
    public static ConnectionFactory sqliteConnections(String jdbcUrl) {
        Properties props = new Properties();
        props.setProperty("busy_timeout", "30000");
        return sqliteConnections(jdbcUrl, props);
    }

    /**
     * The recommended SQLite {@link ConnectionFactory}: each open first creates the database file if absent
     * ({@link #ensureSqliteFile}), so the driver never runs its create-then-delete probe, then opens {@code jdbcUrl}.
     */
    public static ConnectionFactory sqliteConnections(String jdbcUrl, Properties properties) {
        if (jdbcUrl == null || !jdbcUrl.startsWith(SQLITE_URL)) throw new IllegalArgumentException("sqliteConnections needs a jdbc:sqlite: URL");
        Properties props = new Properties();
        if (properties != null) props.putAll(properties);
        return () -> {
            try {
                ensureSqliteFile(jdbcUrl);
            } catch (IOException e) {
                throw new SQLException("cannot create the SQLite database file: " + e.getMessage(), e);
            }
            return DriverManager.getConnection(jdbcUrl, props);
        };
    }

    /** Pre-create the file of a SQLite DataSource (found by its public {@code getUrl()}, {@code getJdbcUrl()} or {@code getURL()}) before any open. */
    static DataSource sqliteReady(DataSource dataSource) {
        try {
            ensureSqliteFile(jdbcUrlOf(dataSource)); // no URL: nothing to create
        } catch (IOException e) {
            throw new IllegalStateException("cannot create the SQLite database file: " + e.getMessage(), e);
        }
        return dataSource;
    }

    static String jdbcUrlOf(Object dataSource) {
        for (String name : new String[] {"getUrl", "getJdbcUrl", "getURL"}) {
            Method m;
            try {
                m = dataSource.getClass().getMethod(name);
            } catch (NoSuchMethodException e) {
                continue;
            }
            if (m.getReturnType() != String.class) continue;
            try {
                return (String) m.invoke(dataSource);
            } catch (ReflectiveOperationException e) {
                return null;
            }
        }
        return null;
    }

    /** Refuse a SQLite connection whose main database is not a file (in memory or temporary: private to that connection). */
    static void requireSqliteFileDatabase(Connection c) throws SQLException {
        if (!"SQLite".equalsIgnoreCase(c.getMetaData().getDatabaseProductName())) return;
        String file = null;
        try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery("PRAGMA database_list")) {
            while (rs.next()) if ("main".equals(rs.getString(2))) file = rs.getString(3);
        }
        if (Objects.toString(file, "").isEmpty()) // no main row, or an in-memory / temporary one
            throw new SQLException("the SQLite database is in memory or temporary: each connection would see its own empty database, so a replay could not be refused (use a database file)");
    }

    private static String percentDecode(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream(b.length);
        int i = 0;
        while (i < b.length) {
            int hi = b[i] == '%' && i + 2 < b.length ? Character.digit(b[i + 1], 16) : -1;
            int lo = hi >= 0 ? Character.digit(b[i + 2], 16) : -1;
            if (lo >= 0) {
                out.write(hi * 16 + lo);
                i += 3;
            } else {
                out.write(b[i]);
                i++;
            }
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    /** {@code CREATE TABLE IF NOT EXISTS <table> (key VARCHAR(512) NOT NULL PRIMARY KEY, last_counter BIGINT NOT NULL)}. */
    public PcaJdbcStateStore createTable() throws SQLException {
        try (Connection c = open(); Statement st = c.createStatement()) {
            c.setAutoCommit(true);
            st.executeUpdate("CREATE TABLE IF NOT EXISTS " + table
                + " (key VARCHAR(512) NOT NULL PRIMARY KEY, last_counter BIGINT NOT NULL)");
            st.executeUpdate("CREATE TABLE IF NOT EXISTS " + ttlTable
                + " (key VARCHAR(512) NOT NULL PRIMARY KEY, retain_until BIGINT NOT NULL)");
        }
        return this;
    }

    /** The atomic claim. A database error is thrown as an unchecked {@link IllegalStateException} (authorize denies). */
    @Override
    public ClaimResult claim(String key, long counter) {
        if (key == null) return ClaimResult.replay(null);
        try (Connection c = open()) {
            c.setAutoCommit(true);
            try (PreparedStatement st = c.prepareStatement(upsert)) {
                st.setString(1, key);
                st.setLong(2, counter);
                if (st.executeUpdate() == 1) return ClaimResult.claimed();
            }
            try (PreparedStatement st = c.prepareStatement(select)) {
                st.setString(1, key);
                try (ResultSet rs = st.executeQuery()) {
                    return ClaimResult.replay(rs.next() ? rs.getLong(1) : null);
                }
            }
        } catch (SQLException e) {
            throw new IllegalStateException("replay store: " + e.getMessage(), e);
        }
    }

    /**
     * TTL'd consume-once on {@code <table>_ttl} (created by {@link #createTable()}): ONE upsert that only overwrites an
     * EXPIRED row ({@code retain_until < now}); one affected row means this call consumed the key. A live row only has its
     * horizon raised (never lowered), and expired rows are pruned. A database error is an unchecked {@link IllegalStateException}.
     */
    @Override
    public boolean consumeOnce(String key, long retainUntilMs, long nowMs) {
        if (key == null || key.isEmpty() || retainUntilMs < nowMs) throw new IllegalArgumentException("consumeOnce: invalid key or retention horizon");
        try (Connection c = open()) {
            c.setAutoCommit(true);
            boolean took;
            try (PreparedStatement st = c.prepareStatement("INSERT INTO " + ttlTable + " (key, retain_until) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET "
                + "retain_until = excluded.retain_until WHERE " + ttlTable + ".retain_until < ?")) {
                st.setString(1, key);
                st.setLong(2, retainUntilMs);
                st.setLong(3, nowMs);
                took = st.executeUpdate() == 1;
            }
            if (!took) {
                try (PreparedStatement st = c.prepareStatement("UPDATE " + ttlTable + " SET retain_until = ? WHERE key = ? AND retain_until < ?")) {
                    st.setLong(1, retainUntilMs);
                    st.setString(2, key);
                    st.setLong(3, retainUntilMs);
                    st.executeUpdate();
                }
            }
            try (PreparedStatement st = c.prepareStatement("DELETE FROM " + ttlTable + " WHERE retain_until < ?")) {
                st.setLong(1, nowMs);
                st.executeUpdate();
            }
            return took;
        } catch (SQLException e) {
            throw new IllegalStateException("replay store: " + e.getMessage(), e);
        }
    }

    /** The last admitted counter of {@code key} (null: none yet). A database error is an unchecked {@link IllegalStateException}. */
    @Override
    public Long last(String key) {
        if (key == null) return null;
        try (Connection c = open(); PreparedStatement st = c.prepareStatement(select)) {
            st.setString(1, key);
            try (ResultSet rs = st.executeQuery()) {
                return rs.next() ? rs.getLong(1) : null;
            }
        } catch (SQLException e) {
            throw new IllegalStateException("replay store: " + e.getMessage(), e);
        }
    }
}
