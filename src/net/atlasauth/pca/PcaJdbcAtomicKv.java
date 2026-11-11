package net.atlasauth.pca;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Objects;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;

import javax.sql.DataSource;

/**
 * Durable {@link AtomicKv} over plain JDBC: one row per key, the value is its canonical JSON text. {@link #update} is a
 * compare-and-set loop of single statements (an insert that does nothing on conflict when the key is absent, an
 * {@code UPDATE ... WHERE v = <the text read>} otherwise), so concurrent threads, connections and processes can never both
 * win the same transition. The dialect is the SQLite (3.24+) / PostgreSQL (9.5+) upsert; no driver is bundled. Each call
 * borrows one connection in auto-commit mode and closes it afterwards.
 *
 * <p>SQLite: open it with {@link PcaJdbcStateStore#sqliteConnections(String)} (or a {@link DataSource} whose {@code getUrl()}/
 * {@code getJdbcUrl()} is the {@code jdbc:sqlite:} URL); both create the database file atomically before the driver opens it. On a
 * missing path, org.xerial:sqlite-jdbc's open probe ({@code createNewFile()} then {@code delete()}) can unlink a file another
 * connection already opened and wrote to (the values stored there are lost: a replay would be admitted). A bare
 * {@link PcaJdbcStateStore.ConnectionFactory} is checked on first use to be a database FILE (in-memory/temporary SQLite is refused).
 */
public final class PcaJdbcAtomicKv implements AtomicKv {
    /** The default table name. */
    public static final String TABLE = "pca_kv";
    /** A compare-and-set that keeps losing this many times in a row gives up (it throws: the caller cannot tell the outcome). */
    static final int MAX_ATTEMPTS = 2000;
    private static final Pattern NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,62}");

    private final PcaJdbcStateStore.ConnectionFactory connections;
    private final String table;
    private volatile boolean fileChecked;

    public PcaJdbcAtomicKv(DataSource dataSource) {
        this(PcaJdbcStateStore.sqliteReady(Objects.requireNonNull(dataSource, "dataSource"))::getConnection, TABLE);
    }

    public PcaJdbcAtomicKv(PcaJdbcStateStore.ConnectionFactory connections) {
        this(connections, TABLE);
    }

    public PcaJdbcAtomicKv(PcaJdbcStateStore.ConnectionFactory connections, String table) {
        this.connections = Objects.requireNonNull(connections, "connections");
        if (table == null || !NAME.matcher(table).matches()) throw new IllegalArgumentException("invalid table name");
        this.table = table;
    }

    private Connection open() throws SQLException {
        Connection c = connections.get();
        if (!fileChecked) {
            try {
                PcaJdbcStateStore.requireSqliteFileDatabase(c);
            } catch (SQLException e) {
                c.close();
                throw e;
            }
            fileChecked = true;
        }
        return c;
    }

    /** {@code CREATE TABLE IF NOT EXISTS <table> (k VARCHAR(512) NOT NULL PRIMARY KEY, v TEXT NOT NULL)}. */
    public PcaJdbcAtomicKv createTable() throws SQLException {
        try (Connection c = open(); Statement st = c.createStatement()) {
            c.setAutoCommit(true);
            st.executeUpdate("CREATE TABLE IF NOT EXISTS " + table + " (k VARCHAR(512) NOT NULL PRIMARY KEY, v TEXT NOT NULL)");
        }
        return this;
    }

    private String read(Connection c, String key) throws SQLException {
        try (PreparedStatement st = c.prepareStatement("SELECT v FROM " + table + " WHERE k = ?")) {
            st.setString(1, key);
            try (ResultSet rs = st.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            }
        }
    }

    @Override
    public Object get(String key) {
        try (Connection c = open()) {
            c.setAutoCommit(true);
            String text = read(c, key);
            return text == null ? null : Json.parseLenient(text);
        } catch (SQLException e) {
            throw new IllegalStateException("kv store: " + e.getMessage(), e);
        }
    }

    @Override
    public void set(String key, Object value) {
        try (Connection c = open()) {
            c.setAutoCommit(true);
            if (value == null) {
                try (PreparedStatement st = c.prepareStatement("DELETE FROM " + table + " WHERE k = ?")) {
                    st.setString(1, key);
                    st.executeUpdate();
                }
                return;
            }
            try (PreparedStatement st = c.prepareStatement("INSERT INTO " + table + " (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v")) {
                st.setString(1, key);
                st.setString(2, Json.canonicalize(value));
                st.executeUpdate();
            }
        } catch (SQLException e) {
            throw new IllegalStateException("kv store: " + e.getMessage(), e);
        }
    }

    @Override
    public Object update(String key, UnaryOperator<Object> fn) {
        try (Connection c = open()) {
            c.setAutoCommit(true);
            for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
                String text = read(c, key);
                Object next = fn.apply(text == null ? null : Json.parseLenient(text));
                if (next == null) return text == null ? null : Json.parseLenient(text);
                String nextText = Json.canonicalize(next);
                int rows;
                if (text == null) {
                    try (PreparedStatement st = c.prepareStatement("INSERT INTO " + table + " (k, v) VALUES (?, ?) ON CONFLICT(k) DO NOTHING")) {
                        st.setString(1, key);
                        st.setString(2, nextText);
                        rows = st.executeUpdate();
                    }
                } else {
                    try (PreparedStatement st = c.prepareStatement("UPDATE " + table + " SET v = ? WHERE k = ? AND v = ?")) {
                        st.setString(1, nextText);
                        st.setString(2, key);
                        st.setString(3, text);
                        rows = st.executeUpdate();
                    }
                }
                if (rows == 1) return Json.parseLenient(nextText);
            }
            throw new IllegalStateException("kv store: compare-and-set kept losing (" + MAX_ATTEMPTS + " attempts)");
        } catch (SQLException e) {
            throw new IllegalStateException("kv store: " + e.getMessage(), e);
        }
    }
}
