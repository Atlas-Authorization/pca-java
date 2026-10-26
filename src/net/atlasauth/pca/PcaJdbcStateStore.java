package net.atlasauth.pca;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Objects;
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
 */
public final class PcaJdbcStateStore implements StateStore {
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

    /** A store on {@code dataSource}, table {@value #TABLE}. Call {@link #createTable()} once (or create it yourself). */
    public PcaJdbcStateStore(DataSource dataSource) {
        this(Objects.requireNonNull(dataSource, "dataSource")::getConnection, TABLE);
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
        this.select = "SELECT last_counter FROM " + table + " WHERE key = ?";
    }

    /** {@code CREATE TABLE IF NOT EXISTS <table> (key VARCHAR(512) NOT NULL PRIMARY KEY, last_counter BIGINT NOT NULL)}. */
    public PcaJdbcStateStore createTable() throws SQLException {
        try (Connection c = connections.get(); Statement st = c.createStatement()) {
            c.setAutoCommit(true);
            st.executeUpdate("CREATE TABLE IF NOT EXISTS " + table
                + " (key VARCHAR(512) NOT NULL PRIMARY KEY, last_counter BIGINT NOT NULL)");
        }
        return this;
    }

    /** The atomic claim. A database error is thrown as an unchecked {@link IllegalStateException} (authorize denies). */
    @Override
    public ClaimResult claim(String key, long counter) {
        if (key == null) return ClaimResult.replay(null);
        try (Connection c = connections.get()) {
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
}
