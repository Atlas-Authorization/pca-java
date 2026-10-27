package net.atlasauth.pca;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * The shared authorize fixtures (pca-authorize-fixtures/1, signed by the TypeScript reference, which also recorded its
 * own authorize() outcome per step as {@code ts}) and small helpers for the authorize tests.
 */
public final class AuthorizeFixtures {
    private AuthorizeFixtures() {}

    public static final String FILE = "test-data/authorize-fixtures.json";
    public static final String PYTHON_COPY = "../python-pca/testdata/authorize-fixtures.json";
    public static final String VECTORS = "conformance/vectors.json";

    private static Map<String, Object> doc;

    @SuppressWarnings("unchecked")
    public static synchronized Map<String, Object> doc() {
        if (doc == null) {
            try {
                doc = (Map<String, Object>) Json.parseLenient(Files.readString(Path.of(FILE)));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
        return doc;
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> cases() { return (List<Map<String, Object>>) (List<?>) doc().get("cases"); }

    public static long now() { return Json.asLong(doc().get("now")); }

    public static String audience() { return (String) doc().get("audience"); }

    public static Map<String, Object> kase(String name) {
        for (Map<String, Object> c : cases()) if (name.equals(c.get("name"))) return c;
        throw new IllegalArgumentException("no fixture case " + name);
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> grant(Map<String, Object> c) { return (Map<String, Object>) c.get("grant"); }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> step(Map<String, Object> c, int i) { return (Map<String, Object>) ((List<Object>) c.get("steps")).get(i); }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> pcactn(Map<String, Object> c, int i) { return (Map<String, Object>) step(c, i).get("pcactn"); }

    @SuppressWarnings("unchecked")
    public static Authorize.Operation operation(Map<String, Object> c, int i) {
        Map<String, Object> op = (Map<String, Object>) step(c, i).get("operation");
        return Authorize.Operation.of((String) op.get("verb"), (String) op.get("resource"), (Map<String, Object>) op.get("params"));
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> params(Map<String, Object> c, int i) {
        return (Map<String, Object>) ((Map<String, Object>) step(c, i).get("operation")).get("params");
    }

    /** {allow, status, sorted failing checks}. */
    public static Map<String, Object> settle(Authorize.AuthorizeResult r) {
        List<String> failed = new ArrayList<>(r.failed());
        Collections.sort(failed);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("allow", r.allow);
        m.put("status", (long) r.status);
        m.put("failed", failed);
        return m;
    }

    /** The {@code expect} / {@code ts} object of a step in the {@link #settle} shape. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> want(Object o, boolean withFailed) {
        Map<String, Object> e = (Map<String, Object>) o;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("allow", e.get("allow"));
        m.put("status", Json.asLong(e.get("status")));
        if (withFailed) {
            List<String> f = new ArrayList<>((List<String>) (List<?>) e.get("failed"));
            Collections.sort(f);
            m.put("failed", f);
        }
        return m;
    }

    /** The base input of a fixture step: memory store, never revoked, fixture clock, single-step plan. */
    public static Authorize.Input input(Map<String, Object> c, int i) {
        Map<String, Object> g = grant(c);
        return new Authorize.Input().operation(operation(c, i)).audience(audience()).resolveGrant(ref -> g)
            .stateStore(new MemoryStateStore()).isRevoked((p, gr) -> false).now(now()).plan(Authorize.SINGLE_STEP);
    }

    /** A SQLite store on a file (one connection per claim, 30 s busy timeout). */
    public static PcaJdbcStateStore sqlite(Path file) throws Exception {
        return new PcaJdbcStateStore(() -> sqliteConnection(file)).createTable();
    }

    public static Connection sqliteConnection(Path file) throws java.sql.SQLException {
        Properties props = new Properties();
        props.setProperty("busy_timeout", "30000");
        return DriverManager.getConnection("jdbc:sqlite:" + file.toAbsolutePath(), props);
    }

    /** A JSON tree from text written with single quotes. */
    public static Object j(String text) { return Json.parseLenient(text.replace('\'', '"')); }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> jm(String text) { return (Map<String, Object>) j(text); }
}
