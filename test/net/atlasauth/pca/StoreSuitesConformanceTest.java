package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.Supplier;
import net.atlasauth.pca.storeconformance.BondStoreConformance;
import net.atlasauth.pca.storeconformance.BudgetLedgerConformance;
import net.atlasauth.pca.storeconformance.LedgerStoreConformance;
import net.atlasauth.pca.storeconformance.MeshWitnessStoreConformance;
import net.atlasauth.pca.storeconformance.Suite;
import org.junit.jupiter.api.Test;
import org.sqlite.SQLiteDataSource;

/**
 * Runs the bond, ledger, budget and mesh-witness conformance suites against the new stores (memory and durable SQLite) and checks that each
 * suite flags every bad store (a suite that passes a bad store is worthless).
 */
public class StoreSuitesConformanceTest {
    private final Path dir;
    private int n;

    public StoreSuitesConformanceTest() throws Exception { dir = Files.createTempDirectory("pca-suites"); }

    /** One isolated SQLite backend per call; each client is a new {@link PcaJdbcAtomicKv} on it (its own connections). */
    private synchronized Callable<Supplier<AtomicKv>> sqliteBackend() {
        return () -> {
            SQLiteDataSource ds = new SQLiteDataSource();
            Path file;
            synchronized (this) { file = dir.resolve("kv" + (n++) + ".db"); }
            ds.setUrl("jdbc:sqlite:" + file + "?busy_timeout=60000");
            new PcaJdbcAtomicKv(ds).createTable();
            return () -> new PcaJdbcAtomicKv(ds);
        };
    }

    private static void assertPasses(Suite.Report r, int minPassed) {
        assertEquals("pass", r.status, r.format());
        assertTrue(r.count("pass") >= minPassed, r.format());
    }

    // ---- ledger ----

    @Test void ledgerMemoryPasses() {
        Suite.Report r = LedgerStoreConformance.run(LedgerStoreConformance.memoryAdapter());
        assertPasses(r, 13);
        assertEquals("skip", r.check("state-survives-reopen").status);
    }

    @Test void ledgerSqlitePasses() {
        Suite.Report r = LedgerStoreConformance.run(LedgerStoreConformance.kvAdapter("KvLedgerStore over SQLite", true, sqliteBackend(), true));
        assertPasses(r, 15);
        assertEquals(0, r.count("skip"), r.format());
    }

    @Test void ledgerBadStoresAreFlagged() {
        for (Map.Entry<String, Supplier<LedgerStoreConformance.Adapter>> e : LedgerStoreConformance.referenceAdapters().entrySet()) {
            if (e.getKey().startsWith("bad-")) assertEquals("fail", LedgerStoreConformance.run(e.getValue().get()).status, e.getKey());
        }
    }

    // ---- bond ----

    @Test void bondMemoryPasses() {
        Suite.Report r = BondStoreConformance.run(BondStoreConformance.memoryAdapter());
        assertPasses(r, 18);
        assertEquals("skip", r.check("state-survives-reopen").status);
    }

    @Test void bondSqlitePasses() {
        Suite.Report r = BondStoreConformance.run(BondStoreConformance.kvAdapter("KvBondStore over SQLite", true, sqliteBackend(), true));
        assertPasses(r, 20);
        assertEquals(0, r.count("skip"), r.format());
    }

    @Test void bondBadStoresAreFlagged() {
        for (Map.Entry<String, Supplier<BondStoreConformance.Adapter>> e : BondStoreConformance.referenceAdapters().entrySet()) {
            if (e.getKey().startsWith("bad-")) assertEquals("fail", BondStoreConformance.run(e.getValue().get()).status, e.getKey());
        }
    }

    // ---- budget ----

    @Test void budgetMemoryPasses() {
        Suite.Report r = BudgetLedgerConformance.run(BudgetLedgerConformance.memoryAdapter());
        assertPasses(r, 20);
        assertEquals("skip", r.check("state-survives-reopen").status);
    }

    @Test void budgetSqlitePasses() {
        Suite.Report r = BudgetLedgerConformance.run(BudgetLedgerConformance.kvAdapter("KvBudgetLedger over SQLite", true, sqliteBackend(), true));
        assertPasses(r, 22);
        assertEquals(0, r.count("skip"), r.format());
    }

    @Test void budgetBadLedgersAreFlagged() {
        for (Map.Entry<String, Supplier<BudgetLedgerConformance.Adapter>> e : BudgetLedgerConformance.referenceAdapters().entrySet()) {
            if (e.getKey().startsWith("bad-")) assertEquals("fail", BudgetLedgerConformance.run(e.getValue().get()).status, e.getKey());
        }
    }

    // ---- mesh witness ----

    @Test void meshWitnessMemoryPasses() {
        assertPasses(MeshWitnessStoreConformance.run(MeshWitnessStoreConformance.memoryAdapter()), 7);
    }

    @Test void meshWitnessBadStoresAreFlagged() {
        for (Map.Entry<String, Supplier<MeshWitnessStoreConformance.Adapter>> e : MeshWitnessStoreConformance.referenceAdapters().entrySet()) {
            if (e.getKey().startsWith("bad-")) assertEquals("fail", MeshWitnessStoreConformance.run(e.getValue().get()).status, e.getKey());
        }
    }

    @Test void meshWitnessFileStorePasses() {
        Map<MeshWitnessStore, Path> paths = new HashMap<>();
        MeshWitnessStoreConformance.Adapter a = new MeshWitnessStoreConformance.Adapter() {
            @Override public String name() { return "FileMeshWitnessStore"; }
            @Override public MeshWitnessStore make() {
                Path p;
                synchronized (StoreSuitesConformanceTest.this) { p = dir.resolve("w" + (n++) + ".json"); }
                MeshWitnessStore s = new FileMeshWitnessStore(p);
                paths.put(s, p);
                return s;
            }
            @Override public boolean canReopen() { return true; }
            @Override public MeshWitnessStore reopen(MeshWitnessStore prev) {
                MeshWitnessStore s = new FileMeshWitnessStore(paths.get(prev));
                paths.put(s, paths.get(prev));
                return s;
            }
            @Override public boolean canDamage() { return true; }
            @Override public void damage(MeshWitnessStore s) throws Exception {
                Path p = paths.get(s);
                Map<String, Object> j = StoreJs.map(Json.parseLenient(new String(Files.readAllBytes(p), StandardCharsets.UTF_8)));
                Map<String, Object> head = StoreJs.map(StoreJs.map(((List<?>) StoreJs.map(j.get("state")).get("seen")).get(0)).get("head"));
                head.put("size", StoreJs.num(99)); // edit without fixing the digest
                Files.write(p, Json.canonicalize(j).getBytes(StandardCharsets.UTF_8));
            }
        };
        assertPasses(MeshWitnessStoreConformance.run(a), 10);
    }

    @Test void meshWitnessKvStorePasses() {
        Callable<Supplier<AtomicKv>> backend = sqliteBackend();
        Map<MeshWitnessStore, Supplier<AtomicKv>> clients = new HashMap<>();
        MeshWitnessStoreConformance.Adapter a = new MeshWitnessStoreConformance.Adapter() {
            @Override public String name() { return "KvMeshWitnessStore over SQLite"; }
            @Override public MeshWitnessStore make() throws Exception {
                Supplier<AtomicKv> c = backend.call();
                MeshWitnessStore s = new KvMeshWitnessStore(c.get());
                clients.put(s, c);
                return s;
            }
            @Override public boolean canReopen() { return true; }
            @Override public MeshWitnessStore reopen(MeshWitnessStore prev) {
                Supplier<AtomicKv> c = clients.get(prev);
                MeshWitnessStore s = new KvMeshWitnessStore(c.get());
                clients.put(s, c);
                return s;
            }
            @Override public boolean canDamage() { return true; }
            @Override public void damage(MeshWitnessStore s) {
                AtomicKv kv = clients.get(s).get();
                Map<String, Object> doc = StoreJs.map(StoreJs.deepCopy(kv.get(KvMeshWitnessStore.DOC_KEY)));
                StoreJs.map(StoreJs.map(((List<?>) StoreJs.map(doc.get("state")).get("seen")).get(0)).get("head")).put("size", StoreJs.num(99));
                kv.set(KvMeshWitnessStore.DOC_KEY, doc);
            }
        };
        assertPasses(MeshWitnessStoreConformance.run(a), 10);
    }

    @Test void fileWitnessStoreRefusesJunk() throws Exception {
        Path p = dir.resolve("junk.json");
        FileMeshWitnessStore s = new FileMeshWitnessStore(p);
        assertTrue(s.load() == null);
        Files.write(p, "not json".getBytes(StandardCharsets.UTF_8));
        assertThrows(IllegalStateException.class, s::load);
        Files.write(p, "{\"v\":2,\"state\":{},\"digest\":\"x\"}".getBytes(StandardCharsets.UTF_8));
        assertThrows(IllegalStateException.class, s::load);
        Files.write(p, "{\"v\":1,\"state\":{},\"digest\":\"x\"}".getBytes(StandardCharsets.UTF_8));
        assertThrows(IllegalStateException.class, s::load);
        List<Object> none = new ArrayList<>();
        Map<String, Object> st = new java.util.LinkedHashMap<>();
        st.put("seen", none);
        s.save(st);
        assertEquals(Json.canonicalize(st), Json.canonicalize(s.load()));
    }
}
