package net.atlasauth.pca.storeconformance;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.MemoryMeshWitnessStore;
import net.atlasauth.pca.MeshDomain;
import net.atlasauth.pca.MeshWitness;
import net.atlasauth.pca.MeshWitnessStore;
import net.atlasauth.pca.StoreJs;
import net.atlasauth.pca.storeconformance.Suite.Check;

/**
 * Conformance cases for a {@link MeshWitnessStore}: the durable memory of a mesh log witness. A witness cosigns a head only if it extends
 * the last head THIS witness cosigned. A store that forgets across a restart, or that loses a save and still lets the cosignature out, lets a
 * domain walk the witness back and show two verifiers different histories. The cases check the store by itself (round trip, replace, copy
 * semantics, atomicity, reopen) and through a real {@link MeshWitness} (every cosignature is persisted first; a restarted witness refuses
 * rollback and forks; a failed save refuses the cosignature and changes nothing; damaged storage is not read as empty).
 */
public final class MeshWitnessStoreConformance {
    private MeshWitnessStoreConformance() {}

    /** The adapter a store author implements. */
    public interface Adapter {
        String name();

        /** A fresh, empty store. */
        MeshWitnessStore make() throws Exception;

        /** True when {@link #reopen} is implemented (a store that can persist). */
        default boolean canReopen() { return false; }

        /** A new store object over the same backing storage as {@code previous} (a restart). */
        default MeshWitnessStore reopen(MeshWitnessStore previous) throws Exception { throw new UnsupportedOperationException("reopen"); }

        /** True when {@link #damage} is implemented (a store that can detect damage). */
        default boolean canDamage() { return false; }

        /** Damage the backing storage of {@code store} so that {@code load} must fail. */
        default void damage(MeshWitnessStore store) throws Exception { throw new UnsupportedOperationException("damage"); }
    }

    /** The environment of one case. */
    public static final class Env implements Suite.Handle {
        public final Adapter adapter;
        Env(Adapter adapter) { this.adapter = adapter; }
    }

    static byte[] seed(String label) {
        byte[] s = new byte[32];
        for (int i = 0; i < 32; i++) s[i] = (byte) ((label.charAt(i % label.length()) + i) & 0xff);
        return s;
    }

    static net.atlasauth.pca.Keys.EdKey key(String label) { return net.atlasauth.pca.Keys.edFromSeed(seed(label)); }

    static Map<String, Object> cap(String label) {
        Map<String, Object> cav = new LinkedHashMap<>();
        cav.put("type", "scope");
        cav.put("actions", new ArrayList<Object>(List.of(label)));
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("id", label);
        c.put("caveats", new ArrayList<Object>(List.of(cav)));
        return c;
    }

    /** Same domain key, different history: the second is a fork of the first from entry 0 on. */
    static MeshDomain[] twoLogs() {
        MeshDomain honest = new MeshDomain("d", key("domain")), fork = new MeshDomain("d", key("domain"));
        honest.record(cap("a"));
        fork.record(cap("x"));
        return new MeshDomain[] {honest, fork};
    }

    static Map<String, Object> state(long n) {
        Map<String, Object> head = new LinkedHashMap<>();
        head.put("domain", "d" + n);
        head.put("size", StoreJs.num(0));
        head.put("root", "");
        head.put("rev_root", "r");
        head.put("rev_size", StoreJs.num(0));
        head.put("timestamp", StoreJs.num(n));
        Map<String, Object> seen = new LinkedHashMap<>();
        seen.put("head", head);
        seen.put("rev_ids", new ArrayList<Object>());
        Map<String, Object> st = new LinkedHashMap<>();
        st.put("seen", new ArrayList<Object>(List.of(seen)));
        return st;
    }

    static int cosigs(Map<String, Object> ch) { return ((List<?>) ch.get("cosigs")).size(); }

    static String thrown(Runnable r) {
        try {
            r.run();
            return "";
        } catch (RuntimeException e) {
            return String.valueOf(e.getMessage());
        }
    }

    /** A store whose saves can be made to fail. */
    private static final class Flaky implements MeshWitnessStore {
        final MeshWitnessStore inner;
        volatile boolean failing;
        Flaky(MeshWitnessStore inner) { this.inner = inner; }
        @Override public Map<String, Object> load() { return inner.load(); }
        @Override public void save(Map<String, Object> st) {
            if (failing) throw new IllegalStateException("disk full");
            inner.save(st);
        }
    }

    /** The cases that apply to {@code a} (reopen and damage cases only when the adapter implements them). */
    public static List<Check<Env>> cases(Adapter a) {
        List<Check<Env>> cases = new ArrayList<>(List.of(
            new Check<Env>("a fresh store loads nothing", "a store that was never written loads null", e -> Suite.ok(a.make().load() == null, "a fresh store must load null")),
            new Check<Env>("save then load returns the same state", "what was saved is what loads", e -> {
                MeshWitnessStore s = a.make();
                s.save(state(1));
                Suite.eq(state(1), s.load());
            }),
            new Check<Env>("a later save replaces the earlier one", "the last save wins", e -> {
                MeshWitnessStore s = a.make();
                s.save(state(1));
                s.save(state(2));
                Suite.eq(state(2), s.load());
            }),
            new Check<Env>("load returns a copy: changing it does not change the store", "mutating a loaded state leaves the store alone", e -> {
                MeshWitnessStore s = a.make();
                s.save(state(1));
                Map<String, Object> got = s.load();
                ((List<?>) got.get("seen")).clear();
                Suite.eq(state(1), s.load());
            }),
            new Check<Env>("save keeps its own copy: changing the argument afterwards does not change the store", "mutating a saved state leaves the store alone", e -> {
                MeshWitnessStore s = a.make();
                Map<String, Object> st = state(1);
                s.save(st);
                ((List<?>) st.get("seen")).clear();
                Suite.eq(state(1), s.load());
            }),
            new Check<Env>("a witness persists every cosignature before returning it", "the stored state is the witness's state after each cosignature", e -> {
                MeshWitnessStore s = a.make();
                MeshWitness.Options o = new MeshWitness.Options();
                o.store = s;
                MeshWitness w = new MeshWitness(key("w"), o);
                MeshDomain honest = twoLogs()[0];
                Map<String, Object> ch = honest.publishHead(List.of(w), 1_000, null);
                Suite.eq(w.exportState(), s.load());
                List<Object> heads = new ArrayList<>();
                for (Object x : (List<?>) s.load().get("seen")) heads.add(StoreJs.map(x).get("head"));
                Suite.eq(List.of(ch.get("head")), heads);
            }),
            new Check<Env>("a failed save refuses the cosignature and leaves the witness unchanged", "the cosignature is released only after the state is saved", e -> {
                Flaky flaky = new Flaky(a.make());
                MeshWitness.Options o = new MeshWitness.Options();
                o.store = flaky;
                MeshWitness w = new MeshWitness(key("w"), o);
                MeshDomain honest = twoLogs()[0];
                honest.publishHead(List.of(w), 1_000, null);
                String before = Json.canonicalize(w.exportState());
                honest.record(cap("b"));
                flaky.failing = true;
                String threw = thrown(() -> honest.publishHead(List.of(w), 2_000, null));
                Suite.eq("witness: could not persist state; refusing to cosign", threw);
                Suite.eq(before, Json.canonicalize(w.exportState()));
                Suite.eq(Json.parseLenient(before), flaky.inner.load());
                flaky.failing = false;
                Suite.ok(cosigs(honest.publishHead(List.of(w), 2_000, null)) == 1, "the same head is cosigned once the disk recovers");
            })));
        if (a.canReopen()) {
            cases.add(new Check<Env>("state survives reopening the store", "a new store object over the same storage loads the saved state", e -> {
                MeshWitnessStore s = a.make();
                s.save(state(3));
                Suite.eq(state(3), a.reopen(s).load());
            }));
            cases.add(new Check<Env>("a restarted witness remembers what it cosigned: it refuses a fork and a rollback", "restart safety: a witness never cosigns a fork of what it saw", e -> {
                MeshWitnessStore s = a.make();
                MeshWitness.Options o = new MeshWitness.Options();
                o.store = s;
                MeshWitness w1 = new MeshWitness(key("w"), o);
                MeshDomain[] logs = twoLogs();
                MeshDomain honest = logs[0], fork = logs[1];
                honest.publishHead(List.of(w1), 1_000, null);
                honest.record(cap("b"));
                honest.publishHead(List.of(w1), 2_000, null);
                MeshWitness.Options o2 = new MeshWitness.Options();
                o2.store = a.reopen(s);
                MeshWitness w2 = new MeshWitness(key("w"), o2);
                Suite.eq(2, w2.lastSeen(honest.id).get("size"));
                fork.record(cap("y"));
                fork.record(cap("z"));
                Suite.ok(!thrown(() -> fork.publishHead(List.of(w2), 3_000, null)).isEmpty(), "a fork that grew past the remembered size must be refused");
                MeshDomain rollback = new MeshDomain("d", key("domain"));
                rollback.record(cap("a"));
                Suite.ok(!thrown(() -> rollback.publishHead(List.of(w2), 3_000, null)).isEmpty(), "a rollback to the first head must be refused");
                Suite.ok(cosigs(honest.publishHead(List.of(w2), 3_000, null)) == 1, "the honest log is still cosigned");
            }));
        }
        if (a.canDamage()) {
            cases.add(new Check<Env>("damaged storage makes load throw, so a witness never starts empty over it", "damaged storage is refused, never read as empty", e -> {
                MeshWitnessStore s = a.make();
                // a state a witness accepts, so that only the damage can make construction fail
                MeshWitness w0 = new MeshWitness(key("w"));
                MeshDomain d0 = new MeshDomain("d", key("domain"));
                d0.record(cap("a"));
                d0.publishHead(List.of(w0), 1_000, null);
                s.save(w0.exportState());
                a.damage(s);
                Suite.ok(!thrown(s::load).isEmpty(), "load must throw on damaged storage");
                MeshWitness.Options o = new MeshWitness.Options();
                o.store = s;
                Suite.ok(!thrown(() -> new MeshWitness(key("w"), o)).isEmpty(), "constructing a witness over damaged storage must throw");
            }));
        }
        return cases;
    }

    /** Run the cases that apply to {@code adapter}. */
    public static Suite.Report run(Adapter adapter) {
        return Suite.run("mesh witness store", adapter.name(), true, () -> new Env(adapter), cases(adapter), null);
    }

    /** GOOD, in process: the memory store (no reopen, no damage). */
    public static Adapter memoryAdapter() {
        return new Adapter() {
            @Override public String name() { return "MemoryMeshWitnessStore"; }
            @Override public MeshWitnessStore make() { return new MemoryMeshWitnessStore(); }
        };
    }

    /** BAD: a store that forgets everything (load nothing, save nothing). The suite MUST flag it. */
    public static Adapter forgetfulAdapter() {
        MeshWitnessStore forget = new MeshWitnessStore() {
            @Override public Map<String, Object> load() { return null; }
            @Override public void save(Map<String, Object> st) { /* forgets */ }
        };
        return new Adapter() {
            @Override public String name() { return "BAD forgetful (loads nothing, saves nothing)"; }
            @Override public MeshWitnessStore make() { return forget; }
            @Override public boolean canReopen() { return true; }
            @Override public MeshWitnessStore reopen(MeshWitnessStore previous) { return forget; }
        };
    }

    /** BAD: a store that accepts a save but returns a stale copy (a lost update); flagged by the round-trip and persistence cases. */
    public static Adapter staleAdapter() {
        return new Adapter() {
            @Override public String name() { return "BAD stale (keeps the first state it was given)"; }
            @Override public MeshWitnessStore make() {
                return new MeshWitnessStore() {
                    private Map<String, Object> first;
                    @Override public synchronized Map<String, Object> load() { return first == null ? null : StoreJs.map(StoreJs.deepCopy(first)); }
                    @Override public synchronized void save(Map<String, Object> st) { if (first == null) first = StoreJs.map(StoreJs.deepCopy(st)); }
                };
            }
        };
    }

    /** The reference adapters by name (the bad ones are positive controls). */
    public static Map<String, Supplier<Adapter>> referenceAdapters() {
        Map<String, Supplier<Adapter>> m = new LinkedHashMap<>();
        m.put("mesh-witness-memory", MeshWitnessStoreConformance::memoryAdapter);
        m.put("bad-mesh-witness-forgetful", MeshWitnessStoreConformance::forgetfulAdapter);
        m.put("bad-mesh-witness-stale", MeshWitnessStoreConformance::staleAdapter);
        return m;
    }
}
