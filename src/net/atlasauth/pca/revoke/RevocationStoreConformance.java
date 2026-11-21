package net.atlasauth.pca.revoke;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Conformance cases for a {@link RevocationStore}. Run them against your own store:
 * {@code for (Case c : RevocationStoreConformance.cases(MyStore::new, null)) c.run.run();}
 *
 * <p>Each case throws an AssertionError when the store breaks the contract. A store that passes keeps (kind, value) keys apart,
 * replaces rather than duplicates, hands out snapshots, and loses nothing under concurrent writes. Durability across a
 * restart is checked with {@code reopen}.
 */
public final class RevocationStoreConformance {
    private RevocationStoreConformance() {}

    /** A named check. */
    public static final class Case {
        public final String name;
        public final ThrowingRunnable run;
        Case(String name, ThrowingRunnable run) { this.name = name; this.run = run; }
    }

    /** A runnable that may throw. */
    public interface ThrowingRunnable { void run() throws Exception; }

    private static RevocationEntry entry(String kind, String value, String reason, Double notBefore) {
        List<String> prefix = kind.equals("prefix") ? Arrays.asList(value.split(",", -1)) : null;
        return new RevocationEntry(kind, value, prefix, reason != null ? reason : "r-" + kind + "-" + value, 1000, notBefore);
    }

    private static RevocationEntry entry(String kind, String value) { return entry(kind, value, null, null); }

    private static void check(boolean ok, String what) { if (!ok) throw new AssertionError(what); }

    private static List<String> sortedValues(List<RevocationEntry> xs) {
        List<RevocationEntry> c = new ArrayList<>(xs);
        c.sort((a, b) -> (a.kind + a.value).compareTo(b.kind + b.value));
        List<String> out = new ArrayList<>();
        for (RevocationEntry e : c) out.add(e.kind + "/" + e.value + "/" + e.reason + "/" + e.notBefore);
        return out;
    }

    /**
     * @param make a fresh, empty store each call
     * @param reopen for stores that persist: opens the same backing location again (null skips the durability case)
     */
    public static List<Case> cases(Supplier<RevocationStore> make, Function<RevocationStore, RevocationStore> reopen) {
        List<Case> cs = new ArrayList<>();
        cs.add(new Case("starts empty", () -> {
            check(make.get().all().isEmpty(), "a new store is not empty");
            check(make.get().get("cap", "x") == null, "a new store returns an entry");
        }));
        cs.add(new Case("add then get returns the whole entry, including notBefore", () -> {
            RevocationStore s = make.get();
            RevocationEntry e = entry("cap", "c1", null, 5000.0);
            s.add(e);
            RevocationEntry g = s.get("cap", "c1");
            check(g != null && sortedValues(List.of(g)).equals(sortedValues(List.of(e))), "get differs from add");
        }));
        cs.add(new Case("the same value under different kinds is kept apart", () -> {
            RevocationStore s = make.get();
            s.add(entry("cap", "k"));
            s.add(entry("holder", "k"));
            s.add(entry("issuer", "k"));
            check(s.all().size() == 3, "kinds collapsed");
            check(s.remove("holder", "k"), "remove said nothing was removed");
            check(s.get("cap", "k") != null && s.get("cap", "k").kind.equals("cap"), "cap lost");
            check(s.get("issuer", "k") != null && s.get("issuer", "k").kind.equals("issuer"), "issuer lost");
            check(s.get("holder", "k") == null, "holder kept");
        }));
        cs.add(new Case("add at an existing key replaces, it does not duplicate", () -> {
            RevocationStore s = make.get();
            s.add(entry("cap", "c", "first", null));
            s.add(entry("cap", "c", "second", null));
            check(s.all().size() == 1, "duplicated");
            check(s.get("cap", "c").reason.equals("second"), "not replaced");
        }));
        cs.add(new Case("remove reports whether something was removed, and only once", () -> {
            RevocationStore s = make.get();
            s.add(entry("cap", "c"));
            check(s.remove("cap", "c"), "first remove");
            check(!s.remove("cap", "c"), "second remove");
            check(!s.remove("cap", "never-added"), "remove of a missing key");
        }));
        cs.add(new Case("prefix paths that differ stay distinct", () -> {
            RevocationStore s = make.get();
            s.add(entry("prefix", "a,b"));
            s.add(entry("prefix", "a"));
            s.add(entry("prefix", "b,a"));
            check(s.all().size() == 3, "paths collapsed");
            check(s.remove("prefix", "a"), "remove a");
            List<String> left = new ArrayList<>();
            for (RevocationEntry e : s.all()) left.add(e.value);
            left.sort(null);
            check(left.equals(List.of("a,b", "b,a")), "wrong entries left: " + left);
        }));
        cs.add(new Case("all() is a snapshot: changing it does not change the store", () -> {
            RevocationStore s = make.get();
            s.add(entry("cap", "c"));
            List<RevocationEntry> snap = s.all();
            try {
                snap.remove(snap.size() - 1);
                snap.add(entry("cap", "forged"));
            } catch (UnsupportedOperationException ignored) { /* a read-only snapshot is fine */ }
            check(s.all().size() == 1, "snapshot edit reached the store");
            check(s.get("cap", "forged") == null, "forged entry reached the store");
        }));
        cs.add(new Case("clear drops everything", () -> {
            RevocationStore s = make.get();
            s.add(entry("cap", "c"));
            s.add(entry("prefix", "a,b"));
            s.clear();
            check(s.all().isEmpty(), "not empty after clear");
            check(s.get("cap", "c") == null, "entry after clear");
        }));
        cs.add(new Case("interleaved adds and removes from many threads lose nothing", () -> {
            RevocationStore s = make.get();
            int n = 200;
            ExecutorService ex = Executors.newFixedThreadPool(8);
            try {
                List<Future<Void>> fs = new ArrayList<>();
                for (int i = 0; i < n; i++) {
                    final int k = i;
                    Callable<Void> t = () -> {
                        // each task owns its pair (an odd task may run before its even neighbour): the survivors are the odd ones whatever the interleaving
                        if (k % 2 == 1) {
                            s.add(entry("cap", "c" + (k - 1)));
                            s.add(entry("cap", "c" + k));
                            s.remove("cap", "c" + (k - 1));
                        } else {
                            s.add(entry("cap", "tmp" + k));
                            s.remove("cap", "tmp" + k);
                        }
                        return null;
                    };
                    fs.add(ex.submit(t));
                }
                for (Future<Void> f : fs) f.get();
            } finally {
                ex.shutdown();
            }
            Set<String> left = new HashSet<>();
            for (RevocationEntry e : s.all()) left.add(e.value);
            check(left.size() == n / 2, "expected " + n / 2 + " entries, found " + left.size());
            for (int i = 0; i < n; i++) check(left.contains("c" + i) == (i % 2 == 1), "wrong membership for c" + i);
        }));
        if (reopen != null) {
            cs.add(new Case("entries survive reopening the store", () -> {
                RevocationStore s = make.get();
                RevocationEntry a = entry("cap", "durable", null, 9000.0);
                RevocationEntry b = entry("prefix", "r,m");
                s.add(a);
                s.add(b);
                s.add(entry("holder", "gone"));
                s.remove("holder", "gone");
                RevocationStore again = reopen.apply(s);
                check(sortedValues(again.all()).equals(sortedValues(List.of(a, b))), "reopened store differs");
            }));
        }
        return cs;
    }
}
