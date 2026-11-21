package net.atlasauth.pca.scitt;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Supplier;
import net.atlasauth.pca.Keys;
import net.atlasauth.pca.scitt.Scitt.ConsistencyProofResult;
import net.atlasauth.pca.scitt.Scitt.ReceiptSignerOpts;
import net.atlasauth.pca.scitt.Scitt.SignStatementOpts;
import net.atlasauth.pca.scitt.ScittLogStore.StoredNode;

/**
 * A durable SCITT Transparency Service. The log keeps the hash of every complete aligned subtree in a {@link ScittLogStore}, so an
 * append is O(log n) store reads and writes, the root is O(log n) and a proof O(log^2 n) reads. State lives entirely in the store you
 * supply (a database, an object store, a file): a restart loses nothing and the service holds no log state of its own.
 */
public final class DurableTransparencyService {
    private static final int MAX_APPEND_ATTEMPTS = 16;

    private final ScittLogStore store;
    private final Reader reader;
    private final ReceiptSignerOpts signer;

    /** The result of registering or re-issuing: index, receipt, root (b64u) and, for appendAndReceipt, the statement. */
    public static final class Registration {
        public final long index;
        public final byte[] receipt;
        public final String root;
        /** The signed statement (appendAndReceipt only), else null. */
        public final byte[] statement;

        public Registration(long index, byte[] receipt, String root, byte[] statement) {
            this.index = index;
            this.receipt = receipt;
            this.root = root;
            this.statement = statement;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            if (statement != null) m.put("statement", statement);
            m.put("index", index);
            m.put("receipt", receipt);
            m.put("root", root);
            return m;
        }
    }

    public DurableTransparencyService(ScittLogStore store, ReceiptSignerOpts signer) {
        if (store == null) throw new ScittLogError("store_required", "a ScittLogStore (size, getEntry, getNode, append) is required; there is no in-memory default");
        this.store = store;
        this.reader = new Reader(store);
        this.signer = signer;
    }

    private static boolean isPow2(long n) { return n > 0 && (n & (n - 1)) == 0; }

    private static long largestPow2Below(long n) {
        long k = 1;
        while (k * 2 < n) k *= 2;
        return k;
    }

    /** Read-side algorithms over a store (hashes of arbitrary ranges, root, proofs). */
    private static final class Reader {
        private final ScittLogStore store;

        Reader(ScittLogStore store) { this.store = store; }

        byte[] node(long level, long index) {
            byte[] h = store.getNode(level, index);
            if (h == null || h.length != 32) throw new ScittLogError("store_corrupt", "missing or malformed subtree hash (" + level + ", " + index + ")");
            return h;
        }

        byte[] range(long lo, long n) {
            if (n == 1) return node(0, lo);
            if (isPow2(n) && lo % n == 0) return node(Long.numberOfTrailingZeros(n), lo / n);
            long k = largestPow2Below(n);
            return Rfc9162.nodeHash(range(lo, k), range(lo + k, n - k));
        }

        byte[] root(long size) { return size == 0 ? Rfc9162.emptyRoot() : range(0, size); }

        List<byte[]> inclusion(long index, long size) { return walk(0, size, index); }

        private List<byte[]> walk(long lo, long n, long idx) {
            if (n == 1) return new ArrayList<>();
            long k = largestPow2Below(n);
            List<byte[]> out;
            if (idx < k) {
                out = walk(lo, k, idx);
                out.add(range(lo + k, n - k));
            } else {
                out = walk(lo + k, n - k, idx - k);
                out.add(range(lo, k));
            }
            return out;
        }

        List<byte[]> consistency(long m, long size) { return sub(0, size, m, true); }

        private List<byte[]> sub(long lo, long n, long mm, boolean complete) {
            List<byte[]> out = new ArrayList<>();
            if (mm == n) {
                if (!complete) out.add(range(lo, n));
                return out;
            }
            long k = largestPow2Below(n);
            if (mm <= k) {
                out = sub(lo, k, mm, complete);
                out.add(range(lo + k, n - k));
            } else {
                out = sub(lo + k, n - k, mm - k, false);
                out.add(range(lo, k));
            }
            return out;
        }
    }

    public long size() {
        long n = store.size();
        if (n < 0) throw new ScittLogError("store_corrupt", "the store reported an invalid size");
        return n;
    }

    /** The current tree root (b64u). */
    public String root() { return Keys.b64u(reader.root(size())); }

    private Registration receiptFor(long index, long size, byte[] statement) {
        byte[] root = reader.root(size);
        Map<String, Object> proof = Scitt.inclusionProofMap(index, size, reader.inclusion(index, size));
        String r = Keys.b64u(root);
        return new Registration(index, Scitt.buildReceipt(r, proof, signer), r, statement);
    }

    /** Append a Signed Statement (validated structurally first) and return its receipt against the new root. */
    public Registration register(byte[] statement) {
        try {
            Scitt.CoseSign1 cose = Scitt.decodeCoseSign1(statement);
            if (cose.payload == null) throw new IllegalArgumentException("detached payload");
        } catch (RuntimeException e) {
            throw new ScittLogError("bad_statement", "cannot register: " + e.getMessage());
        }
        for (int attempt = 0; attempt < MAX_APPEND_ATTEMPTS; attempt++) {
            long n = size();
            List<StoredNode> nodes = new ArrayList<>();
            byte[] hash = Rfc9162.leafHash(statement);
            nodes.add(new StoredNode(0, n, hash));
            // Completing a subtree at level l: the new leaf is its last leaf, so its left sibling is already stored.
            for (int level = 1; level < 62 && (n + 1) % (1L << level) == 0; level++) {
                long idx = (n + 1) / (1L << level) - 1;
                byte[] left = store.getNode(level - 1, 2 * idx);
                if (left == null || left.length != 32) throw new ScittLogError("store_corrupt", "missing subtree hash (" + (level - 1) + ", " + (2 * idx) + ")");
                hash = Rfc9162.nodeHash(left, hash);
                nodes.add(new StoredNode(level, idx, hash));
            }
            if (store.append(n, statement, nodes)) return receiptFor(n, n + 1, null);
        }
        throw new ScittLogError("append_contention", "could not append: the log kept changing");
    }

    /** Sign {@code payload} as a Signed Statement, register it, and return the statement plus its receipt. */
    public Registration appendAndReceipt(Object payload, SignStatementOpts stmt) {
        byte[] statement = Scitt.signStatement(payload, stmt);
        Registration r = register(statement);
        return new Registration(r.index, r.receipt, r.root, statement);
    }

    /** A receipt for an entry, against the CURRENT root. */
    public Registration getReceipt(long index) {
        long size = size();
        if (index < 0 || index >= size) throw new ScittLogError("out_of_range", "getReceipt: index out of range");
        return receiptFor(index, size, null);
    }

    public byte[] getEntry(long index) {
        long size = size();
        if (index < 0 || index >= size) throw new ScittLogError("out_of_range", "getEntry: index out of range");
        byte[] e = store.getEntry(index);
        if (e == null) throw new ScittLogError("store_corrupt", "entry " + index + " is missing");
        return e;
    }

    /** An RFC 9162 consistency proof that the first {@code oldSize} entries are a prefix of the current log. */
    public ConsistencyProofResult consistencyProof(long oldSize) {
        long size = size();
        if (oldSize < 1 || oldSize > size) throw new ScittLogError("out_of_range", "consistencyProof: size out of range");
        List<byte[]> path = reader.consistency(oldSize, size);
        return new ConsistencyProofResult(oldSize, size, Keys.b64u(reader.root(oldSize)), Keys.b64u(reader.root(size)),
            Cbor.encode(Arrays.asList((Object) oldSize, size, new ArrayList<Object>(path))));
    }

    /**
     * Check a store implementation against the contract the service relies on. Returns the failures (empty = conforms): compare-and-set,
     * atomic entry-plus-nodes, immutability and a single winner among concurrent appends.
     */
    public static List<String> checkScittLogStore(Supplier<ScittLogStore> makeStore) {
        List<String> failures = new ArrayList<>();
        try {
            ScittLogStore s = makeStore.get();
            if (s.size() != 0) failures.add("a new store is not empty");
            if (!s.append(0, new byte[] {1}, List.of(new StoredNode(0, 0, filled(1))))) failures.add("append at the right size was refused");
            if (s.append(0, new byte[] {2}, List.of(new StoredNode(0, 1, filled(2))))) failures.add("append at a stale size was accepted (no compare-and-set)");
            if (s.size() != 1) failures.add("a refused append changed the size");
            if (s.getNode(0, 1) != null) failures.add("a refused append left a node behind (not atomic)");
            if (s.getEntry(1) != null) failures.add("a refused append left an entry behind");
            byte[] e0 = s.getEntry(0);
            if (e0 == null || e0.length != 1 || e0[0] != 1) failures.add("the stored entry does not read back");
            if (e0 != null && e0.length > 0) e0[0] = 9;
            byte[] again = s.getEntry(0);
            if (again == null || again.length < 1 || again[0] != 1) failures.add("a returned entry aliases the stored one (mutable)");
            ExecutorService pool = Executors.newFixedThreadPool(4);
            try {
                List<Future<Boolean>> racers = new ArrayList<>();
                for (int i = 1; i <= 4; i++) {
                    final int k = i;
                    racers.add(pool.submit(() -> s.append(1, new byte[] {(byte) (10 + k)}, List.of(new StoredNode(0, 1, filled(10 + k))))));
                }
                int wins = 0;
                for (Future<Boolean> f : racers) if (f.get()) wins++;
                if (wins != 1) failures.add("concurrent appends at the same size did not produce exactly one winner");
            } finally {
                pool.shutdown();
            }
            if (s.size() != 2) failures.add("the size after a race is not 2");
        } catch (Exception e) {
            failures.add("the store threw: " + e.getMessage());
        }
        return failures;
    }

    private static byte[] filled(int b) {
        byte[] h = new byte[32];
        Arrays.fill(h, (byte) b);
        return h;
    }
}
