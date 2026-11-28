package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Chain compaction: a long delegation chain folds into one handle, a Merkle root over the ordered hop hashes, plus the leaf hop. A verifier that
 * has verified the full chain once remembers it under that root ({@link Memo}); later presentations carry only {@code {depth, hops_root, leaf}}.
 *
 * <p>The root commits to the order and the number of hops. Nothing is trusted from the presentation: a compact chain is accepted only when the
 * verifier's OWN memo holds an entry for {@code hops_root} that its own chain verification produced ({@link Memo#rememberVerified} runs the
 * verification itself), the depth equals the memoized depth and the presented leaf hashes to the memoized last hop.
 */
public final class ChainCompact {
    private ChainCompact() {}

    public static final String CHAIN_HOP_DOMAIN = "atlas-pca/chain-hop/v1";
    /** A memo entry lives at most this long. */
    public static final double CHAIN_MEMO_MAX_TTL_MS = 3_600_000;
    public static final int CHAIN_MEMO_DEFAULT_MAX_ENTRIES = 10_000;
    /** The reference's MAX_CHAIN_DEPTH. */
    public static final int MAX_CHAIN_DEPTH = 16;

    /** The Merkle leaf of one hop: its content hash under a domain tag, {@code {d, hop}}. */
    public static Map<String, Object> hopLeaf(Map<String, Object> hop) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("d", CHAIN_HOP_DOMAIN);
        m.put("hop", Pca.capHash(hop));
        return m;
    }

    /** The handle of a chain: Merkle root over the ordered hop leaves. */
    public static String hopsRoot(List<Object> chain) {
        List<Object> leaves = new ArrayList<>();
        for (Object h : chain) leaves.add(hopLeaf(StoreJs.map(h)));
        return Pca.merkleRoot(leaves);
    }

    /** Fold a chain into {@code {v:1, kind, depth, hops_root, leaf}}. Throws on an empty or over-deep chain. Does not verify it (the memo does). */
    public static Map<String, Object> compactChain(List<Object> chain) {
        if (chain == null || chain.isEmpty() || chain.size() > MAX_CHAIN_DEPTH) throw new IllegalArgumentException("compactChain: the chain must have 1..MAX_CHAIN_DEPTH hops");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", StoreJs.num(1L));
        m.put("kind", "pca-chain-compact");
        m.put("depth", StoreJs.num((long) chain.size()));
        m.put("hops_root", hopsRoot(chain));
        m.put("leaf", chain.get(chain.size() - 1));
        return m;
    }

    /** Why a presented compact chain is malformed, or null. */
    public static String compactChainShapeError(Object c) {
        if (!(c instanceof Map)) return "not an object";
        Map<String, Object> m = StoreJs.map(c);
        List<String> required = List.of("v", "kind", "depth", "hops_root", "leaf");
        for (String k : m.keySet()) if (!required.contains(k)) return "unknown member 'compact chain." + k + "'";
        for (String k : required) if (!m.containsKey(k)) return "missing member 'compact chain." + k + "'";
        if (!(StoreJs.isFinite(m.get("v")) && StoreJs.dbl(m.get("v")) == 1) || !"pca-chain-compact".equals(m.get("kind"))) return "not a pca-chain-compact v1";
        Object d = m.get("depth");
        if (!(Json.isSafeInt(d) && StoreJs.dbl(d) >= 1 && StoreJs.dbl(d) <= MAX_CHAIN_DEPTH)) return "depth must be 1.." + MAX_CHAIN_DEPTH;
        if (!(m.get("hops_root") instanceof String) || ((String) m.get("hops_root")).length() != 43) return "hops_root must be a 43 character digest";
        if (!(m.get("leaf") instanceof Map)) return "leaf must be a capability";
        return null;
    }

    /** What the caveat language needs of a chain: hop count, per-hop hash and caveat-list length, and the leaf. */
    public interface ChainView {
        int n();

        Map<String, Object> leaf();

        String hash(int i);

        int count(int i);
    }

    /** The view of a full chain (root first). */
    public static ChainView viewOfChain(Map<String, Object> grant, List<Object> chain) {
        List<Object> hops = chain != null && !chain.isEmpty() ? chain : new ArrayList<Object>(List.of(grant));
        String[] cache = new String[hops.size()];
        return new ChainView() {
            @Override public int n() { return hops.size(); }
            @Override public Map<String, Object> leaf() { return StoreJs.map(hops.get(hops.size() - 1)); }
            @Override public String hash(int i) { if (cache[i] == null) cache[i] = Pca.capHash(StoreJs.map(hops.get(i))); return cache[i]; }
            @Override public int count(int i) { Map<String, Object> h = StoreJs.map(hops.get(i)); return h != null && h.get("caveats") instanceof List ? ((List<?>) h.get("caveats")).size() : 0; }
        };
    }

    private static final class Entry {
        final int depth;
        final String root;
        final List<String> hashes;
        final List<Integer> counts;
        final double expiresAt;

        Entry(int depth, String root, List<String> hashes, List<Integer> counts, double expiresAt) {
            this.depth = depth;
            this.root = root;
            this.hashes = hashes;
            this.counts = counts;
            this.expiresAt = expiresAt;
        }
    }

    /** The verifier's memory of chains it verified itself. Thread-safe. */
    public static final class Memo {
        private final Map<String, Entry> entries = new LinkedHashMap<>();
        private final Integer maxEntries;
        private final Double ttlMs;

        /** Both limits may be null (the defaults). */
        public Memo(Integer maxEntries, Double ttlMs) {
            this.maxEntries = maxEntries;
            this.ttlMs = ttlMs;
        }

        public synchronized int size() { return entries.size(); }

        /**
         * Verify {@code chain} (rooted at {@code expectedRootIssuer}) with the full verifier and remember it; returns the compact form a holder
         * presents. Throws when the chain does not verify or the memo is full of live entries (a full memo never evicts a live entry, so one
         * tenant cannot push another out).
         */
        public synchronized Map<String, Object> rememberVerified(List<Object> chain, String expectedRootIssuer, double now) {
            if (Double.isNaN(now) || Double.isInfinite(now) || now != Math.rint(now) || Math.abs(now) > 9007199254740991.0) throw new IllegalStateException("rememberVerified: the clock is not a safe integer");
            String why = Pca.verifyChain(chain, expectedRootIssuer, true, null);
            if (!why.isEmpty()) throw new IllegalStateException("rememberVerified: the chain does not verify: " + why);
            Map<String, Object> compact = compactChain(chain);
            double ttl = Math.min(ttlMs != null ? ttlMs : CHAIN_MEMO_MAX_TTL_MS, CHAIN_MEMO_MAX_TTL_MS);
            prune(now);
            String root = (String) compact.get("hops_root");
            if (!entries.containsKey(root) && entries.size() >= (maxEntries != null ? maxEntries : CHAIN_MEMO_DEFAULT_MAX_ENTRIES)) throw new IllegalStateException("rememberVerified: the memo is full of live entries");
            List<String> hashes = new ArrayList<>();
            List<Integer> counts = new ArrayList<>();
            for (Object h : chain) {
                hashes.add(Pca.capHash(StoreJs.map(h)));
                counts.add(((List<?>) StoreJs.map(h).get("caveats")).size());
            }
            entries.put(root, new Entry(chain.size(), root, hashes, counts, now + ttl));
            return compact;
        }

        /** Drop entries whose time is up. */
        public synchronized void prune(double now) { entries.values().removeIf(e -> !(Double.isFinite(now) && e.expiresAt >= now)); }

        /** Forget a chain (e.g. when it is revoked). */
        public synchronized boolean forget(String hopsRoot) { return entries.remove(hopsRoot) != null; }

        /** The outcome of {@link #resolve}: {@code view} when ok, else {@code reason}. */
        public static final class Resolved {
            public final boolean ok;
            public final ChainView view;
            public final String reason;

            Resolved(boolean ok, ChainView view, String reason) {
                this.ok = ok;
                this.view = view;
                this.reason = reason;
            }
        }

        private static Resolved no(String r) { return new Resolved(false, null, r); }

        /** Resolve a presented compact chain against the memo. Total. */
        public synchronized Resolved resolve(Object compact, double now) {
            try {
                if (Double.isNaN(now) || Double.isInfinite(now) || now != Math.rint(now) || Math.abs(now) > 9007199254740991.0) return no("the verifier clock is not a safe integer (fail closed)");
                String e = compactChainShapeError(compact);
                if (e != null) return no("malformed compact chain: " + e);
                Map<String, Object> c = StoreJs.map(compact);
                Entry m = entries.get(c.get("hops_root"));
                if (m == null) return no("the chain is not in this verifier memo (present the full chain)");
                if (m.expiresAt < now) {
                    entries.remove(c.get("hops_root"));
                    return no("the memoized chain has expired (present the full chain)");
                }
                if (m.depth != (int) (double) StoreJs.dbl(c.get("depth"))) return no("the depth differs from the memoized chain");
                Map<String, Object> leaf = StoreJs.map(c.get("leaf"));
                if (!Pca.capHash(leaf).equals(m.hashes.get(m.depth - 1))) return no("the leaf is not the memoized last hop");
                if (!(leaf.get("caveats") instanceof List) || ((List<?>) leaf.get("caveats")).size() != m.counts.get(m.depth - 1)) return no("the leaf caveats differ from the memoized chain");
                return new Resolved(true, new ChainView() {
                    @Override public int n() { return m.depth; }
                    @Override public Map<String, Object> leaf() { return leaf; }
                    @Override public String hash(int i) { return m.hashes.get(i); }
                    @Override public int count(int i) { return m.counts.get(i); }
                }, null);
            } catch (RuntimeException err) {
                return no("compact chain error (fail closed): " + (err.getMessage() == null ? "unknown" : err.getMessage()));
            }
        }
    }
}
