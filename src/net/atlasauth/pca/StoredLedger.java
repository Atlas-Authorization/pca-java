package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.DoubleSupplier;

/**
 * A transparency log over a {@link LedgerStore} (Ed25519 guardian checkpoints). Open it with {@link #open}; the constructor is
 * private so that no instance exists whose state was not verified against the stored checkpoints.
 *
 * <p>On {@code open} the Merkle tree is rebuilt from the stored commits and checked against EVERY stored checkpoint: the guardian
 * signature, the signed {@code prev_root} chain, the RFC 9162 consistency proof at each boundary, and that the commits reproduce each
 * checkpoint root. A store that lost entries after a checkpoint (rollback), edited an entry (tamper) or holds a forged checkpoint
 * FAILS CLOSED with a {@link LedgerStoreError}. {@link #checkpoint} refuses to sign a head that is not consistent with the previous one.
 *
 * <p>Checkpoints are Ed25519 by default. A post-quantum or hybrid suite ({@link Options#suite}) needs the verifier's PQ pin for the guardian
 * ({@link Options#pin}); every stored checkpoint is then verified under that pin, so a checkpoint signed by another PQ key is refused.
 */
public final class StoredLedger {
    /** Open options. {@code store} and {@code guardianKey} are required (there is no in-memory default). */
    public static final class Options {
        public LedgerStore store;
        public Keys.EdKey guardianKey;
        /** Checkpoint signature suite (null: ed25519). A PQ or hybrid suite needs {@link #pin}; its Ed25519 key, when it has one, is the guardian key. */
        public Keys.SuiteKey suite;
        /** PQ pins for the guardian identity, {@code {ed25519 b64u: pq_pk}} (the reference's {@code pin.pqPins}); required with a non-ed25519 suite. */
        public Map<String, Object> pin;
        public String instanceId;
        public String principal;
        /** Epoch-ms clock for checkpoint timestamps (default the system clock). */
        public DoubleSupplier clock;
    }

    private final Options opts;
    private final String guardianPublic;
    private final MerkleLog log;
    private final List<Map<String, Object>> cps;

    private StoredLedger(Options opts, String guardianPublic, MerkleLog log, List<Map<String, Object>> cps) {
        this.opts = opts;
        this.guardianPublic = guardianPublic;
        this.log = log;
        this.cps = cps;
    }

    private static LedgerStoreError unavailable(RuntimeException e) {
        if (e instanceof LedgerStoreError) return (LedgerStoreError) e;
        return new LedgerStoreError("store_unavailable", e.getMessage() == null ? "store failed" : e.getMessage(), e);
    }

    /** Load the log and verify it against every stored checkpoint. Throws {@link LedgerStoreError} with the reference's codes. */
    public static StoredLedger open(Options opts) {
        if (opts == null || opts.store == null) throw new LedgerStoreError("store_missing", "a LedgerStore is required (there is no in-memory default)");
        if (opts.guardianKey == null || opts.guardianKey.isDestroyed()) throw new LedgerStoreError("guardian_key_missing", "a guardian secret key is required");
        String gp = opts.guardianKey.id();
        if (opts.suite != null && !"ed25519".equals(opts.suite.alg) && opts.pin == null) {
            throw new LedgerStoreError("pin_missing", "a post-quantum or hybrid checkpoint suite needs a PQ pin for the guardian (and a known suite name)");
        }
        if (opts.suite != null && opts.suite.ed != null && !opts.suite.ed.id().equals(gp)) throw new IllegalArgumentException("the suite's Ed25519 key is not the guardian key");
        try {
            long size = opts.store.size();
            List<String> commits = opts.store.read(0, size);
            List<Map<String, Object>> cps = new ArrayList<>(opts.store.checkpoints(0));
            StoredLedger self = new StoredLedger(opts, gp, MerkleLog.of(commits), cps);
            self.verifyAgainstCheckpoints();
            return self;
        } catch (RuntimeException e) {
            throw unavailable(e);
        }
    }

    private static final class Verdict {
        final int at;
        final String reason;
        Verdict(int at, String reason) { this.at = at; this.reason = reason; }
    }

    /** verifyCheckpointChain with the failing reason (head / proof_missing / inconsistent); null when the chain verifies. */
    private Verdict chainFailure(List<Map<String, Object>> chain) {
        Map<String, Object> prev = null;
        for (int i = 0; i < chain.size(); i++) {
            Map<String, Object> cp = chain.get(i);
            Map<String, Object> sth = StoreJs.map(cp.get("sth"));
            if (!Ledger.verifyTreeHead(sth, guardianPublic, null, opts.pin)) return new Verdict(i, "head");
            if (i > 0) {
                Object proof = cp.get("proof");
                if (proof == null || Boolean.FALSE.equals(proof)) return new Verdict(i, "proof_missing");
                if (!Ledger.verifyHeadConsistency(prev, sth, proof, guardianPublic, null, opts.pin)) return new Verdict(i, "inconsistent");
            }
            prev = sth;
        }
        return null;
    }

    private static Map<String, Object> sthOf(Map<String, Object> cp) { return StoreJs.map(cp.get("sth")); }

    /** The checkpoint chain, the log and the stored commits must tell one story. */
    private void verifyAgainstCheckpoints() {
        long attested = 0;
        for (Map<String, Object> cp : cps) {
            Object sz = sthOf(cp).get("size");
            if (StoreJs.isInt(sz)) attested = Math.max(attested, StoreJs.lng(sz));
        }
        if (log.size() < attested) throw new LedgerStoreError("rollback", "the log has " + log.size() + " entries but a checkpoint attests " + attested);
        for (int i = 0; i < cps.size(); i++) {
            Map<String, Object> sth = sthOf(cps.get(i));
            if (!java.util.Objects.equals(sth.get("instance_id"), opts.instanceId) || !java.util.Objects.equals(sth.get("principal"), opts.principal)) {
                throw new LedgerStoreError("forged_checkpoint", "checkpoint " + i + " belongs to another log");
            }
            Object sz = sth.get("size");
            if (!StoreJs.isInt(sz)) throw new IllegalArgumentException("rootAt: size out of range");
            if (!log.rootAt(StoreJs.lng(sz)).equals(sth.get("root"))) {
                throw new LedgerStoreError("tamper", "the stored entries do not reproduce the root of checkpoint " + i + " (size " + sz + ")");
            }
        }
        if (cps.isEmpty()) return;
        Verdict v = chainFailure(cps);
        if (v != null) throw new LedgerStoreError("inconsistent".equals(v.reason) ? "inconsistent" : "forged_checkpoint", "checkpoint " + v.at + ": " + v.reason);
    }

    public synchronized int size() { return log.size(); }

    /** The guardian public key (b64u) every checkpoint verifies under. */
    public String guardian() { return guardianPublic; }

    /** The latest signed tree head, or null. */
    public synchronized Map<String, Object> latestCheckpoint() { return cps.isEmpty() ? null : sthOf(cps.get(cps.size() - 1)); }

    public synchronized List<Map<String, Object>> checkpointChain() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> c : cps) out.add(StoreJs.map(StoreJs.deepCopy(c)));
        return out;
    }

    /** {size, root}. */
    public synchronized Map<String, Object> head() { return log.head(); }

    public synchronized Map<String, Object> inclusionProof(long index) { return log.inclusionProof(index); }

    /** RFC 9162 proof from a size the caller already pinned (a checkpoint, or a witness's) to the current log. */
    public synchronized Map<String, Object> consistencyProofFrom(long oldSize) { return log.consistencyProof(oldSize, log.size()); }

    public synchronized List<String> commits() { return log.commits(); }

    /** Append an opaque commitment leaf; returns its index. If another writer took the position, reloads and appends at the new tail. */
    public synchronized long append(String commit) {
        if (commit == null || commit.isEmpty()) throw new LedgerStoreError("invalid_commit", "a commit must be a non-empty string");
        for (int attempt = 0; attempt < 16; attempt++) {
            long index = log.size();
            LedgerStore.AppendOutcome out;
            try {
                out = opts.store.append(index, List.of(commit));
            } catch (RuntimeException e) {
                throw unavailable(e);
            }
            if ("appended".equals(out.outcome) || "replayed".equals(out.outcome)) {
                log.appendCommitment(commit);
                return index;
            }
            catchUpLocked(); // another writer advanced the log: pick up its entries, then try the new tail
        }
        throw new LedgerStoreError("conflict", "the log kept moving; could not append");
    }

    /** Reload entries other writers appended since this handle last looked (and re-verify them against the checkpoints). */
    public synchronized void catchUp() { catchUpLocked(); }

    private void catchUpLocked() {
        try {
            long size = opts.store.size();
            if (size < log.size()) throw new LedgerStoreError("rollback", "the store shrank from " + log.size() + " to " + size + " entries");
            for (String c : opts.store.read(log.size(), size)) log.appendCommitment(c);
            cps.addAll(opts.store.checkpoints(cps.size()));
            verifyAgainstCheckpoints();
        } catch (RuntimeException e) {
            throw unavailable(e);
        }
    }

    /** A checkpoint signs what THIS handle holds, so first prove the store still holds exactly that. */
    private void assertStoreMatchesMemory() {
        List<String> stored;
        try {
            stored = opts.store.read(0, log.size());
        } catch (RuntimeException e) {
            throw unavailable(e);
        }
        if (!stored.equals(log.commits())) throw new LedgerStoreError("tamper", "the stored entries no longer match this handle; refusing to sign a checkpoint over them");
    }

    /**
     * Sign and persist a checkpoint of the current head. It is verified BEFORE it is stored: the new head must be consistent with the
     * previous checkpoint, so a log that was rewritten under this handle is refused ({@code inconsistent}). An unchanged head returns
     * the existing tree head.
     */
    public synchronized Map<String, Object> checkpoint() {
        catchUpLocked();
        assertStoreMatchesMemory();
        Map<String, Object> prev = cps.isEmpty() ? null : cps.get(cps.size() - 1);
        long size = log.size();
        String root = log.root();
        if (prev != null && StoreJs.isInt(sthOf(prev).get("size")) && StoreJs.lng(sthOf(prev).get("size")) == size) return sthOf(prev);
        DoubleSupplier clock = opts.clock != null ? opts.clock : () -> (double) System.currentTimeMillis();
        double t = clock.getAsDouble();
        if (Double.isNaN(t) || Double.isInfinite(t)) throw new LedgerStoreError("clock_invalid", "the clock returned a non-finite time");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("instance_id", opts.instanceId);
        body.put("principal", opts.principal);
        body.put("size", StoreJs.num(size));
        body.put("root", root);
        body.put("prev_root", prev == null ? "" : sthOf(prev).get("root"));
        body.put("timestamp", t == Math.rint(t) && Math.abs(t) < 9e15 ? StoreJs.num((long) t) : StoreJs.num(t));
        Keys.SuiteKey suite = opts.suite != null ? opts.suite : Keys.ed25519(opts.guardianKey);
        Map<String, Object> bound = IntentJs.bindSuiteFields(body, suite.alg, true, suite.pqPk(), true);
        byte[] msg = Pca.concat(Json.utf8(Ledger.STH_DOMAIN), Pca.canonBytes(bound));
        String[] sigs = suite.sign(msg);
        Map<String, Object> sth = new LinkedHashMap<>(bound); // the bound body carries alg and pq_pk for a non-ed25519 suite
        sth.put("guardian", guardianPublic);
        sth.put("sig", sigs[0]);
        if (sigs[1] != null) sth.put("pq_sig", sigs[1]);
        Map<String, Object> cp = new LinkedHashMap<>();
        cp.put("sth", sth);
        if (prev != null) cp.put("proof", log.consistencyProof(StoreJs.lng(sthOf(prev).get("size")), size));
        List<Map<String, Object>> chain = new ArrayList<>(cps);
        chain.add(cp);
        Verdict v = chainFailure(chain);
        if (v != null) {
            if ("head".equals(v.reason)) throw new LedgerStoreError("forged_checkpoint", "the new checkpoint does not verify under the pinned guardian identity (check the guardian key and the PQ pin)");
            throw new LedgerStoreError("inconsistent", "the new head is not consistent with checkpoint " + (v.at - 1));
        }
        LedgerStore.CheckpointOutcome out;
        try {
            out = opts.store.appendCheckpoint(cps.size(), cp);
        } catch (RuntimeException e) {
            throw unavailable(e);
        }
        if ("conflict".equals(out.outcome)) throw new LedgerStoreError("conflict", out.reason);
        cps.add(cp);
        return sth;
    }
}
