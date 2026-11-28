package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The issuing side of a mesh domain (an organisation): an append-only delegation log, a revocation set, and head publication against
 * {@link MeshWitness}es. In production this is the deployed signed-tree-head + revocation-epoch machinery; here it is in memory so the
 * witness protocol can be exercised end to end.
 */
public final class MeshDomain {
    public final String id;
    public final String name;
    private final Keys.EdKey key;
    private final MerkleLog log = new MerkleLog();
    private final RevocationSet rev = new RevocationSet();
    /** What each published head saw, keyed by the head's signature (what {@link #evidence} and {@link #pinProof} prove against). */
    private final Map<String, Snapshot> snaps = new LinkedHashMap<>();

    private static final class Snapshot {
        final List<String> log;
        final RevocationSet rev;
        Snapshot(List<String> log, RevocationSet rev) { this.log = log; this.rev = rev; }
    }

    public MeshDomain(String name, Keys.EdKey key) {
        this.name = name;
        this.key = key;
        this.id = key.id();
    }

    /** Vouch that an agent key belongs to this domain: {@code {agent, domain, role, sig}} (for domain policy, not authority). */
    public Map<String, Object> enroll(String agent, String role) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("agent", agent);
        body.put("domain", id);
        body.put("role", role);
        byte[] m = Pca.concat(Json.utf8(Mesh.BINDING_DOMAIN), Pca.canonBytes(body));
        Map<String, Object> out = new LinkedHashMap<>(body);
        out.put("sig", Keys.b64u(key.sign(m)));
        return out;
    }

    /**
     * The proof a verifier holding {@code pin} (a head of this domain) needs to accept {@code head} (a cosigned head this domain published, larger
     * than the pin): {@code {domain, proof}}. Throws if the head is unknown or the pin is not a prefix of that head's log.
     */
    public synchronized Map<String, Object> pinProof(Map<String, Object> pin, Map<String, Object> head) {
        Snapshot snap = snaps.get(String.valueOf(head.get("sig")));
        if (snap == null) throw new IllegalStateException("pinProof: unknown head");
        Map<String, Object> inner = StoreJs.map(head.get("head"));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("domain", id);
        out.put("proof", MerkleLog.of(snap.log).consistencyProof(Json.asLong(pin.get("size")), Json.asLong(inner.get("size"))));
        return out;
    }

    /**
     * Per-hop evidence against a previously published head: {@code {domain, head, inclusion, binding?, revocation: {cap, issuer_key}}}. Throws if the
     * head is unknown, the capability is not in that head's log, or the capability or its issuer key is revoked as of that head. {@code binding} may be null.
     */
    public synchronized Map<String, Object> evidence(Map<String, Object> cap, Map<String, Object> head, Map<String, Object> binding) {
        Snapshot snap = snaps.get(String.valueOf(head.get("sig")));
        if (snap == null) throw new IllegalStateException("evidence: unknown head");
        int idx = snap.log.indexOf(Pca.capHash(cap));
        if (idx < 0) throw new IllegalStateException("evidence: capability not in this head");
        Map<String, Object> rv = new LinkedHashMap<>();
        rv.put("cap", snap.rev.nonMembershipProof((String) cap.get("id")));
        rv.put("issuer_key", snap.rev.nonMembershipProof("key:" + cap.get("issuer")));
        Map<String, Object> ev = new LinkedHashMap<>();
        ev.put("domain", id);
        ev.put("head", head);
        ev.put("inclusion", MerkleLog.of(snap.log).inclusionProof(idx));
        ev.put("revocation", rv);
        if (binding != null) ev.put("binding", binding);
        return ev;
    }

    /** Log a delegation hop issued in this domain (identified by its capability hash). Idempotent. Returns its index. */
    public synchronized int record(Map<String, Object> cap) {
        String h = Pca.capHash(cap);
        List<String> cs = log.commits();
        int i = cs.indexOf(h);
        return i >= 0 ? i : log.appendCommitment(h);
    }

    /** A copy of the current revocation set (for proofs about it). */
    public synchronized RevocationSet revocationSetCopy() { return new RevocationSet(rev.list()); }

    /** Revoke a capability id or an agent key. */
    public synchronized void revoke(String revokedId) { rev.revoke(revokedId); }

    /** RFC 9162 consistency proof between two sizes of this domain's current log. */
    public synchronized Map<String, Object> consistencyProof(long oldSize, long newSize) { return log.consistencyProof(oldSize, newSize); }

    /** As {@link #consistencyProof(long, long)} up to the current size of the log. */
    public synchronized Map<String, Object> consistencyProof(long oldSize) { return log.consistencyProof(oldSize); }

    /**
     * Publish a head: domain-signed, then cosigned by {@code witnesses}, each shown a real consistency proof from ITS last-seen head plus the
     * revocation list. Throws if a witness refuses (unless {@code threshold} tolerates it). Returns {@code {head, sig, cosigs}}.
     */
    public synchronized Map<String, Object> publishHead(List<MeshWitness> witnesses, double timestamp, Integer threshold) {
        long size = log.size();
        Map<String, Object> head = new LinkedHashMap<>();
        head.put("domain", id);
        head.put("size", StoreJs.num(size));
        head.put("root", size == 0 ? "" : log.root());
        head.put("rev_root", rev.root());
        head.put("rev_size", StoreJs.num((long) rev.size()));
        head.put("timestamp", timestamp == Math.rint(timestamp) && Math.abs(timestamp) < 9e15 ? StoreJs.num((long) timestamp) : StoreJs.num(timestamp));
        byte[] m = Pca.concat(Json.utf8(Mesh.HEAD_DOMAIN), Pca.canonBytes(head));
        Map<String, Object> ch = new LinkedHashMap<>();
        ch.put("head", head);
        ch.put("sig", Keys.b64u(key.sign(m)));
        List<Object> cosigs = new ArrayList<>();
        ch.put("cosigs", cosigs);
        List<String> revIds = rev.list();
        List<RuntimeException> errors = new ArrayList<>();
        for (MeshWitness w : witnesses) {
            Map<String, Object> prev = w.lastSeen(id);
            Map<String, Object> consistency = null;
            if (prev != null) {
                long ps = Json.asLong(prev.get("size"));
                if (ps < size) consistency = log.consistencyProof(ps, size);
                else if (ps > size) { // will be refused as rollback
                    consistency = new LinkedHashMap<>();
                    consistency.put("oldSize", StoreJs.num(ps));
                    consistency.put("newSize", StoreJs.num(size));
                    consistency.put("path", new ArrayList<Object>());
                }
            }
            Map<String, Object> req = new LinkedHashMap<>();
            req.put("head", ch);
            if (consistency != null) req.put("consistency", consistency);
            req.put("rev_ids", new ArrayList<Object>(revIds));
            try {
                cosigs.add(w.cosign(req));
            } catch (RuntimeException e) {
                errors.add(e);
            }
        }
        int need = threshold != null ? threshold : witnesses.size();
        if (cosigs.size() < need) throw errors.isEmpty() ? new IllegalStateException("publishHead: not enough witnesses") : errors.get(0);
        snaps.put((String) ch.get("sig"), new Snapshot(log.commits(), new RevocationSet(rev.list())));
        return ch;
    }
}
