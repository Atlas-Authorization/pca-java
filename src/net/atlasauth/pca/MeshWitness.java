package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.DoubleSupplier;

/**
 * An independent mesh log witness. It cosigns a domain head only if (1) the domain signed it, (2) it is an RFC 9162-verified append-only
 * extension of the last head THIS witness cosigned for that domain, (3) its revocation list reproduces {@code rev_root} and is a superset
 * of the previously cosigned list, and (4) the timestamp does not regress (nor run ahead of the witness's own clock, when configured).
 * State is committed only after every check passes, and (with a store) persisted BEFORE the cosignature is returned. First sight of a
 * domain is trust-on-first-use. Every refusal throws IllegalStateException with the reference's message.
 */
public final class MeshWitness {
    public static final double DEFAULT_MAX_CLOCK_SKEW_MS = 60_000;
    private static final int MAX_REV_IDS = 1_000_000;

    /** Optional witness configuration. */
    public static final class Options {
        public MeshWitnessStore store;
        /** Witness's own clock; when set, heads timestamped beyond {@code now + maxClockSkewMs} are refused. */
        public DoubleSupplier clock;
        public Double maxClockSkewMs;
    }

    private static final class Seen {
        final Map<String, Object> head;
        final List<String> rev;
        Seen(Map<String, Object> head, List<String> rev) { this.head = head; this.rev = rev; }
    }

    public final String id;
    private final Keys.EdKey key;
    private final Options opts;
    private final Map<String, Seen> seen = new LinkedHashMap<>();

    public MeshWitness(Keys.EdKey key) { this(key, new Options()); }

    public MeshWitness(Keys.EdKey key, Options opts) {
        this.key = key;
        this.opts = opts == null ? new Options() : opts;
        this.id = key.id();
        if (this.opts.store != null) {
            Map<String, Object> loaded = this.opts.store.load();
            if (loaded != null) importState(loaded);
        }
    }

    private static boolean nat(Object x) { return Json.isSafeInt(x) && Json.asLong(x) >= 0; }

    /** The head shape the reference's validHead accepts, or null. */
    static Map<String, Object> validHead(Object h) {
        Map<String, Object> m = StoreJs.map(h);
        if (m == null || !(m.get("domain") instanceof String) || !(m.get("root") instanceof String) || !(m.get("rev_root") instanceof String)) return null;
        if (!nat(m.get("size")) || !nat(m.get("rev_size")) || !StoreJs.isFinite(m.get("timestamp"))) return null;
        return (Json.asLong(m.get("size")) == 0) == ((String) m.get("root")).isEmpty() ? m : null;
    }

    private static byte[] msg(String domain, Object body) {
        return Pca.concat(Json.utf8(domain), Pca.canonBytes(body));
    }

    private static Map<String, Object> stateOf(Map<String, Seen> seen) {
        List<Seen> all = new ArrayList<>(seen.values());
        all.sort((a, b) -> ((String) a.head.get("domain")).compareTo((String) b.head.get("domain")) < 0 ? -1 : 1);
        List<Object> out = new ArrayList<>();
        for (Seen s : all) {
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("head", StoreJs.deepCopy(s.head));
            e.put("rev_ids", new ArrayList<Object>(s.rev));
            out.add(e);
        }
        Map<String, Object> st = new LinkedHashMap<>();
        st.put("seen", out);
        return st;
    }

    /** The newest head this witness cosigned for {@code domain} (a copy), or null. */
    public synchronized Map<String, Object> lastSeen(String domain) {
        Seen s = seen.get(domain);
        return s == null ? null : StoreJs.map(StoreJs.deepCopy(s.head));
    }

    private static IllegalStateException refuse(String why) { return new IllegalStateException("witness: " + why); }

    /** Cosign a head request {@code {head: {head, sig, cosigs}, consistency?, rev_ids}}; returns {@code {witness, sig}}. Throws (and changes nothing) if any rule is violated. */
    public synchronized Map<String, Object> cosign(Map<String, Object> req) {
        Map<String, Object> ch = req == null ? null : StoreJs.map(req.get("head"));
        if (ch == null || validHead(ch.get("head")) == null || !(ch.get("sig") instanceof String)) throw refuse("malformed head");
        Map<String, Object> h = validHead(ch.get("head"));
        if (!Pca.verifyB64u((String) h.get("domain"), msg(Mesh.HEAD_DOMAIN, h), (String) ch.get("sig"))) throw refuse("head not signed by its domain");
        double ts = StoreJs.dbl(h.get("timestamp"));
        if (opts.clock != null) {
            double skew = opts.maxClockSkewMs != null ? opts.maxClockSkewMs : DEFAULT_MAX_CLOCK_SKEW_MS;
            double clk = opts.clock.getAsDouble();
            if (!(Double.isFinite(clk) && Double.isFinite(skew) && ts <= clk + skew)) throw refuse("head timestamp is in the future");
        }
        Object idsO = req.get("rev_ids");
        if (!(idsO instanceof List) || ((List<?>) idsO).size() > MAX_REV_IDS) throw refuse("malformed revocation list");
        List<String> ids = new ArrayList<>();
        for (Object o : (List<?>) idsO) {
            if (!(o instanceof String)) throw refuse("malformed revocation list");
            ids.add((String) o);
        }
        RevocationSet set = new RevocationSet(ids);
        if (set.size() != Json.asLong(h.get("rev_size")) || !set.root().equals(h.get("rev_root"))) throw refuse("revocation list does not match head");
        Seen prev = seen.get((String) h.get("domain"));
        if (prev != null) {
            String why = Mesh.checkHeadAdvance(prev.head, h, req.get("consistency"));
            if (!why.isEmpty()) throw refuse(why);
            if (ts < StoreJs.dbl(prev.head.get("timestamp"))) throw refuse("timestamp regresses");
            Set<String> now = new HashSet<>(set.list());
            if (!now.containsAll(prev.rev)) throw refuse("revocation set drops a previously cosigned revocation");
        }
        Seen next = new Seen(StoreJs.map(StoreJs.deepCopy(h)), set.list());
        if (opts.store != null) {
            // Persist first, commit to memory second: if the disk write fails nothing was cosigned and nothing changed.
            Map<String, Seen> copy = new LinkedHashMap<>(seen);
            copy.put((String) h.get("domain"), next);
            try {
                opts.store.save(stateOf(copy));
            } catch (RuntimeException e) {
                throw refuse("could not persist state; refusing to cosign");
            }
        }
        seen.put((String) h.get("domain"), next);
        Map<String, Object> cos = new LinkedHashMap<>();
        cos.put("witness", id);
        cos.put("sig", Keys.b64u(key.sign(msg(Mesh.COSIG_DOMAIN, h))));
        return cos;
    }

    /** Export memory for persistence. Deterministic order. */
    public synchronized Map<String, Object> exportState() { return stateOf(seen); }

    /** Restore memory; each record must be internally consistent (its revocation list reproduces its root). */
    public synchronized void importState(Map<String, Object> state) {
        Map<String, Seen> next = new LinkedHashMap<>();
        Object list = state == null ? null : state.get("seen");
        if (list != null && !(list instanceof List)) throw refuse("malformed state");
        if (list != null) {
            for (Object so : (List<?>) list) {
                Map<String, Object> s = StoreJs.map(so);
                Map<String, Object> head = s == null ? null : validHead(s.get("head"));
                if (head == null || !(s.get("rev_ids") instanceof List)) throw refuse("malformed state");
                List<String> ids = new ArrayList<>();
                for (Object o : (List<?>) s.get("rev_ids")) {
                    if (!(o instanceof String)) throw refuse("malformed state");
                    ids.add((String) o);
                }
                RevocationSet set = new RevocationSet(ids);
                if (set.size() != Json.asLong(head.get("rev_size")) || !set.root().equals(head.get("rev_root"))) throw refuse("malformed state");
                next.put((String) head.get("domain"), new Seen(StoreJs.map(StoreJs.deepCopy(head)), set.list()));
            }
        }
        seen.clear();
        seen.putAll(next);
    }
}
