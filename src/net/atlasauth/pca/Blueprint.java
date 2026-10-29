package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Agent blueprints (verification side): a record signed by an operator for a blueprint KEY; an instance is a chain with a hop issued
 * by that key. {@link Registry} keeps the newest record per key (pinned operators, a strictly higher epoch replaces, the same epoch
 * with different content is a fork). A non-empty ceiling is never evaluated here: it denies ({@code ceiling_unevaluable}). Total.
 */
public final class Blueprint {
    private Blueprint() {}

    public static final String DOMAIN = "atlas-pca/agent-blueprint/v1\u0000";
    private static final String[] BODY_KEYS = {"v", "id", "key", "ceiling", "max_depth", "expires_at", "epoch", "status", "issued_at", "operator"};

    private static boolean str(Object o, int max) { return o instanceof String && !((String) o).isEmpty() && ((String) o).length() <= max; }
    private static boolean nat(Object o) { return Json.isSafeInt(o) && Json.asLong(o) >= 0; }

    @SuppressWarnings("unchecked")
    static boolean wellFormed(Object v) {
        if (!(v instanceof Map)) return false;
        Map<String, Object> b = (Map<String, Object>) v;
        if (!Json.isSafeInt(b.get("v")) || Json.asLong(b.get("v")) != 1) return false;
        if (!str(b.get("id"), 128) || !str(b.get("key"), 128) || !str(b.get("operator"), 128)) return false;
        if (!nat(b.get("epoch")) || !nat(b.get("issued_at"))) return false;
        Object st = b.get("status");
        if (!"active".equals(st) && !"disabled".equals(st)) return false;
        if (b.containsKey("max_depth") && !(nat(b.get("max_depth")) && Json.asLong(b.get("max_depth")) >= 1)) return false;
        if (b.containsKey("expires_at") && !nat(b.get("expires_at"))) return false;
        if (!(b.get("ceiling") instanceof List) || ((List<Object>) b.get("ceiling")).size() > 32) return false;
        for (Object c : (List<Object>) b.get("ceiling")) if (!(c instanceof Map) || !(((Map<String, Object>) c).get("type") instanceof String)) return false;
        return true;
    }

    @SuppressWarnings("unchecked")
    public static boolean verify(Object v) {
        if (!wellFormed(v)) return false;
        Map<String, Object> b = (Map<String, Object>) v;
        Map<String, Object> body = new LinkedHashMap<>();
        for (String k : BODY_KEYS) if (b.containsKey(k)) body.put(k, b.get(k));
        return K3.verifyBody(DOMAIN, body, (String) b.get("operator"), b.get("sig"));
    }

    /** Outcome of {@link Registry#accept}: {@code code} is null when taken. */
    public static final class Accept {
        public final String code;
        public final boolean replaced;
        Accept(String code, boolean replaced) { this.code = code; this.replaced = replaced; }
    }

    public static final class Registry {
        private final List<String> operators;
        final Map<String, Map<String, Object>> store = new HashMap<>();
        public Registry(List<String> operators) { this.operators = operators; }

        @SuppressWarnings("unchecked")
        public Accept accept(Object v) {
            if (!verify(v)) return new Accept("bad_record", false);
            Map<String, Object> b = (Map<String, Object>) v;
            if (!operators.contains(b.get("operator"))) return new Accept("unknown_operator", false);
            Map<String, Object> cur = store.get((String) b.get("key"));
            if (cur != null) {
                if (!cur.get("operator").equals(b.get("operator"))) return new Accept("operator_changed", false);
                long ce = Json.asLong(cur.get("epoch")), be = Json.asLong(b.get("epoch"));
                if (be < ce) return new Accept("stale_epoch", false);
                if (be == ce) return cur.get("sig").equals(b.get("sig")) ? new Accept(null, false) : new Accept("epoch_fork", false);
            }
            store.put((String) b.get("key"), b);
            return new Accept(null, true);
        }

        public long epoch() {
            long m = 0;
            for (Map<String, Object> r : store.values()) m = Math.max(m, Json.asLong(r.get("epoch")));
            return m;
        }
    }

    /** {@code decision} is allow, deny or escalate. */
    public static final class Decision {
        public final String decision, code, blueprint;
        public final List<String> governed;
        public final long have, need;
        Decision(String decision, String code, String blueprint, List<String> governed, long have, long need) {
            this.decision = decision; this.code = code; this.blueprint = blueprint; this.governed = governed; this.have = have; this.need = need;
        }
    }

    private static Decision deny(String code, String bp) { return new Decision("deny", code, bp, new ArrayList<>(), 0, 0); }

    /** Gate a chain (hops with issuer and holder, root first). {@code mode} is require or any; {@code minEpoch} may be null. */
    @SuppressWarnings("unchecked")
    public static Decision check(Object chain, Registry reg, Object now, String mode, Long minEpoch) {
        if (!(chain instanceof List) || ((List<Object>) chain).isEmpty() || !nat(now)) return deny("bad_input", null);
        List<String[]> hs = new ArrayList<>();
        for (Object h : (List<Object>) chain) {
            if (!(h instanceof Map)) return deny("bad_input", null);
            Map<String, Object> m = (Map<String, Object>) h;
            if (!str(m.get("issuer"), 128) || !str(m.get("holder"), 128)) return deny("bad_input", null);
            hs.add(new String[] {(String) m.get("issuer"), (String) m.get("holder")});
        }
        long nowMs = Json.asLong(now);
        if (minEpoch != null && reg.epoch() < minEpoch) return new Decision("escalate", "stale_blueprint_state", null, new ArrayList<>(), reg.epoch(), minEpoch);
        List<String> governed = new ArrayList<>();
        for (int i = 0; i < hs.size(); i++) {
            Map<String, Object> bp = reg.store.get(hs.get(i)[0]);
            if (bp == null) continue;
            String id = (String) bp.get("id");
            if (i == 0 || !hs.get(i - 1)[1].equals(bp.get("key"))) return deny("broken_link", id);
            if (!"active".equals(bp.get("status"))) return deny("blueprint_disabled", id);
            if (bp.containsKey("expires_at") && nowMs >= Json.asLong(bp.get("expires_at"))) return deny("blueprint_expired", id);
            if (bp.containsKey("max_depth") && hs.size() - i > Json.asLong(bp.get("max_depth"))) return deny("too_deep", id);
            if (!((List<Object>) bp.get("ceiling")).isEmpty()) return deny("ceiling_unevaluable", id);
            governed.add(id);
        }
        if (governed.isEmpty() && "require".equals(mode)) return deny("no_blueprint", null);
        return new Decision("allow", null, null, governed, 0, 0);
    }
}
