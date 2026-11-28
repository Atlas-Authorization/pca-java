package net.atlasauth.pca.doctor;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.doctor.Doctor.CheckResult;
import net.atlasauth.pca.storeconformance.Kit;
import net.atlasauth.pca.storeconformance.Op;
import net.atlasauth.pca.storeconformance.Reference;
import net.atlasauth.pca.storeconformance.Runner;
import net.atlasauth.pca.storeconformance.StoreAdapter;
import net.atlasauth.pca.storeconformance.Workloads;

/**
 * Replay / counter store checks through the conformance kit's adapter interface: a REAL concurrent conflicting write (many clients
 * consume one fresh key at once: exactly one may win; counters race on one stream) and durability (write, close, restart when the
 * adapter can, read back). Short by design; the full kit goes further.
 */
final class DoctorStore {
    private DoctorStore() {}

    private static String opName(String kind) { return kind.equals("consume") ? "consumeOnce" : "advance"; }

    private static String firstCounterexample(Kit.HistoryCheck h) {
        if (h.violations.isEmpty()) return "";
        Kit.KeyResult v = h.violations.get(0);
        List<Op> ce = v.counterexample != null ? v.counterexample : new ArrayList<>();
        return " First violating key " + v.key + ": " + String.join(" | ", Kit.formatOps(ce));
    }

    private static List<CheckResult> one(CheckResult r) { List<CheckResult> l = new ArrayList<>(); l.add(r); return l; }

    /** Without a store adapter the replay store cannot be exercised remotely: both checks are skipped. */
    static List<CheckResult> checkStore(Map<String, Object> cfg) {
        Object store = Js.g(cfg, "store");
        Object spec = Js.g(store, "adapter");
        List<CheckResult> out = new ArrayList<>();
        if (!Js.truthy(spec)) {
            String detail = "no store adapter given (--store ./adapter.mjs); the replay store cannot be exercised remotely";
            out.add(CheckResult.of("store.atomicity", "skip", detail));
            out.add(CheckResult.of("store.durability", "skip", detail));
            return out;
        }
        Map<String, String> options = new LinkedHashMap<>();
        Object opts = Js.g(store, "options");
        if (opts instanceof Map) for (Map.Entry<?, ?> e : ((Map<?, ?>) opts).entrySet()) options.put((String) e.getKey(), Js.str(e.getValue()));
        StoreAdapter adapter;
        try {
            adapter = Reference.loadAdapter(Js.str(spec), options);
        } catch (Exception e) {
            return one(CheckResult.of("store.atomicity", "fail", "cannot load the store adapter " + Js.str(spec) + ": " + e.getMessage())
                .fix("Point --store at a store adapter class (see the store conformance kit guide)."));
        }
        try {
            List<String> kinds = Runner.detectKinds(adapter);
            List<CheckResult> res = new ArrayList<>();
            res.add(atomicity(adapter, kinds, store));
            res.add(durability(adapter, kinds));
            return res;
        } catch (Exception e) {
            return one(CheckResult.of("store.atomicity", "fail", "the store adapter failed: " + e.getMessage()).fix(Doctor.ATOMICITY_REMEDIATION));
        } finally {
            try { adapter.teardown(); } catch (Exception ignored) { /* the check's result stands */ }
        }
    }

    private static CheckResult atomicity(StoreAdapter adapter, List<String> kinds, Object store) throws Exception {
        int clients = (int) Js.toNumber(Js.or(Js.g(store, "concurrency"), 32.0));
        int rounds = (int) Js.toNumber(Js.or(Js.g(store, "rounds"), 10.0));
        List<String> parts = new ArrayList<>();
        Map<String, Object> observed = new LinkedHashMap<>();
        String status = "pass";
        String cx = "";
        for (String kind : kinds) {
            Workloads.WorkloadOptions wo = new Workloads.WorkloadOptions();
            wo.clients = clients;
            wo.rounds = rounds;
            wo.values = 8;
            Workloads.WorkloadResult w = Workloads.runBurst(adapter, kind, wo);
            Kit.HistoryCheck h = Kit.checkHistory(w.ops, null);
            Set<String> winners = new HashSet<>();
            for (Op o : w.ops) if (o.res.equals("true")) winners.add(o.key);
            Map<String, Object> oc = new LinkedHashMap<>();
            oc.put("true", h.outcomes[0]);
            oc.put("false", h.outcomes[1]);
            oc.put("unknown", h.outcomes[2]);
            Map<String, Object> ob = new LinkedHashMap<>();
            ob.put("ops", h.ops);
            ob.put("keys", h.keys);
            ob.put("outcomes", oc);
            ob.put("violations", h.violations.size());
            ob.put("unresolved", h.unresolved.size());
            observed.put(kind, ob);
            int definite = h.outcomes[0] + h.outcomes[1];
            if (!h.violations.isEmpty()) {
                status = "fail";
                if (cx.isEmpty()) cx = firstCounterexample(h);
                parts.add(opName(kind) + ": " + h.violations.size() + " of " + rounds + " same-key rounds NOT linearizable (" + clients + " concurrent clients)");
            } else if (definite == 0 || !h.unresolved.isEmpty()) {
                if (status.equals("pass")) status = "warn";
                parts.add(opName(kind) + ": inconclusive (" + w.errors + " of " + h.ops + " calls failed or timed out" + (h.unresolved.isEmpty() ? "" : ", " + h.unresolved.size() + " key(s) undecided") + ")");
            } else {
                parts.add(opName(kind) + ": " + rounds + " rounds of " + clients + " concurrent conflicting calls linearizable"
                    + (kind.equals("consume") ? " (" + winners.size() + " of " + rounds + " rounds had exactly one TRUE)" : "") + (w.errors > 0 ? ", " + w.errors + " calls failed closed" : ""));
            }
        }
        CheckResult r = CheckResult.of("store.atomicity", status, adapter.name() + ": " + String.join("; ", parts) + "." + cx);
        if (!status.equals("pass")) r.fix(Doctor.ATOMICITY_REMEDIATION);
        return r.observed(observed);
    }

    private static CheckResult durability(StoreAdapter adapter, List<String> kinds) throws Exception {
        if (adapter.capabilities() != null && Boolean.FALSE.equals(adapter.capabilities().durable)) {
            return CheckResult.of("store.durability", "warn", adapter.name() + " declares itself non-durable: a restart forgets consumed nonces").fix(Doctor.DURABILITY_REMEDIATION);
        }
        List<String> parts = new ArrayList<>();
        String status = "pass";
        String cx = "";
        for (String kind : kinds) {
            Workloads.WorkloadResult w = Workloads.runDurability(adapter, kind, new Workloads.WorkloadOptions());
            Kit.HistoryCheck h = Kit.checkHistory(w.ops, null);
            if (!h.violations.isEmpty()) {
                status = "fail";
                if (cx.isEmpty()) cx = firstCounterexample(h);
                parts.add(opName(kind) + ": state LOST across close/restart");
            } else if (h.outcomes[0] + h.outcomes[1] < w.ops.size()) {
                if (status.equals("pass")) status = "warn";
                parts.add(opName(kind) + ": inconclusive (" + w.errors + " calls failed)");
            } else {
                parts.add(opName(kind) + ": survived");
            }
        }
        String how = adapter.hasRestart() ? "write, close, restart() the backend, read back" : "write, close, re-open (no restart() hook: the backend itself was not restarted)";
        CheckResult r = CheckResult.of("store.durability", status, adapter.name() + " (" + how + "): " + String.join("; ", parts) + "." + cx);
        if (!status.equals("pass")) r.fix(Doctor.DURABILITY_REMEDIATION);
        return r;
    }
}
