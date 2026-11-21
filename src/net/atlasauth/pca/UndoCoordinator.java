package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.LongSupplier;

/**
 * The undo-window coordinator: admission, the durable ledger, the human surface and the real rollback (a port of the reference
 * {@code server/undo}; the pure record, token, receipts and store contract are in {@link Undo} and {@link UndoStore}).
 *
 * <ul>
 * <li><b>admit</b>: ELIGIBILITY. An action gets a veto window only when the policy does not turn windows off, its signed reversibility class is
 * {@code reversible}, the {@link Engine} (the verifier's own CONFIRMED action definitions) returns a plan, and the compensating action is AUTHORIZED
 * under the original grant (the Policy VM releases it over the original PCActn's verified chain). Anything else stays irreversible.</li>
 * <li><b>open</b>: writes the record DURABLY before the effect may run (a store that is not durable is refused), signs the {@code opened} receipt, mints
 * the one-click undo token and notifies the principal. A window nobody was told about is no window: a failed notification aborts the record and alerts.</li>
 * <li><b>veto</b>: a valid token (or an operator, a fraud proof, a revocation policy) inside the window moves {@code open -> vetoed} exactly once and
 * starts the compensation.</li>
 * <li><b>compensate</b>: re-decides the compensating action under the grant AS IT STOOD AT ADMISSION, then runs it at most once per attempt through the
 * operation store and the compensator. Success: {@code compensated}, the budget reservation released. Anything else: {@code compensation_failed}, the
 * reservation kept and an alert raised (never silent).</li>
 * <li><b>finalizeDue</b>: closes the windows whose time is up ({@code open -> finalized}) and commits their budget reservations.</li>
 * </ul>
 *
 * <p>Synchronous: every injected callback is a plain call. Records are the maps of {@link Undo} (numbers as {@link Json.Num}).
 */
public final class UndoCoordinator {
    private static final int MAX_CAS = 64;
    /** With a veto relay, a window is finalized only this long after it ended (a veto in flight at the relay still lands). */
    public static final long UNDO_RELAY_GRACE_MS = 60_000L;

    // ---- the injected pieces ----

    /** The source of confirmed reversibility. It must answer from SIGNED, reviewer-confirmed definitions only. */
    public interface Engine {
        /** A plan {@code {def_digest, compensation: {verb, params, def_digest, target_param?}, render?, render_digest?}}, or null (not undoable = irreversible). */
        Map<String, Object> plan(Map<String, Object> op, String operationId);
    }

    /** The principal's channels. Never throws (a throw counts as not delivered). */
    public interface Notifier {
        Notice notify(Map<String, Object> notice);
    }

    /** Whether at least one of the principal's channels accepted the notice. */
    public static final class Notice {
        public final boolean delivered;
        public final String reason;
        public Notice(boolean delivered, String reason) { this.delivered = delivered; this.reason = reason; }
    }

    /** What the per-operation policy says. */
    public static final class Policy {
        /** {@code always} (default), {@code escalations} or {@code off}. */
        public String mode;
        public Double windowMs;
        /** {@code keep} (default) or {@code veto}. */
        public String onRevocation;
    }

    public interface PolicyFn { Policy policy(Map<String, Object> op, Map<String, Object> grant); }

    /** The grant by reference, from YOUR store (the same lookup {@code authorize} uses); null when unknown. */
    public interface GrantResolver { Map<String, Object> resolve(String grantRef, Map<String, Object> pcactn); }

    /** What the compensating-action executor receives. */
    public static final class CompensationCall {
        /** The compensating operation with its target filled in (when the definition names one). */
        public final Map<String, Object> operation;
        /** The idempotency key of this attempt (pass it to the downstream call). */
        public final String idempotencyKey;
        /** The original operation id ({@code undo_of}). */
        public final String undoOf;
        public final boolean hasOriginalResult;
        public final Object originalResult;
        public final Map<String, Object> record;

        CompensationCall(Map<String, Object> operation, String idempotencyKey, String undoOf, boolean hasOriginalResult, Object originalResult, Map<String, Object> record) {
            this.operation = operation; this.idempotencyKey = idempotencyKey; this.undoOf = undoOf; this.hasOriginalResult = hasOriginalResult; this.originalResult = originalResult; this.record = record;
        }
    }

    /** Runs a compensating action (your connector); throw on failure. */
    public interface Compensator { Object compensate(CompensationCall call); }

    public static final class Alert {
        /** {@code critical} or {@code warning}. */
        public final String level;
        /** {@code compensation_failed}, {@code notify_failed}, {@code effect_unknown}, {@code slash_after_window}, {@code budget_settle_failed}, {@code revoked_open_window}, {@code compensation_denied} or {@code veto_relay_failed}. */
        public final String code;
        public final String record;
        public final String reason;
        public Alert(String level, String code, String record, String reason) { this.level = level; this.code = code; this.record = record; this.reason = reason; }
    }

    /** A veto taken by a relay: the principal's token and the time the relay received it. */
    public static final class RelayedVeto {
        public final String id;
        public final Object token;
        public final Object at;
        public RelayedVeto(String id, Object token, Object at) { this.id = id; this.token = token; this.at = at; }
    }

    /** Vetoes received somewhere else (the hosted veto endpoint); a relay that cannot be read throws (and so finalizes nothing). */
    public interface Relay { List<RelayedVeto> pending(); }

    /** Aggregate budgets held during the window: committed on finalize, released (with evidence) on compensation or abort. */
    public static final class Budget {
        public final BudgetLedger ledger;
        /** Optional: the release evidence for a reservation and the reason ({@code rollback} or {@code effect_not_run}); null: none. */
        public final BiFunction<Map<String, Object>, String, Map<String, Object>> evidence;
        public Budget(BudgetLedger ledger, BiFunction<Map<String, Object>, String, Map<String, Object>> evidence) { this.ledger = ledger; this.evidence = evidence; }
    }

    /** The bond ledger {@link #rollbackOnSlash} slashes through (for example {@code storeBondLedger::slashBond}). */
    public interface Slasher { Map<String, Object> slashBond(Map<String, Object> params); }

    /** The options of {@link #createUndoCoordinator}. */
    public static final class Options {
        /** REQUIRED: the durable undo ledger ({@code durable() == true}). */
        public UndoStore store;
        /** REQUIRED: confirmed reversibility and compensations. */
        public Engine engine;
        /** REQUIRED: the undo service key (32-byte Ed25519 seed): signs tokens and receipts. */
        public byte[] signerSecret;
        /** REQUIRED: this resource server's audience (bound into the token). */
        public String audience;
        /** REQUIRED. */
        public GrantResolver resolveGrant;
        /** REQUIRED: runs a compensating action. */
        public Compensator compensate;
        /** REQUIRED: at-most-once records for compensation attempts (shared and durable in production). */
        public OperationStore operations;
        /** REQUIRED: the principal's channels ({@link #undoNotifierFromDispatcher}). */
        public Notifier notifier;
        /** REQUIRED: where a failure that needs a human goes (pager, SIEM). Never silent. */
        public Consumer<Alert> alert;
        public PolicyFn policy;
        /** The window bounds (ms); null members take the defaults (30 s / 24 h / 15 min). */
        public Double windowMinMs, windowMaxMs, windowDefaultMs;
        /** The value of the compensating action's target parameter. Default: {@code effect.result.id} when it is a non-empty string. */
        public Function<Map<String, Object>, String> resolveTarget;
        public Budget budget;
        /** Verifier-side PQ pins forwarded to the compensation decision. */
        public Map<String, Object> pqPins;
        /** A vetoed record whose effect was never reported is compensated anyway after this long (ms). Default 5 minutes. */
        public long effectTimeoutMs = 5 * 60_000L;
        public LongSupplier now;
        public Relay relay;
        /** TESTS ONLY: accept a store whose {@code durable()} is false (every open window is lost on restart). */
        public boolean insecureVolatileStore;
    }

    /** The answer of a veto. */
    public static final class VetoResult {
        public final boolean ok;
        public final Map<String, Object> record;
        public final boolean replayed;
        public final String code, reason;

        VetoResult(boolean ok, Map<String, Object> record, boolean replayed, String code, String reason) { this.ok = ok; this.record = record; this.replayed = replayed; this.code = code; this.reason = reason; }

        static VetoResult fail(String code, String reason) { return new VetoResult(false, null, false, code, reason); }
    }

    /** {@link #rollbackOnSlash}: the bond settlement and the veto that followed it. */
    public static final class SlashResult {
        public final Map<String, Object> settlement;
        public final VetoResult veto;
        SlashResult(Map<String, Object> settlement, VetoResult veto) { this.settlement = settlement; this.veto = veto; }
    }

    private static final class Applied {
        final Map<String, Object> record;
        final boolean applied;
        final String refused, reason;
        Applied(Map<String, Object> record, boolean applied, String refused, String reason) { this.record = record; this.applied = applied; this.refused = refused; this.reason = reason; }
    }

    // ---- construction ----

    private final Options o;
    private final UndoStore store;
    private final Keys.EdKey key;
    private final LongSupplier clock;
    /** The undo service key's public half (b64u), for verifying tokens and receipts elsewhere. */
    public final String signerPublic;

    private UndoCoordinator(Options o) {
        this.o = o;
        this.store = o.store;
        this.key = Keys.edFromSeed(o.signerSecret);
        this.clock = o.now != null ? o.now : System::currentTimeMillis;
        this.signerPublic = key.id();
    }

    /** The names of the required components that are absent or malformed. */
    public static List<String> missingUndoComponents(Options x) {
        List<String> m = new ArrayList<>();
        Options y = x == null ? new Options() : x;
        if (!UndoStore.isUndoStore(y.store)) m.add("store");
        if (y.engine == null) m.add("engine");
        if (y.signerSecret == null || y.signerSecret.length != 32) m.add("signerSecret");
        if (y.audience == null || y.audience.isEmpty()) m.add("audience");
        if (y.resolveGrant == null) m.add("resolveGrant");
        if (y.compensate == null) m.add("compensate");
        if (y.operations == null) m.add("operations");
        if (y.notifier == null) m.add("notifier");
        if (y.alert == null) m.add("alert");
        return m;
    }

    /** Build the coordinator. Throws {@code config} for a missing component and {@code not_durable} for a volatile store (fail closed). */
    public static UndoCoordinator createUndoCoordinator(Options opts) {
        List<String> missing = missingUndoComponents(opts);
        if (!missing.isEmpty()) throw new Undo.UndoError("config", "undo coordinator: missing required component(s): " + String.join(", ", missing));
        if (!(opts.effectTimeoutMs >= 0)) throw new Undo.UndoError("config", "undo coordinator: effectTimeoutMs must be a non-negative number");
        if (!opts.store.durable() && !opts.insecureVolatileStore) throw new Undo.UndoError("not_durable", "an undo ledger must be durable: a restart would lose every open window and its compensation");
        return new UndoCoordinator(opts);
    }

    /** The undo service key's public half, for verifying tokens and receipts elsewhere (for example the hosted veto route). */
    public static String undoSignerPublic(byte[] secret) { return Keys.edFromSeed(secret).id(); }

    // ---- plumbing ----

    @SuppressWarnings("unchecked")
    private static Map<String, Object> m(Object x) { return (Map<String, Object>) x; }

    private static Object deep(Object v) { return IntentJs.normalize(v); }

    private static Json.Num num(long v) { return IntentJs.ofLong(v); }

    private static Map<String, Object> obj(Object... kv) {
        Map<String, Object> r = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]);
        return r;
    }

    private long now() {
        long t = clock.getAsLong();
        if (t < -9007199254740991L || t > 9007199254740991L) throw new Undo.UndoError("invalid", "the clock returned a non-finite time");
        return t;
    }

    private static Map<String, Object> strip(Map<String, Object> r) {
        Map<String, Object> out = new LinkedHashMap<>(r);
        out.remove("pcactn");
        out.remove("receipts");
        return out;
    }

    private void alert(Alert a) {
        try {
            o.alert.accept(a);
        } catch (RuntimeException e) {
            // an alert sink that throws is itself a failure the operator must see: write it where a host always looks
            System.err.println("pca undo alert (" + a.code + ") for " + a.record + ": " + a.reason);
        }
    }

    private Notice notify(Map<String, Object> n) {
        try {
            Notice r = o.notifier.notify(n);
            if (r != null && r.delivered) return new Notice(true, null);
            return new Notice(false, r != null && r.reason != null ? r.reason : "no channel delivered the notice");
        } catch (RuntimeException e) {
            return new Notice(false, e.getMessage() != null ? e.getMessage() : "notifier error");
        }
    }

    private static Map<String, Object> notice(String kind, Map<String, Object> record) { return obj("kind", kind, "record", strip(record)); }

    /** Apply one event with compare-and-swap retries; returns the stored record and whether this call applied it. */
    private Applied apply(String id, Map<String, Object> ev, Long checkAt) {
        for (int i = 0; i < MAX_CAS; i++) {
            Map<String, Object> cur = store.get(id);
            if (cur == null) return new Applied(null, false, "unknown", "no undo record " + id);
            long t = now();
            // a relayed veto is judged as of when the principal made it; its receipt is still written at the current time
            Undo.Transition tr = Undo.transition(cur, ev, num(checkAt != null ? checkAt : t));
            if (tr.outcome.equals("refused")) return new Applied(null, false, tr.code, tr.reason);
            if (tr.outcome.equals("replayed")) return new Applied(tr.record, false, null, null);
            Map<String, Object> next = Undo.withReceipt(tr.record, tr.event, tr.note, t, key);
            if (store.replace(id, IntentJs.lng(cur.get("ver")), next)) return new Applied(next, true, null, null);
        }
        throw new Undo.UndoError("conflict_exhausted", "undo record " + id + " kept changing");
    }

    private Applied must(String id, Map<String, Object> ev) {
        Applied r = apply(id, ev, null);
        if (r.refused != null) throw new Undo.UndoError("invalid", r.refused + ": " + r.reason);
        return r;
    }

    private void settleBudget(Map<String, Object> rec, String how) {
        Budget b = o.budget;
        if (b == null || !(rec.get("budget") instanceof List) || ((List<?>) rec.get("budget")).isEmpty()) return;
        for (Object ro : (List<?>) rec.get("budget")) {
            Map<String, Object> r = m(ro);
            String k = (String) r.get("key"), id = (String) r.get("id");
            try {
                BudgetLedger.SettleOutcome out = how.equals("commit") ? b.ledger.commit(k, id) : b.ledger.release(k, id, b.evidence != null ? b.evidence.apply(r, how) : null);
                if (!out.outcome.equals("settled") && !out.outcome.equals("replayed")) {
                    alert(new Alert("warning", "budget_settle_failed", (String) rec.get("id"), how + " of " + k + "/" + id + ": " + out.outcome));
                }
            } catch (RuntimeException e) {
                alert(new Alert("warning", "budget_settle_failed", (String) rec.get("id"), how + " of " + k + "/" + id + ": " + (e.getMessage() != null ? e.getMessage() : "error")));
            }
        }
    }

    private Policy policyOf(Map<String, Object> op, Map<String, Object> grant) {
        Policy p = o.policy != null ? o.policy.policy(op, grant) : null;
        return p != null ? p : new Policy();
    }

    /** The Policy VM on the compensating action under the original chain, at {@code at} (the admission time). Returns null when allowed, else the reason. */
    private String compensationDenied(Map<String, Object> pc, Map<String, Object> grant, Map<String, Object> op, long at) {
        Map<String, Object> in = new LinkedHashMap<>();
        in.put("grant", grant);
        in.put("trustedRoot", grant);
        in.put("chain", pc.get("cap_chain"));
        if (o.pqPins != null) in.put("pqPins", o.pqPins);
        Object params = op.get("params");
        in.put("action", obj("action", obj("verb", op.get("verb"), "resource", op.get("resource"), "params", params instanceof Map ? params : new LinkedHashMap<String, Object>())));
        in.put("risk", new LinkedHashMap<String, Object>());
        in.put("budget", obj("B", num(0), "tau", num(at)));
        in.put("now", num(at));
        Map<String, Object> d = Decide.decide(in);
        if (Boolean.TRUE.equals(d.get("releaseGuardianShare"))) return null;
        if (d.get("reasons") instanceof List) {
            for (Object r : (List<?>) d.get("reasons")) if (r instanceof String && !((String) r).startsWith("risk input")) return (String) r;
        }
        return "the grant does not authorize the compensating action";
    }

    // ---- the API ----

    /**
     * ELIGIBILITY: an admission map {@code {id, opened_at, window_end, converted, plan, compensation, pcactn, grant, operation}}, or
     * {@code {refused: reason}}. {@code grant} null: resolved by reference. Never throws.
     */
    public Map<String, Object> admit(Map<String, Object> pcactn, Map<String, Object> operation, boolean converted, Map<String, Object> grant) {
        try {
            Map<String, Object> pc = pcactn, op = operation;
            if (pc == null || op == null || !(op.get("verb") instanceof String) || !(op.get("resource") instanceof String)) return obj("refused", "no operation");
            Map<String, Object> g = grant != null ? grant : o.resolveGrant.resolve(pc.get("grant_ref") instanceof String ? (String) pc.get("grant_ref") : null, pc);
            if (g == null) return obj("refused", "unknown grant");
            Policy pol = policyOf(op, g);
            String mode = pol.mode != null ? pol.mode : "always";
            if (mode.equals("off")) return obj("refused", "policy: undo windows are off");
            if (mode.equals("escalations") && !converted) return obj("refused", "policy: windows only replace approvals");
            // the stricter of the signed class and the definition applies: an agent signing `irreversible` is taken at its word
            Object act = pc.get("action");
            Object cls = act instanceof Map ? m(act).get("reversibility_class") : null;
            if (RevocationStaleness.classRank(cls) != 0) return obj("refused", "the signed class is " + (cls == null ? "undefined" : cls));
            String id = Pca.hashCanonical(pc);
            Map<String, Object> plan = o.engine.plan(op, id);
            if (plan == null) return obj("refused", "not confirmed reversible, or no confirmed compensating action");
            Map<String, Object> pcomp = m(plan.get("compensation"));
            Map<String, Object> comp = obj("verb", pcomp.get("verb"), "resource", op.get("resource"), "params", deep(pcomp.get("params")), "undo_of", id, "def_digest", pcomp.get("def_digest"));
            if (pcomp.get("target_param") != null) comp.put("target_param", pcomp.get("target_param"));
            long t = now();
            String denied = compensationDenied(pc, g, obj("verb", comp.get("verb"), "resource", comp.get("resource"), "params", comp.get("params")), t);
            if (denied != null) return obj("refused", "the compensating action is not authorized under the grant: " + denied);
            long windowMs = Undo.resolveWindow(pol.windowMs, o.windowMinMs, o.windowMaxMs, o.windowDefaultMs);
            Object opParams = op.get("params");
            return obj("id", id, "opened_at", num(t), "window_end", num(t + windowMs), "converted", converted, "plan", plan, "compensation", comp, "pcactn", pc, "grant", g,
                "operation", obj("verb", op.get("verb"), "resource", op.get("resource"), "params", deep(opParams instanceof Map ? opParams : new LinkedHashMap<String, Object>())));
        } catch (RuntimeException e) {
            return obj("refused", "undo admission error (fail closed): " + (e.getMessage() != null ? e.getMessage() : "unknown"));
        }
    }

    private Map<String, Object> infoOf(Map<String, Object> rec) {
        Map<String, Object> comp = m(rec.get("compensation"));
        return obj("id", rec.get("id"), "window_end", rec.get("window_end"), "converted", rec.get("converted"),
            "compensation", obj("verb", comp.get("verb"), "resource", comp.get("resource")),
            "token", Undo.encodeToken(Undo.signToken(rec, key)),
            "obligation", obj("kind", "undo_window", "params", obj("id", rec.get("id"), "window_end", rec.get("window_end")), "due", rec.get("window_end")));
    }

    /**
     * Write the record durably, sign the {@code opened} receipt, mint the one-click token and tell the principal. {@code bondRef} /
     * {@code bondChallengeEndsAt} (both or neither) tie the window to a bond challenge. Returns {@code {id, window_end, converted, compensation, token, obligation}}.
     */
    public Map<String, Object> open(Map<String, Object> adm, String bondRef, Long bondChallengeEndsAt) {
        Map<String, Object> pc = m(adm.get("pcactn"));
        List<?> chain = (List<?>) pc.get("cap_chain");
        long admEnd = IntentJs.lng(adm.get("window_end"));
        long windowEnd = bondRef != null && bondChallengeEndsAt != null ? Math.max(admEnd, bondChallengeEndsAt) : admEnd;
        Map<String, Object> comp = m(adm.get("compensation"));
        String cdig = Undo.compensationDigest(comp);
        Map<String, Object> plan = m(adm.get("plan"));
        Map<String, Object> op = m(adm.get("operation"));
        Map<String, Object> base = new LinkedHashMap<>();
        base.put("v", num(1));
        base.put("id", adm.get("id"));
        base.put("aud", o.audience);
        base.put("grant_ref", pc.get("grant_ref"));
        base.put("holder", m(chain.get(chain.size() - 1)).get("holder"));
        base.put("principal", m(adm.get("grant")).get("issuer"));
        base.put("action", obj("verb", op.get("verb"), "resource", op.get("resource"), "params_digest", m(pc.get("action")).get("params_digest"), "def_digest", plan.get("def_digest")));
        base.put("compensation", comp);
        base.put("compensation_digest", cdig);
        if (plan.get("render_digest") != null) base.put("render_digest", plan.get("render_digest"));
        base.put("opened_at", adm.get("opened_at"));
        base.put("window_end", num(windowEnd));
        base.put("converted", adm.get("converted"));
        base.put("state", "open");
        base.put("ver", num(0));
        base.put("pcactn", Pca.canonicalizeLenientServerOnly(pc));
        if (bondRef != null && bondChallengeEndsAt != null) base.put("bond_ref", bondRef);
        base.put("attempt", num(0));
        base.put("receipts", new ArrayList<Object>());
        Map<String, Object> rec = Undo.withReceipt(m(deep(base)), "opened", Boolean.TRUE.equals(adm.get("converted")) ? "converted" : "", IntentJs.lng(adm.get("opened_at")), key);
        UndoStore.CreateResult c = store.create(rec);
        if (!c.created) {
            // a retry of the same admission returns the same window; anything else is a different action under the same id
            if (!cdig.equals(c.record.get("compensation_digest")) || !"open".equals(c.record.get("state"))) {
                throw new Undo.UndoError("invalid", "undo record " + adm.get("id") + " already exists with other terms or state " + c.record.get("state"));
            }
            return infoOf(c.record);
        }
        Map<String, Object> info = infoOf(rec);
        Map<String, Object> n = notice("opened", rec);
        n.put("token", info.get("token"));
        if (plan.get("render") != null) n.put("render", plan.get("render"));
        Notice sent = notify(n);
        if (!sent.delivered) {
            apply((String) rec.get("id"), obj("kind", "abort", "reason", "notify_failed"), null);
            String why = sent.reason != null ? sent.reason : "not delivered";
            alert(new Alert("critical", "notify_failed", (String) rec.get("id"), "the principal could not be told about the undo window: " + why));
            throw new Undo.UndoError("invalid", "notify_failed: the undo window could not be announced (" + why + ")");
        }
        return info;
    }

    public Map<String, Object> open(Map<String, Object> adm) { return open(adm, null, null); }

    public Map<String, Object> get(String id) { return store.get(id); }

    /** Hold aggregate budget reservations {@code [{key, id}]} until the window closes. */
    public Map<String, Object> holdBudget(String id, List<Map<String, Object>> reservations) {
        for (int i = 0; i < MAX_CAS; i++) {
            Map<String, Object> cur = store.get(id);
            if (cur == null) throw new Undo.UndoError("invalid", "no undo record " + id);
            if (!"open".equals(cur.get("state")) && !"vetoed".equals(cur.get("state"))) throw new Undo.UndoError("invalid", "a " + cur.get("state") + " record holds no budget");
            List<Object> held = new ArrayList<>();
            if (cur.get("budget") instanceof List) held.addAll((List<?>) cur.get("budget"));
            for (Map<String, Object> r : reservations) held.add(obj("key", r.get("key"), "id", r.get("id")));
            Map<String, Object> next = new LinkedHashMap<>(cur);
            next.put("budget", held);
            next.put("ver", num(IntentJs.lng(cur.get("ver")) + 1));
            if (store.replace(id, IntentJs.lng(cur.get("ver")), next)) return next;
        }
        throw new Undo.UndoError("conflict_exhausted", "undo record " + id + " kept changing");
    }

    /** Report the original effect (its result names the compensation target). A veto that arrived while it ran is acted on now. */
    public Map<String, Object> recordEffect(String id, Object result, boolean hasResult) {
        Map<String, Object> ev = obj("kind", "effect");
        if (hasResult) ev.put("result", result);
        Applied r = must(id, ev);
        return "vetoed".equals(r.record.get("state")) ? runCompensation(r.record) : r.record;
    }

    public Map<String, Object> recordEffect(String id, Object result) { return recordEffect(id, result, result != null); }

    public Map<String, Object> abort(String id, String reason) {
        Applied r = must(id, obj("kind", "abort", "reason", reason));
        if (r.applied) settleBudget(r.record, "effect_not_run");
        return r.record;
    }

    private Map<String, Object> finishCompensated(Map<String, Object> rec) {
        if ("compensated".equals(rec.get("state"))) {
            settleBudget(rec, "rollback");
            notify(notice("compensated", rec));
        }
        return rec;
    }

    private Map<String, Object> fail(Map<String, Object> rec, String reason, String code) {
        Applied r = apply((String) rec.get("id"), obj("kind", "compensation_failed", "reason", reason), null);
        Map<String, Object> out;
        if (r.refused != null) {
            Map<String, Object> s = store.get((String) rec.get("id"));
            out = s != null ? s : rec;
        } else out = r.record;
        if (r.refused == null && r.applied) {
            alert(new Alert("critical", code, (String) rec.get("id"), reason));
            notify(notice("compensation_failed", out));
        }
        return out;
    }

    private static Map<String, Object> decodePcactn(Object text) {
        if (!(text instanceof String)) throw new IllegalArgumentException("decodePCActn: not a string");
        if (Pca.artifactTooLarge((String) text)) throw new IllegalArgumentException(Pca.ARTIFACT_SIZE_REASON); // FIRST: before any parsing
        Object v = Json.parse((String) text);
        if (!(v instanceof Map)) throw new IllegalArgumentException("decodePCActn: not an object");
        return m(v);
    }

    private Map<String, Object> runCompensation(Map<String, Object> rec0) {
        Map<String, Object> rec = rec0;
        if (!"vetoed".equals(rec.get("state"))) return rec;
        long t = now();
        Object veto0 = rec.get("veto");
        long vetoAt = veto0 instanceof Map && IntentJs.num(m(veto0).get("at")) != null ? IntentJs.lng(m(veto0).get("at")) : t;
        if (!rec.containsKey("effect") && t - vetoAt < o.effectTimeoutMs) return rec; // wait for the effect report (recordEffect resumes)
        Map<String, Object> pc = decodePcactn(rec.get("pcactn"));
        Map<String, Object> grant = o.resolveGrant.resolve((String) rec.get("grant_ref"), pc);
        if (grant == null) return fail(rec, "the grant is no longer known: the compensation cannot be authorized", "compensation_denied");
        Map<String, Object> comp = m(rec.get("compensation"));
        Map<String, Object> params = new LinkedHashMap<>(m(comp.get("params")));
        Object tp = comp.get("target_param");
        if (tp != null) {
            String target;
            if (o.resolveTarget != null) target = o.resolveTarget.apply(rec);
            else {
                Object eff = rec.get("effect");
                Object res = eff instanceof Map ? m(eff).get("result") : null;
                Object rid = res instanceof Map ? m(res).get("id") : null;
                target = rid instanceof String && !((String) rid).isEmpty() ? (String) rid : null;
            }
            if (target == null) return fail(rec, "the target '" + tp + "' of the compensation is unknown (no effect result names it)", "compensation_failed");
            params.put((String) tp, target);
        }
        Map<String, Object> op = obj("verb", comp.get("verb"), "resource", comp.get("resource"), "params", params);
        String denied = compensationDenied(pc, grant, op, IntentJs.lng(rec.get("opened_at")));
        if (denied != null) return fail(rec, "the compensating action is not authorized under the grant: " + denied, "compensation_denied");
        OperationStore ops = o.operations;
        // at most once per attempt: the operation record is created before the compensator runs
        String opId = Pca.hashCanonical(obj("d", "atlas-pca/undo-compensation-op/v1", "record", rec.get("id"), "attempt", rec.get("attempt")));
        OperationRecord orec = OperationRecord.pending(opId, (String) op.get("verb"), (String) op.get("resource"), Pca.hashCanonical(params), "irreversible", t);
        OperationRecord prev = ops.create(orec);
        if (prev != null) {
            if (OperationRecord.COMMITTED.equals(prev.state())) {
                Map<String, Object> ev = obj("kind", "compensated");
                if (prev.hasResult()) ev.put("result", prev.result());
                Applied r = apply((String) rec.get("id"), ev, null);
                if (r.refused == null) rec = r.record;
                return finishCompensated(rec);
            }
            if (OperationRecord.FAILED.equals(prev.state()) || OperationRecord.UNCERTAIN.equals(prev.state())) {
                return fail(rec, "compensation attempt " + IntentJs.lng(rec.get("attempt")) + " " + prev.state() + ": " + (prev.error() != null ? prev.error() : ""), "compensation_failed");
            }
            if (OperationRecord.ABORTED.equals(prev.state())) {
                Applied r = apply((String) rec.get("id"), obj("kind", "compensation_failed", "reason", "attempt never started"), null);
                if (r.refused != null) return rec;
                Applied again = apply((String) rec.get("id"), obj("kind", "retry"), null);
                return again.refused != null ? r.record : runCompensation(again.record);
            }
            // pending / executing: another worker holds it, or a crash; stale ones are settled here
            long since = prev.executingAt() != null ? prev.executingAt() : prev.startedAt();
            if (t - since > o.effectTimeoutMs) {
                OperationRecord settled = OperationRecord.PENDING.equals(prev.state()) ? prev.moved(OperationRecord.ABORTED, null, t, "never started")
                    : prev.moved(OperationRecord.UNCERTAIN, null, t, "no outcome recorded: the compensation may or may not have run");
                ops.transition(prev.id(), prev.state(), settled);
                Map<String, Object> again = store.get((String) rec.get("id"));
                return runCompensation(again != null ? again : rec);
            }
            return rec;
        }
        // re-read under the record: a concurrent retry or resolution wins
        Map<String, Object> cur = store.get((String) rec.get("id"));
        if (cur == null || !"vetoed".equals(cur.get("state")) || IntentJs.lng(cur.get("attempt")) != IntentJs.lng(rec.get("attempt"))) {
            ops.transition(opId, OperationRecord.PENDING, orec.moved(OperationRecord.ABORTED, null, now(), "the undo record moved on"));
            return cur != null ? cur : rec;
        }
        OperationRecord running = orec.moved(OperationRecord.EXECUTING, now(), null, null);
        if (!ops.transition(opId, OperationRecord.PENDING, running)) {
            Map<String, Object> s = store.get((String) rec.get("id"));
            return s != null ? s : rec;
        }
        Object eff = rec.get("effect");
        boolean hasOrig = eff instanceof Map && m(eff).get("result") != null;
        Map<String, Object> callRec = new LinkedHashMap<>(cur);
        callRec.remove("pcactn");
        Object result;
        try {
            result = o.compensate.compensate(new CompensationCall(op, opId, (String) rec.get("id"), hasOrig, hasOrig ? m(eff).get("result") : null, callRec));
        } catch (RuntimeException e) {
            String error = e.getMessage() != null ? e.getMessage() : e.toString();
            try {
                ops.transition(opId, OperationRecord.EXECUTING, running.moved(OperationRecord.FAILED, null, now(), error));
            } catch (RuntimeException ignored) {
                // the failed record is a courtesy: the undo record below carries the failure
            }
            return fail(rec, "the compensating action failed: " + error, "compensation_failed");
        }
        try {
            OperationRecord done = running.moved(OperationRecord.COMMITTED, null, now(), null);
            if (result != null) done = done.with("result", result);
            ops.transition(opId, OperationRecord.EXECUTING, done);
        } catch (RuntimeException ignored) {
            // the committed record is a courtesy: the undo record below carries the outcome
        }
        Map<String, Object> ev = obj("kind", "compensated");
        if (result != null) ev.put("result", result);
        Applied r = apply((String) rec.get("id"), ev, null);
        if (r.refused != null) {
            Map<String, Object> s = store.get((String) rec.get("id"));
            return s != null ? s : rec;
        }
        return finishCompensated(r.record);
    }

    /** Veto with the one-click token (the principal); {@code at} (nullable) is the time a relay received it. */
    public VetoResult vetoWithToken(String id, Object token, Object at) { return veto(id, token, true, at, null, null); }

    /** Veto as an authenticated operator of this server. */
    public VetoResult vetoAsOperator(String id, String operator) { return veto(id, null, false, null, operator, null); }

    /** Veto with a prepared veto ({@code {via: revocation | fraud_proof, by, evidence?}}). */
    public VetoResult vetoWith(String id, Map<String, Object> veto) { return veto(id, null, false, null, null, veto); }

    private VetoResult veto(String id, Object token, boolean byToken, Object at, String operator, Map<String, Object> prepared) {
        try {
            Map<String, Object> cur = store.get(id);
            if (cur == null) return VetoResult.fail("unknown", "no undo record " + id);
            Map<String, Object> v;
            long t = now();
            Long checkAt = null;
            if (byToken) {
                if (at != null) {
                    if (!IntentJs.isInt(at) || IntentJs.lng(at) > t || IntentJs.lng(at) < IntentJs.lng(cur.get("opened_at"))) {
                        return VetoResult.fail("malformed", "a relayed veto time must lie between the opening of the window and now");
                    }
                    t = IntentJs.lng(at);
                    checkAt = t;
                }
                Object tok = token instanceof String ? Undo.decodeToken(token) : token;
                String chk = Undo.tokenCheck(tok, signerPublic, cur, t);
                if (!chk.equals(Undo.OK)) return VetoResult.fail(chk, "the undo token was refused (" + chk + ")");
                v = obj("at", num(t), "via", "token", "by", cur.get("principal"), "evidence", Undo.tokenDigest(m(tok)));
            } else if (operator != null || prepared == null) {
                if (operator == null || operator.isEmpty()) return VetoResult.fail("malformed", "an operator veto names the operator");
                v = obj("at", num(t), "via", "operator", "by", operator);
            } else {
                v = new LinkedHashMap<>(prepared);
                v.put("at", num(t));
            }
            Applied r = apply(id, obj("kind", "veto", "veto", v), checkAt);
            if (r.refused != null) return VetoResult.fail(r.refused, r.reason);
            if (r.applied) notify(notice("vetoed", r.record));
            Map<String, Object> done = runCompensation(r.record);
            return new VetoResult(true, done, !r.applied, null, null);
        } catch (RuntimeException e) {
            return VetoResult.fail("malformed", "veto error (fail closed): " + (e.getMessage() != null ? e.getMessage() : "unknown"));
        }
    }

    /** Apply the relay's pending vetoes now (also done by every {@link #finalizeDue}). Throws when the relay cannot be read. */
    public List<VetoResult> syncRelay() {
        List<VetoResult> out = new ArrayList<>();
        if (o.relay == null) return out;
        List<RelayedVeto> list = o.relay.pending();
        if (list == null) throw new Undo.UndoError("invalid", "the veto relay returned no list");
        for (RelayedVeto x : list) {
            if (x == null || x.id == null) continue;
            // a forged or late relay entry is refused by the same checks as any veto
            out.add(vetoWithToken(x.id, x.token, x.at));
        }
        return out;
    }

    public Map<String, Object> compensate(String id) {
        Map<String, Object> cur = store.get(id);
        if (cur == null) throw new Undo.UndoError("invalid", "no undo record " + id);
        return runCompensation(cur);
    }

    public Map<String, Object> retry(String id) { return runCompensation(must(id, obj("kind", "retry")).record); }

    /** Close the windows whose time is up ({@code open -> finalized}) and commit their budget reservations; returns the finalized ids. */
    public List<String> finalizeDue() {
        List<String> out = new ArrayList<>();
        try {
            syncRelay();
        } catch (RuntimeException e) {
            // a veto may be waiting at the relay: closing any window now could finalize an action the principal undid
            alert(new Alert("critical", "veto_relay_failed", "*", "the veto relay could not be read; no window was finalized: " + (e.getMessage() != null ? e.getMessage() : "error")));
            return out;
        }
        // with a relay, a veto accepted there just before the window closed may still be in flight: wait out a grace period
        UndoStore.Query q = new UndoStore.Query("open");
        q.windowEndedBy = now() - 1 - (o.relay != null ? UNDO_RELAY_GRACE_MS : 0);
        for (Map<String, Object> rec : store.list(q)) {
            Applied r = apply((String) rec.get("id"), obj("kind", "finalize"), null);
            if (r.refused != null || !r.applied) continue;
            out.add((String) rec.get("id"));
            if (!r.record.containsKey("effect")) {
                alert(new Alert("warning", "effect_unknown", (String) rec.get("id"), "the window closed without an effect report: reconcile the original operation"));
            }
            settleBudget(r.record, "commit");
            notify(notice("finalized", r.record));
        }
        return out;
    }

    /** After a restart: resume every vetoed record's compensation, then finalize what is due. */
    public List<String> recover() {
        List<String> out = new ArrayList<>();
        for (Map<String, Object> rec : store.list(new UndoStore.Query("vetoed"))) {
            if (!"vetoed".equals(runCompensation(rec).get("state"))) out.add((String) rec.get("id"));
        }
        out.addAll(finalizeDue());
        return out;
    }

    /** A grant was revoked: veto its open windows when the policy says so, else alert and tell the principal. */
    public List<String> onRevocation(String grantRef) {
        List<String> out = new ArrayList<>();
        UndoStore.Query q = new UndoStore.Query("open");
        q.grantRef = grantRef;
        for (Map<String, Object> rec : store.list(q)) {
            Map<String, Object> pc = decodePcactn(rec.get("pcactn"));
            Map<String, Object> grant = o.resolveGrant.resolve((String) rec.get("grant_ref"), pc);
            Map<String, Object> act = m(rec.get("action"));
            Policy pol = grant != null ? policyOf(obj("verb", act.get("verb"), "resource", act.get("resource")), grant) : new Policy();
            if ("veto".equals(pol.onRevocation != null ? pol.onRevocation : "keep")) {
                if (vetoWith((String) rec.get("id"), obj("at", num(0), "via", "revocation", "by", grantRef)).ok) out.add((String) rec.get("id"));
            } else {
                alert(new Alert("warning", "revoked_open_window", (String) rec.get("id"), "grant " + grantRef + " was revoked while this window is open; the principal can still undo it"));
                notify(notice("revoked", rec));
            }
        }
        return out;
    }

    /** Slash a bond (the bond ledger re-verifies the fraud proof itself and refuses outside the challenge window), then undo the record. */
    public SlashResult rollbackOnSlash(Slasher bonds, Map<String, Object> params) {
        Map<String, Object> settlement = bonds.slashBond(params);
        String claimId = (String) params.get("claimId");
        String evidence = Pca.hashCanonical(obj("d", "atlas-pca/undo-slash-ref/v1", "settlement", settlement));
        UndoStore.Query q = new UndoStore.Query("open");
        q.bondRef = claimId;
        List<Map<String, Object>> recs = store.list(q);
        Map<String, Object> target = !recs.isEmpty() ? recs.get(0) : store.get(claimId);
        if (target == null) return new SlashResult(settlement, VetoResult.fail("unknown", "no undo record for bond " + claimId));
        VetoResult v = vetoWith((String) target.get("id"), obj("at", num(0), "via", "fraud_proof", "by", claimId, "evidence", evidence));
        if (!v.ok) alert(new Alert("critical", "slash_after_window", (String) target.get("id"), "the bond was slashed but the effect could not be rolled back: " + v.reason));
        return new SlashResult(settlement, v);
    }

    // ---- the helpers around the coordinator ----

    /**
     * Execute-side report of an allowed {@code authorize()} result that carries an undo window: a committed effect is recorded (its result names the
     * compensation target), an effect that failed or never started aborts the window (nothing to undo; held budget released); pending / uncertain
     * leaves the window running ({@code finalizeDue} alerts if it closes without a report).
     */
    public static Map<String, Object> reportUndoEffect(UndoCoordinator undo, String id, Map<String, Object> outcome) {
        Object status = outcome.get("status");
        if ("committed".equals(status)) return undo.recordEffect(id, outcome.get("result"), outcome.containsKey("result"));
        if ("failed".equals(status) || "aborted".equals(status) || "refused".equals(status)) return undo.abort(id, "effect_" + status);
        Map<String, Object> r = undo.get(id);
        if (r == null) throw new Undo.UndoError("invalid", "no undo record " + id);
        return r;
    }

    /** {@code undoUrl(token, recordId)}: the one-click undo link. */
    public interface UndoUrl { String url(String token, String recordId); }

    private static final DateTimeFormatter ISO = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    /**
     * An undo {@link Notifier} over the approval channels (Slack, webhook, email, SMS, push). The notice becomes a step-up-shaped message whose
     * link is the one-click undo URL and whose render is the WYSIWYS render of the action.
     */
    public static Notifier undoNotifierFromDispatcher(ApprovalChannels.Dispatcher dispatcher, UndoUrl undoUrl, String inboxUrl) {
        return n -> {
            Map<String, Object> r = m(n.get("record"));
            String kind = (String) n.get("kind");
            Map<String, Object> act = m(r.get("action"));
            String what = act.get("verb") + " on " + act.get("resource");
            String until = ISO.format(Instant.ofEpochMilli(IntentJs.lng(r.get("window_end"))));
            String reason;
            switch (kind) {
                case "opened": reason = "Already done: " + what + ". You can undo it until " + until + "."; break;
                case "vetoed": reason = "Undo started for " + what + "."; break;
                case "compensated": reason = "Undone: " + what + "."; break;
                case "compensation_failed": {
                    Object out = r.get("outcome");
                    Object why = out instanceof Map ? m(out).get("reason") : null;
                    reason = "UNDO FAILED for " + what + ": " + (why instanceof String && !((String) why).isEmpty() ? why : "unknown") + ". An operator has been alerted.";
                    break;
                }
                case "revoked": reason = "The agent's grant was revoked. " + what + " can still be undone until " + until + "."; break;
                default: reason = "Final: " + what + " can no longer be undone.";
            }
            Map<String, Object> link = obj("kind", "action", "label", act.get("verb") + " " + act.get("resource"), "detail", "undo: " + m(r.get("compensation")).get("verb"));
            Map<String, Object> lineage = obj("goalCommit", "", "goalVerified", false, "chain", new ArrayList<Object>(List.of(link)), "because", reason);
            Map<String, Object> req = obj("id", "undo:" + r.get("id") + ":" + kind, "verb", act.get("verb"), "resource", act.get("resource"), "tier", num(3), "reason", reason,
                "goalCommit", "", "lineage", lineage, "r", num(0), "requestedAt", r.get("opened_at"));
            if (n.get("render") != null && r.get("render_digest") != null) {
                req.put("render", n.get("render"));
                req.put("renderDigest", r.get("render_digest"));
            }
            String url = "opened".equals(kind) && n.get("token") != null ? undoUrl.url((String) n.get("token"), (String) r.get("id")) : inboxUrl;
            ApprovalChannels.NotifyContext ctx = new ApprovalChannels.NotifyContext();
            ctx.inboxUrl = url;
            List<ApprovalChannels.Delivery> out = dispatcher.notifyAll(req, ctx);
            for (ApprovalChannels.Delivery d : out) if (d.delivered) return new Notice(true, null);
            List<String> parts = new ArrayList<>();
            for (ApprovalChannels.Delivery d : out) parts.add(d.kind + ": " + (d.reason != null ? d.reason : "not delivered"));
            return new Notice(false, parts.isEmpty() ? "no enabled channel" : String.join("; ", parts));
        };
    }

    /** The HTTP transport of {@link #hostedUndoVetoRelay}. */
    public interface RelayFetch { RelayResponse get(String url, Map<String, String> headers) throws Exception; }

    /** An HTTP answer: {@code ok} (2xx), the status and the parsed JSON body. */
    public static final class RelayResponse {
        public final boolean ok;
        public final int status;
        public final Object json;
        public RelayResponse(boolean ok, int status, Object json) { this.ok = ok; this.status = status; this.json = json; }
    }

    private static RelayFetch defaultFetch() {
        return (url, headers) -> {
            java.net.http.HttpRequest.Builder b = java.net.http.HttpRequest.newBuilder(java.net.URI.create(url)).GET().timeout(java.time.Duration.ofSeconds(30));
            for (Map.Entry<String, String> e : headers.entrySet()) b.header(e.getKey(), e.getValue());
            java.net.http.HttpResponse<byte[]> res = java.net.http.HttpClient.newHttpClient().send(b.build(), java.net.http.HttpResponse.BodyHandlers.ofByteArray());
            boolean ok = res.statusCode() >= 200 && res.statusCode() < 300;
            Object body = null;
            try {
                body = Json.parseLenient(new String(res.body(), StandardCharsets.UTF_8));
            } catch (RuntimeException e) {
                // not JSON: the caller refuses a missing body
            }
            return new RelayResponse(ok, res.statusCode(), body);
        };
    }

    /**
     * The relay over a hosted undo ledger: {@code GET {baseUrl}/v1/pca/undo/vetoes} with the instance secret key. Pass it as {@link Options#relay}. A
     * non-2xx answer or a malformed body throws (and so finalizes nothing). {@code fetch} null: {@code java.net.http}.
     */
    public static Relay hostedUndoVetoRelay(String baseUrl, String secretKey, RelayFetch fetch, Integer limit) {
        RelayFetch f = fetch != null ? fetch : defaultFetch();
        String base = baseUrl.replaceAll("/+$", "");
        int lim = Math.min(200, Math.max(1, limit == null ? 200 : limit));
        return () -> {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("authorization", "Bearer " + secretKey);
            headers.put("accept", "application/json");
            RelayResponse res;
            try {
                res = f.get(base + "/v1/pca/undo/vetoes?limit=" + lim, headers);
            } catch (RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new Undo.UndoError("invalid", "the veto relay could not be reached: " + (e.getMessage() != null ? e.getMessage() : e.toString()));
            }
            if (!res.ok) throw new Undo.UndoError("invalid", "the veto relay answered " + res.status);
            if (!(res.json instanceof Map) || !(m(res.json).get("data") instanceof List)) throw new Undo.UndoError("invalid", "the veto relay answered without a data list");
            List<RelayedVeto> out = new ArrayList<>();
            for (Object row : (List<?>) m(res.json).get("data")) {
                Object v = row instanceof Map ? m(row).get("veto") : null;
                if (!(row instanceof Map) || !(m(row).get("record_id") instanceof String) || !(v instanceof Map) || !(m(v).get("token") instanceof String) || IntentJs.num(m(v).get("at")) == null) {
                    throw new Undo.UndoError("invalid", "the veto relay answered a malformed entry");
                }
                out.add(new RelayedVeto((String) m(row).get("record_id"), m(v).get("token"), m(v).get("at")));
            }
            return out;
        };
    }
}
