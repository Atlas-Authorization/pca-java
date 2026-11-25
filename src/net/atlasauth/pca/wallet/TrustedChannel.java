package net.atlasauth.pca.wallet;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.DoubleSupplier;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.WalletBridge;
import net.atlasauth.pca.oauth.JsVal;
import net.atlasauth.pca.webauthn.Webauthn;

/**
 * The trusted question channel, one instance per session, wallet side.
 *
 * <ol>
 * <li>SELECTION belongs to the verifier: questions enter only as a site-signed intent_required (checked against the site's
 * discovery keys, the session, the current map digest and the action digest; the wallet re-derives the cell itself).
 * <li>The wallet RENDERS the card itself from fixed templates; no agent text exists on this path.
 * <li>Typed and device questions are always alone on their screen; tap and hold questions share a screen.
 * <li>FRICTION scales with harm, never below the site's minimum.
 * <li>CANARIES are inserted with probability rho and rendered like real questions; their answers only update the noise counts.
 * <li>CAPS: at most perSession (default 6) questions per session and perHour (default 12) per hour across the principal's
 * sessions; when the estimated false-yes rate passes eta_stop the session is frozen.
 * <li>A cell is asked at most once per session (clarified cells count as visited).
 * <li>Under estimated noise an irreversible cell needs two typed or device confirmations on screens at least two apart.
 * </ol>
 * What the channel returns for a real answer is the principal-signed observation. Results are maps shaped like the reference's.
 */
public final class TrustedChannel {
    /** Value-dependent reversibility of a box (from the signed schema); null means the verb's own. */
    public interface ReversibilityFn { String of(Map<String, Object> vs, int[][] box); }

    /** The principal's registered security keys. */
    public static final class DeviceTrust {
        public String rpId;
        public List<Object> origins = new ArrayList<>();
        /** Credential id to public key (a JWK map or the COSE_Key bytes). */
        public Map<String, Object> credentials = new LinkedHashMap<>();
        /** Last accepted signature counter per credential id (absent = 0); updated on each accepted assertion. May be null. */
        public Map<String, Object> signCounts;
    }

    public static final class Options {
        public Map<String, Object> omega;
        public String session;
        public Supplier<String> mapDigest;
        /** The principal's Ed25519 seed. */
        public byte[] principalSeed;
        public String siteOrigin, siteName;
        /** The site's discovery keys: {kid, alg, pk, pq_pk?}. */
        public List<Object> siteKeys = new ArrayList<>();
        /** The principal's own words, or null. */
        public String statementText;
        public Map<String, Object> units;
        public ReversibilityFn reversibility;
        public Map<String, Object> sensitivity;
        public List<String> identityPaths = new ArrayList<>();
        public WalletView view;
        public Function<Map<String, Object>, Map<String, Object>> lift;
        public UnaryOperator<Map<String, Object>> liftCandidate;
        public WalletOmega.HarmModel harm;
        public Map<String, Object> frictionThresholds;
        public Integer perSession, perHour;
        public WalletNoise.SlidingWindowCounter hourly;
        public Supplier<Map<String, Object>> noise;
        public Consumer<Map<String, Object>> onNoise;
        public Map<String, Object> fatigue;
        public Double rho;
        public DoubleSupplier rand;
        public DoubleSupplier now;
        public DeviceTrust device;
        public Integer maxPerScreen;
        public Integer maxBoxCells;
    }

    private static final class Item {
        String id, kind, source, verb;
        int[][] box;
        Map<String, Object> coords, card, action, vs, first;
        String actionDigest;
        boolean irreversible, jit;
        Integer expected;
        double weight, flat;
        Double expiresAt;
        Integer shownOn, notBefore;

        Item copy() {
            Item c = new Item();
            c.id = id; c.kind = kind; c.source = source; c.verb = verb; c.box = box; c.coords = coords; c.card = card; c.action = action; c.vs = vs; c.first = first;
            c.actionDigest = actionDigest; c.irreversible = irreversible; c.jit = jit; c.expected = expected; c.weight = weight; c.flat = flat; c.expiresAt = expiresAt;
            c.shownOn = shownOn; c.notBefore = notBefore;
            return c;
        }
    }

    private static final String B64U = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    private final Options o;
    private final Map<String, Item> pending = new LinkedHashMap<>();
    private final Set<String> asked = new HashSet<>();
    private final Set<String> canaryUsed = new HashSet<>();
    private final List<Map<String, Object>> knownYes = new ArrayList<>();
    private final Map<String, List<Map<String, Object>>> confirmations = new LinkedHashMap<>();
    private final List<Map<String, Object>> refusedWhileFrozen = new ArrayList<>();
    private int sessionQuestions = 0;
    private int canaries = 0;
    private int screenNo = 0;

    public TrustedChannel(Options opts) { this.o = opts; }

    private int perSession() { return o.perSession != null ? o.perSession : 6; }

    private int perHour() { return o.perHour != null ? o.perHour : 12; }

    private Map<String, Object> fatigue() { return o.fatigue != null ? o.fatigue : WalletNoise.defaultFatigue(); }

    private WalletOmega.HarmModel harm() { return o.harm != null ? o.harm : WalletOmega.DEFAULT_HARM; }

    /** The current noise state: {etaPos, etaPosBar, etaNegBar, frozen}. */
    public Map<String, Object> noise() { return WalletNoise.noiseState(o.noise.get(), o.hourly.count(o.now.getAsDouble()), fatigue()); }

    /** The admission policy the learner should use now: {tau, etaPos, etaNeg, doubleConfirmIrreversible, falseAdmitBound}. */
    public Map<String, Object> admission() { return WalletNoise.admissionPolicy(noise(), fatigue()); }

    /** Questions asked so far in this session. */
    public int questionsAsked() { return sessionQuestions; }

    private String newId() {
        StringBuilder s = new StringBuilder("q_");
        for (int i = 0; i < 10; i++) s.append(B64U.charAt((int) (Math.floor(o.rand.getAsDouble() * 64) % 64)));
        return pending.containsKey(s.toString()) ? newId() : s.toString();
    }

    /** {weight, meanHarm} of a box, or null when it covers too many cells. */
    private double[] boxStats(Map<String, Object> vs, int[][] box) {
        List<int[]> cells = WalletBox.boxCells(box);
        if (cells.size() > (o.maxBoxCells != null ? o.maxBoxCells : 4096)) return null;
        double m = 0, mh = 0;
        for (int[] idx : cells) {
            double[] s = WalletOmega.cellStats(vs, idx, harm());
            m += s[0];
            mh += s[0] * s[1];
        }
        return new double[] {mh, m > 0 ? mh / m : 0};
    }

    private String reversibilityOf(Map<String, Object> vs, int[][] box) { return o.reversibility != null ? o.reversibility.of(vs, box) : (String) vs.get("reversibility"); }

    private String frictionOf(Map<String, Object> vs, int[][] box, double meanHarm, String siteMin, boolean irreversible) {
        List<Object> provenance = new ArrayList<>();
        boolean widensIdentity = false;
        for (int k = 0; k < WalletOmega.dims(vs).size(); k++) {
            Map<String, Object> d = WalletOmega.dim(vs, k);
            String path = (String) d.get("path");
            if (path.startsWith("env.prov.") && "cat".equals(d.get("kind"))) {
                String param = path.substring("env.prov.".length());
                List<Object> levels = new ArrayList<>();
                for (int i : box[k]) {
                    Map<String, Object> v = WalletOmega.value(d, i);
                    String t = "prefix".equals(v.get("kind")) ? v.get("value") + "*" : (String) v.get("value");
                    for (String part : t.split("[|,]", -1)) levels.add(part);
                }
                Object sens = o.sensitivity == null ? null : o.sensitivity.get(param);
                provenance.add(Wallet.obj("path", param, "sensitivity", sens != null ? sens : "material", "levels", levels));
            }
            if ("cat".equals(d.get("kind")) && o.identityPaths.contains(path)) {
                for (int i : box[k]) if (!"exact".equals(WalletOmega.value(d, i).get("kind"))) widensIdentity = true;
            }
        }
        Map<String, Object> inp = Wallet.obj("reversibility", reversibilityOf(vs, box), "expectedHarm", meanHarm, "provenance", provenance, "widensCriticalIdentity", widensIdentity);
        if (siteMin != null && !siteMin.isEmpty()) inp.put("siteMin", siteMin);
        String tier = (String) Wallet.frictionFor(inp, o.frictionThresholds != null ? o.frictionThresholds : Wallet.defaultFrictionThresholds()).get("tier");
        if (irreversible && Boolean.TRUE.equals(admission().get("doubleConfirmIrreversible"))) tier = Wallet.maxFriction(tier, "typed");
        return tier;
    }

    /** The rendered card and its friction, or null when it cannot be rendered. */
    @SuppressWarnings("unchecked")
    private Map<String, Object> render(String kind, String verb, Map<String, Object> coords, String friction, Map<String, Object> action, Map<String, Object> vs, int[][] box, String reason) {
        Map<String, Object> base = new LinkedHashMap<>();
        base.put("omega", o.omega);
        base.put("verb", verb);
        base.put("coords", coords);
        base.put("site", Wallet.obj("origin", o.siteOrigin, "name", o.siteName));
        if (o.statementText != null) base.put("statementText", o.statementText);
        base.put("reversibility", reversibilityOf(vs, box));
        if (o.units != null) base.put("units", o.units);
        if (action != null) base.put("action", action);
        base.put("kind", kind);
        if (reason != null) base.put("reason", reason);
        Map<String, Object> in = new LinkedHashMap<>(base);
        in.put("friction", friction);
        Map<String, Object> r = WalletCard.renderCard(in);
        if (Boolean.TRUE.equals(r.get("ok")) && Wallet.frictionRank(friction) == Wallet.frictionRank("typed") && ((Map<String, Object>) r.get("card")).get("typed") == null) {
            in = new LinkedHashMap<>(base);
            in.put("friction", "device");
            r = WalletCard.renderCard(in);
        }
        return Boolean.TRUE.equals(r.get("ok")) ? (Map<String, Object>) r.get("card") : null;
    }

    private Map<String, Object> refusal(String code, String reason) { return Wallet.obj("ok", false, "code", code, "reason", reason); }

    /** null when the gate is open, else the refusal. */
    private Map<String, Object> gate() {
        if (Boolean.TRUE.equals(noise().get("frozen"))) return refusal("frozen", "the estimated false-yes rate is above η_stop: no more questions this session");
        if (sessionQuestions >= perSession()) return refusal("cap_session", "at most " + perSession() + " questions per session");
        double nowH = o.now.getAsDouble();
        if (!(Double.isFinite(nowH) && o.hourly.count(nowH) < perHour())) return refusal("cap_hour", "at most " + perHour() + " questions per hour");
        return null;
    }

    private void enqueue(Item it) {
        double flat = Double.POSITIVE_INFINITY;
        for (int[] idx : WalletBox.boxCells(it.box)) flat = Math.min(flat, WalletBox.flatIndex(it.vs, idx));
        it.flat = flat;
        pending.put(it.id, it);
    }

    private void count() {
        sessionQuestions++;
        if (!o.hourly.tryAdd(o.now.getAsDouble(), 9007199254740991.0)) throw new IllegalStateException("unreachable");
    }

    /** Insert a canary with probability rho (rendered and ordered like a real question). */
    private void maybeCanary() {
        Set<String> exclude = new HashSet<>(canaryUsed);
        for (Item p : pending.values()) for (int[] idx : WalletBox.boxCells(p.box)) exclude.add(WalletNoise.cellKey(p.verb, idx));
        boolean lowHarm = true;
        for (Item p : pending.values()) if (!(!"real".equals(p.kind) || Wallet.frictionRank(p.card.get("friction")) <= Wallet.frictionRank("hold"))) lowHarm = false;
        WalletNoise.CanaryContext ctx = new WalletNoise.CanaryContext();
        ctx.omega = o.omega;
        ctx.confirmed = o.view.confirmed();
        ctx.knownNo = (verb, idx) -> o.view.outsideCeiling(verb, idx) ? "ceiling" : o.view.vetoed(verb, idx) ? "veto" : null;
        ctx.knownYes = knownYes;
        ctx.exclude = exclude;
        ctx.rand = o.rand;
        ctx.rho = o.rho;
        ctx.lowHarmSession = lowHarm;
        ctx.canariesSoFar = canaries;
        Map<String, Object> c = WalletNoise.pickCanary(ctx);
        if (c == null) return;
        String verb = (String) c.get("verb");
        int[] cidx = WalletNoise.idxOf(c.get("idx"));
        Map<String, Object> vs = WalletOmega.verbSpace(o.omega, verb);
        int[][] box = new int[cidx.length][];
        for (int i = 0; i < cidx.length; i++) box[i] = new int[] {cidx[i]};
        double[] st = boxStats(vs, box);
        if (st == null) return;
        Map<String, Object> coords = WalletBox.coordsOfCell(vs, cidx);
        Map<String, Object> action = Wallet.obj("verb", verb, "values", WalletOmega.cellRep(vs, cidx).get("values"));
        String friction = frictionOf(vs, box, st[1], null, false);
        Map<String, Object> card = render("question", verb, coords, friction, action, vs, box, null);
        if (card == null) return;
        canaries++;
        canaryUsed.add(WalletNoise.cellKey(verb, cidx));
        Item it = new Item();
        it.id = newId();
        it.kind = "canary"; it.source = "elicitation"; it.verb = verb; it.box = box; it.coords = coords; it.card = card; it.action = action; it.irreversible = false;
        it.expected = (int) Wallet.nv(c.get("expected")); it.weight = st[0]; it.jit = false; it.vs = vs;
        enqueue(it);
    }

    /**
     * Receive a site-signed intent_required (delivered directly, or relayed unchanged by the agent) together with the action the
     * agent attempted ({verb, resource, params, reversibility_class}). Every check fails closed. Returns {ok:true, questionId,
     * friction} or {ok:false, code, reason}.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> receive(Map<String, Object> ir, Map<String, Object> action) {
        double now = o.now.getAsDouble();
        String bad = WalletBridge.verifyIntentRequired(ir, o.siteKeys, (Object) Double.valueOf(now));
        if (bad != null) return refusal("bad_site_signature", bad);
        if (!o.session.equals(ir.get("session"))) return refusal("wrong_session", "the question is for another session");
        if (!o.mapDigest.get().equals(ir.get("map_digest"))) return refusal("stale_map", "the question names another map version");
        Map<String, Object> irCell = (Map<String, Object>) ir.get("cell");
        String verb = (String) irCell.get("verb");
        if (!verb.equals(action.get("verb")) || !Wallet.pcaActionDigest(action).equals(ir.get("action_digest")))
            return refusal("action_mismatch", "the action does not match the signed action digest");
        Map<String, Object> lifted = o.lift != null ? o.lift.apply(action) : Wallet.actionValuesOf(action);
        Map<String, Object> coords = (Map<String, Object>) irCell.get("coords");
        WalletBox.BoxResult r = WalletBox.resolveCoords(o.omega, verb, coords);
        if (!r.ok) return refusal("cell_mismatch", r.reason);
        WalletBox.CellAtVs at = WalletBox.cellOfAction(o.omega, lifted);
        if (at == null || !WalletBox.cellInBox(r.box, at.idx)) return refusal("cell_mismatch", "the action's cell (re-derived by the wallet) is not the cell the site names");
        double[] st = boxStats(r.vs, r.box);
        if (st == null) return refusal("cell_too_large", "the question covers too many cells");
        List<int[]> cells = WalletBox.boxCells(r.box);
        String rvVerb = (String) r.vs.get("verb");
        for (int[] idx : cells) {
            if (o.view.outsideCeiling(rvVerb, idx)) return refusal("not_uncertain", "the cell is outside a ceiling: the principal cannot widen it");
            if (o.view.vetoed(rvVerb, idx)) return refusal("not_uncertain", "the cell was vetoed");
        }
        double pa = o.view.p(rvVerb, at.idx);
        if (!(pa > 0 && pa < 1)) return refusal("not_uncertain", pa <= 0 ? "the cell is denied" : "the cell is already in the grant");
        for (int[] idx : cells) if (asked.contains(WalletNoise.cellKey(rvVerb, idx))) return refusal("already_asked", "a cell is asked at most once per session");
        Map<String, Object> g = gate();
        if (g != null) {
            if ("frozen".equals(g.get("code"))) refusedWhileFrozen.add(Wallet.obj("verb", rvVerb, "coords", coords));
            return g;
        }
        boolean irreversible = "irreversible".equals(reversibilityOf(r.vs, r.box));
        String friction = frictionOf(r.vs, r.box, st[1], (String) ir.get("friction"), irreversible);
        Map<String, Object> card = render("question", verb, coords, friction, lifted, r.vs, r.box, null);
        if (card == null) return refusal("render_failed", "the card could not be rendered");
        String qid = (String) ir.get("question_id");
        if (pending.containsKey(qid)) return refusal("already_asked", "duplicate question id");
        for (int[] idx : cells) asked.add(WalletNoise.cellKey(rvVerb, idx));
        count();
        Item it = new Item();
        it.id = qid; it.kind = "real"; it.source = "elicitation"; it.verb = verb; it.box = r.box; it.coords = coords; it.card = card; it.action = lifted;
        it.actionDigest = (String) ir.get("action_digest"); it.irreversible = irreversible; it.weight = st[0]; it.expiresAt = Wallet.nv(ir.get("expires_at")); it.jit = true; it.vs = r.vs;
        enqueue(it);
        maybeCanary();
        return Wallet.obj("ok", true, "questionId", qid, "friction", card.get("friction"));
    }

    /**
     * An agent clarification: {candidates: [at most 8 structured actions], reason}, no text. Certain cells are answered at once
     * (dry run); among the uncertain ones the wallet picks the most informative and asks it. Returns {status, verdicts,
     * questionId?, refused?, error?}.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> clarify(Object body) {
        Map<String, Object> parsed = WalletClarify.parseClarifyRequest(body);
        if (!Boolean.TRUE.equals(parsed.get("ok"))) return Wallet.obj("status", JsVal.n(400), "verdicts", new ArrayList<Object>(), "error", parsed.get("error"));
        Map<String, Object> request = (Map<String, Object>) parsed.get("request");
        List<Map<String, Object>> cands = new ArrayList<>();
        for (Object c : (List<Object>) request.get("candidates")) cands.add((Map<String, Object>) c);
        Map<String, Object> st = noise();
        double etaPos = Math.min(0.5 - 1e-9, Wallet.nv(st.get("etaPosBar")));
        double etaNeg = Math.min(0.5 - 1e-9, Wallet.nv(st.get("etaNegBar")));
        WalletClarify.Plan plan = WalletClarify.planClarification(o.omega, o.view, cands, o.liftCandidate, asked, etaPos, etaNeg, harm());
        List<Object> verdicts = new ArrayList<Object>(plan.verdicts);
        if (plan.ask == null) return Wallet.obj("status", JsVal.n(200), "verdicts", verdicts);
        Map<String, Object> g = gate();
        if (g != null) return Wallet.obj("status", JsVal.n("frozen".equals(g.get("code")) ? 200 : 429), "verdicts", verdicts, "refused", g.get("code"));
        String verb = (String) plan.ask.get("verb");
        Map<String, Object> vs = WalletOmega.verbSpace(o.omega, verb);
        int[] aidx = plan.askIdx;
        int[][] box = new int[aidx.length][];
        for (int i = 0; i < aidx.length; i++) box[i] = new int[] {aidx[i]};
        double[] stats = boxStats(vs, box);
        Map<String, Object> coords = WalletBox.coordsOfCell(vs, aidx);
        Map<String, Object> raw = cands.get((int) Wallet.nv(plan.ask.get("index")));
        Map<String, Object> action = o.liftCandidate != null ? o.liftCandidate.apply(raw) : raw;
        boolean irreversible = "irreversible".equals(reversibilityOf(vs, box));
        String friction = frictionOf(vs, box, stats[1], null, irreversible);
        Map<String, Object> card = render("clarification", verb, coords, friction, action, vs, box, (String) request.get("reason"));
        if (card == null) return Wallet.obj("status", JsVal.n(200), "verdicts", verdicts, "refused", "render_failed");
        String id = newId();
        asked.add(WalletNoise.cellKey(verb, aidx));
        count();
        Item it = new Item();
        it.id = id; it.kind = "real"; it.source = "clarification"; it.verb = verb; it.box = box; it.coords = coords; it.card = card; it.action = action; it.irreversible = irreversible;
        it.weight = stats[0]; it.jit = false; it.vs = vs;
        enqueue(it);
        maybeCanary();
        return Wallet.obj("status", JsVal.n(200), "verdicts", verdicts, "questionId", id);
    }

    /** Pending items in display order: friction desc, E[h|c] mu(c) desc, cell index asc, id asc. */
    private List<Item> ordered() {
        List<Item> l = new ArrayList<>(pending.values());
        l.sort((a, b) -> {
            int f = Wallet.frictionRank(b.card.get("friction")) - Wallet.frictionRank(a.card.get("friction"));
            if (f != 0) return f;
            double w = b.weight - a.weight;
            if (w != 0 && !Double.isNaN(w)) return w > 0 ? 1 : -1;
            double fl = a.flat - b.flat;
            if (fl != 0 && !Double.isNaN(fl)) return fl > 0 ? 1 : -1;
            return a.id.compareTo(b.id) < 0 ? -1 : a.id.compareTo(b.id) > 0 ? 1 : 0;
        });
        return l;
    }

    /**
     * The next screen {screen, kind, questions:[{questionId, card}]} or null. A typed or device question is always alone; tap and
     * hold questions share up to maxPerScreen (default 3).
     */
    public Map<String, Object> nextScreen() {
        double now = o.now.getAsDouble();
        for (Map.Entry<String, Item> e : new ArrayList<>(pending.entrySet())) {
            Item it = e.getValue();
            if (it.expiresAt != null && !(Double.isFinite(now) && now <= it.expiresAt)) pending.remove(e.getKey());
        }
        List<Item> items = new ArrayList<>();
        for (Item it : ordered()) if (it.shownOn == null) items.add(it);
        if (items.isEmpty()) return null;
        int next = screenNo + 1;
        List<Item> eligible = new ArrayList<>();
        for (Item it : items) if (it.notBefore == null || next >= it.notBefore) eligible.add(it);
        screenNo = next;
        if (eligible.isEmpty()) return Wallet.obj("screen", JsVal.n(next), "kind", "interstitial", "questions", new ArrayList<Object>());
        Item first = eligible.get(0);
        List<Item> picked = new ArrayList<>();
        picked.add(first);
        if (Wallet.frictionRank(first.card.get("friction")) <= Wallet.frictionRank("hold")) {
            for (Item it : eligible.subList(1, eligible.size())) {
                if (picked.size() >= (o.maxPerScreen != null ? o.maxPerScreen : 3)) break;
                if (Wallet.frictionRank(it.card.get("friction")) <= Wallet.frictionRank("hold")) picked.add(it);
            }
        }
        List<Object> qs = new ArrayList<>();
        for (Item it : picked) {
            it.shownOn = next;
            qs.add(Wallet.obj("questionId", it.id, "card", it.card));
        }
        return Wallet.obj("screen", JsVal.n(next), "kind", "questions", "questions", qs);
    }

    private Map<String, Object> fail(String code, String reason) { return Wallet.obj("ok", false, "code", code, "reason", reason); }

    private Object cardTier(Item it) { return it.card.get("friction"); }

    /**
     * The principal's response to a shown question: {answer: "no"} | {answer: "yes", holdMs?, typed?, webauthn?} | {answer:
     * "partly", partial, ...}. Returns {ok:true, kind, answer(s)} or {ok:false, code, reason}.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> answer(String questionId, Map<String, Object> response) {
        Item it = pending.get(questionId);
        if (it == null) return fail("unknown_question", "no such pending question");
        if (it.shownOn == null) return fail("not_shown", "the question was never shown");
        double now = o.now.getAsDouble();
        if (it.expiresAt != null && !(Double.isFinite(now) && now <= it.expiresAt)) {
            pending.remove(questionId);
            return fail("expired", "the question expired");
        }
        int y;
        Map<String, Object> partial = null;
        Object ans = response.get("answer");
        if ("no".equals(ans)) y = 0;
        else if ("partly".equals(ans)) {
            String e = WalletCard.partialError(it.card, (Map<String, Object>) response.get("partial"));
            if (e != null) return fail("bad_response", e);
            y = 1;
            partial = (Map<String, Object>) response.get("partial");
        } else y = 1;
        Map<String, Object> ux = Wallet.obj("tier", cardTier(it), "rendered_digest", it.card.get("rendered_digest"), "canary", "canary".equals(it.kind));
        if (y == 1) {
            Map<String, Object> ev = tierEvidence(it, response, questionId);
            if (!Boolean.TRUE.equals(ev.get("ok"))) return ev;
            ux.putAll((Map<String, Object>) ev.get("ux"));
        }
        boolean plainYes = y == 1 && partial == null;
        if (!"canary".equals(it.kind) && it.jit && it.irreversible && plainYes && it.actionDigest != null && !it.actionDigest.isEmpty()
            && Wallet.frictionRank(cardTier(it)) >= Wallet.frictionRank("typed")) {
            ux.put("action_digest", it.actionDigest);
            ux.put("consent_for_action", true);
        }
        Map<String, Object> in = Wallet.obj("map_digest", o.mapDigest.get(), "session", o.session, "question_id", questionId, "verb", it.verb, "cell", it.coords, "y", JsVal.n(y));
        if (partial != null) in.put("partial", partial);
        in.put("source", it.source);
        in.put("observed_at", now);
        in.put("ux", ux);
        Map<String, Object> answer = Wallet.signIntentAnswer(in, o.principalSeed);
        pending.remove(questionId);
        if ("canary".equals(it.kind)) {
            o.onNoise.accept(WalletNoise.recordCanary(o.noise.get(), JsVal.n(it.expected), JsVal.n(y)));
            return Wallet.obj("ok", true, "kind", "canary", "answer", answer);
        }
        if (y == 0) return Wallet.obj("ok", true, "kind", "veto", "answer", answer);
        boolean singles = true;
        for (int[] ids : it.box) if (ids.length != 1) singles = false;
        if (plainYes && Wallet.frictionRank(cardTier(it)) >= Wallet.frictionRank("typed") && singles) {
            int[] idx = new int[it.box.length];
            for (int i = 0; i < idx.length; i++) idx[i] = it.box[i][0];
            knownYes.add(Wallet.obj("verb", it.verb, "idx", WalletNoise.idxList(idx)));
        }
        if (plainYes && it.irreversible && Boolean.TRUE.equals(admission().get("doubleConfirmIrreversible"))) {
            String key = it.verb + "|" + WalletDelivery.jsonStringify(it.coords);
            List<Map<String, Object>> recs = new ArrayList<>(confirmations.getOrDefault(key, new ArrayList<>()));
            recs.add(Wallet.obj("screen", JsVal.n(it.shownOn), "tier", cardTier(it)));
            confirmations.put(key, recs);
            if ("confirmation".equals(it.kind) && it.first != null && WalletNoise.doubleConfirmed(recs))
                return Wallet.obj("ok", true, "kind", "confirmed", "answers", new ArrayList<Object>(List.of(it.first, answer)));
            if ("confirmation".equals(it.kind)) return Wallet.obj("ok", true, "kind", "pending_confirmation", "answer", answer);
            Item second = it.copy();
            second.id = newId();
            second.kind = "confirmation";
            second.first = answer;
            second.notBefore = it.shownOn + 2;
            second.shownOn = null;
            pending.put(second.id, second);
            return Wallet.obj("ok", true, "kind", "pending_confirmation", "answer", answer);
        }
        return Wallet.obj("ok", true, "kind", "answer", "answer", answer);
    }

    private String challengeOf(Item it, String questionId) {
        String ad = it.jit && it.irreversible && it.actionDigest != null && !it.actionDigest.isEmpty() ? it.actionDigest : null;
        return Wallet.deviceChallenge(questionId, (String) it.card.get("rendered_digest"), 1, ad);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> tierEvidence(Item it, Map<String, Object> response, String questionId) {
        Map<String, Object> r = "no".equals(response.get("answer")) ? new LinkedHashMap<>() : response;
        Object tier = cardTier(it);
        if ("tap".equals(tier)) return Wallet.obj("ok", true, "ux", new LinkedHashMap<String, Object>());
        if ("hold".equals(tier)) {
            Object h = r.get("holdMs");
            if (!(JsVal.isNumber(h) && Wallet.nv(h) == Math.rint(Wallet.nv(h)) && !Double.isInfinite(Wallet.nv(h)) && Wallet.nv(h) >= Wallet.MIN_HOLD_MS))
                return fail("tier_evidence", "hold for at least " + Wallet.MIN_HOLD_MS + " ms");
            return Wallet.obj("ok", true, "ux", Wallet.obj("hold_ms", h));
        }
        if ("typed".equals(tier)) {
            Map<String, Object> t = (Map<String, Object>) it.card.get("typed");
            if (t == null || it.action == null || !(r.get("typed") instanceof String)) return fail("tier_evidence", "type the value shown on the card");
            String want = WalletCard.expectedTyped(it.card, it.action);
            String got = WalletCard.normalizeTyped((String) r.get("typed"), (String) t.get("mode"), o.units == null ? null : o.units.get(t.get("path")));
            if (want == null || got == null || !got.equals(want)) return fail("typed_mismatch", "the typed value does not match the card");
            return Wallet.obj("ok", true, "ux", Wallet.obj("typed_digest", Wallet.typedDigest(questionId, got)));
        }
        if ("device".equals(tier)) {
            Object waO = r.get("webauthn");
            DeviceTrust dev = o.device;
            if (!JsVal.truthy(waO) || dev == null) return fail("tier_evidence", "a security-key assertion is required");
            Map<String, Object> wa = (Map<String, Object>) waO;
            Object credId = wa.get("credential_id");
            Object pk = credId instanceof String ? dev.credentials.get(credId) : null;
            byte[] ad = Pca.decodeB64uStrict(wa.get("authenticator_data"), -1);
            byte[] cd = Pca.decodeB64uStrict(wa.get("client_data_json"), -1);
            byte[] sg = Pca.decodeB64uStrict(wa.get("signature"), -1);
            if (pk == null || ad == null || cd == null || sg == null) return fail("tier_evidence", "unknown credential or malformed assertion");
            String challenge = challengeOf(it, questionId);
            Map<String, Object> assertion = Wallet.obj("authenticatorData", ad, "clientDataJSON", cd, "signature", sg, "publicKey", pk);
            Object stored = dev.signCounts == null ? null : dev.signCounts.get(credId);
            Map<String, Object> expect = Wallet.obj("expectedChallenge", challenge, "rpId", dev.rpId, "origins", dev.origins, "requireUV", true,
                "storedSignCount", stored != null ? stored : JsVal.n(0));
            Map<String, Object> res = Webauthn.verifyAssertion(assertion, expect);
            if (!Boolean.TRUE.equals(res.get("ok"))) return fail("tier_evidence", "security key: " + res.get("reason"));
            if (dev.signCounts != null) dev.signCounts.put((String) credId, res.get("signCount"));
            return Wallet.obj("ok", true, "ux", Wallet.obj("webauthn", new LinkedHashMap<>(wa)));
        }
        throw new IllegalStateException("unreachable friction tier");
    }

    /** The WebAuthn challenge the wallet UI passes to the credential API for a shown device-tier question, or null. */
    public String deviceChallengeFor(String questionId) {
        Item it = pending.get(questionId);
        if (it == null || it.shownOn == null || !"device".equals(cardTier(it))) return null;
        return challengeOf(it, questionId);
    }

    /** The end-of-session summary {frozen, refused:[{verb, coords}], asked, canaries}. */
    public Map<String, Object> summary() {
        return Wallet.obj("frozen", noise().get("frozen"), "refused", new ArrayList<Object>(refusedWhileFrozen), "asked", JsVal.n(sessionQuestions), "canaries", JsVal.n(canaries));
    }

    /** A stable digest of the channel's pending state (for tests and audit logs). */
    public String stateDigest() {
        List<Object> p = new ArrayList<>();
        for (Item i : ordered()) p.add(Wallet.obj("id", i.id, "k", i.kind, "d", i.card.get("rendered_digest")));
        List<String> a = new ArrayList<>(asked);
        Collections.sort(a);
        return Pca.hashCanonical(Wallet.obj("d", "atlas-pca/wallet-channel-state/v1", "p", p, "a", new ArrayList<Object>(a), "n", JsVal.n(sessionQuestions)));
    }
}
