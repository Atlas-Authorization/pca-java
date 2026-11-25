package net.atlasauth.pca;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import net.atlasauth.pca.oauth.JsVal;
import net.atlasauth.pca.wallet.Wallet;
import net.atlasauth.pca.wallet.WalletBox;
import net.atlasauth.pca.wallet.WalletCard;
import net.atlasauth.pca.wallet.WalletClarify;
import net.atlasauth.pca.wallet.WalletNoise;
import net.atlasauth.pca.wallet.WalletOmega;
import net.atlasauth.pca.wallet.WalletPricing;
import net.atlasauth.pca.wallet.WalletStats;
import net.atlasauth.pca.wallet.TrustedChannel;
import net.atlasauth.pca.wallet.WalletDelivery;
import net.atlasauth.pca.wallet.WalletHandlers;
import net.atlasauth.pca.wallet.WalletPopulation;
import net.atlasauth.pca.wallet.WalletView;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle for the wallet package (see the oracle header for the case shapes and the placeholders). */
class WalletDiffTest {
    static final String MODULE = "ref-wallet";

    // ---- helpers ------------------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked") static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") static List<Object> l(Object o) { return (List<Object>) o; }
    static double d(Object o) { Double x = JsVal.num(o); return x == null ? Double.NaN : x; }
    static long n(Object o) { return (long) d(o); }
    static int[] ints(Object o) { return WalletNoise.idxOf(o); }
    static String s(Object o) { return (String) o; }
    static Map<String, Object> obj(Object... kv) { Map<String, Object> r = new LinkedHashMap<>(); for (int i = 0; i < kv.length; i += 2) r.put((String) kv[i], kv[i + 1]); return r; }

    private static Map<String, Object> omegas;

    static synchronized Map<String, Object> omegas() throws Exception {
        if (omegas == null) omegas = m(OracleCases.of(MODULE, "omegas").get(0).get("out"));
        return omegas;
    }

    static byte[] seed(String label) {
        try { return MessageDigest.getInstance("SHA-256").digest(("atlas-pca-conformance/" + label).getBytes(StandardCharsets.UTF_8)); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }

    /** Replace the {"$omega": id} and {"$seed": label} placeholders of an argument tree. */
    static Object sub(Object x) throws Exception {
        if (x instanceof Map) {
            Map<String, Object> mm = m(x);
            if (mm.size() == 1 && mm.containsKey("$omega")) return omegas().get(mm.get("$omega"));
            if (mm.size() == 1 && mm.containsKey("$seed")) return seed((String) mm.get("$seed"));
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : mm.entrySet()) out.put(e.getKey(), sub(e.getValue()));
            return out;
        }
        if (x instanceof List) { List<Object> out = new ArrayList<>(); for (Object y : (List<?>) x) out.add(sub(y)); return out; }
        return x;
    }

    interface Fn { Object apply(List<Object> a) throws Exception; }

    static void each(String fn, Fn f) throws Exception { OracleCases.each(MODULE, fn, a -> f.apply(l(sub(a)))); }

    /** As {@link #each}, but a finite numeric result may differ in the last digits (the platform's log/exp/pow versus V8's): relative 1e-12. */
    static void eachNear(String fn, Fn f) throws Exception {
        List<String> bad = new ArrayList<>();
        for (Map<String, Object> c : OracleCases.of(MODULE, fn)) {
            Double want = OracleCases.num(c.get("out"));
            Object got = null;
            try { got = f.apply(l(sub(c.get("args")))); } catch (Throwable t) { /* diff reports it */ }
            if (want != null && got instanceof Double && !((Double) got).isNaN() && !want.isNaN()) {
                double g = (Double) got;
                if (g == want || Math.abs(g - want) <= 1e-12 * Math.max(1, Math.abs(want))) continue;
            }
            String d = OracleCases.diff(c, c.get("out"), a -> f.apply(l(sub(a))));
            if (d != null) bad.add(d);
        }
        org.junit.jupiter.api.Assertions.assertTrue(bad.isEmpty(), bad.size() + " divergent case(s) of " + fn + ":\n" + String.join("\n", bad));
    }

    static Map<String, Object> vs(Object id, Object verb) throws Exception { return WalletOmega.verbSpace(m(omegas().get(id)), verb); }

    // ---- friction and the wire ----------------------------------------------------------------------------------------------

    @Test void isFrictionTier() throws Exception { each("isFrictionTier", a -> Wallet.isFrictionTier(a.get(0))); }
    @Test void frictionRank() throws Exception { each("frictionRank", a -> (long) Wallet.frictionRank(a.get(0))); }
    @Test void isProvenanceLevel() throws Exception { each("isProvenanceLevel", a -> Wallet.isProvenanceLevel(a.get(0))); }
    @Test void worstProvenance() throws Exception { each("worstProvenance", a -> Wallet.worstProvenance(a.get(0))); }
    @Test void satisfiesTier() throws Exception { each("satisfiesTier", a -> Wallet.satisfiesTier(a.get(0), a.get(1))); }
    @Test void maxFriction() throws Exception { each("maxFriction", a -> Wallet.maxFriction(a)); }
    @Test void frictionFor() throws Exception { each("frictionFor", a -> a.size() > 1 ? Wallet.frictionFor(m(a.get(0)), m(a.get(1))) : Wallet.frictionFor(m(a.get(0)))); }
    @Test void pcaActionDigest() throws Exception { each("pcaActionDigest", a -> Wallet.pcaActionDigest(m(a.get(0)))); }
    @Test void actionValuesOf() throws Exception { each("actionValuesOf", a -> Wallet.actionValuesOf(m(a.get(0)))); }
    @Test void isB64u32() throws Exception { each("isB64u32", a -> Wallet.isB64u32(a.get(0))); }
    @Test void isObj() throws Exception { each("isObj", a -> Wallet.isObj(a.get(0))); }
    @Test void coordsError() throws Exception { each("coordsError", a -> Wallet.coordsError(a.get(0))); }
    @Test void answerShapeError() throws Exception { each("answerShapeError", a -> Wallet.answerShapeError(a.get(0))); }
    @Test void signIntentAnswer() throws Exception { each("signIntentAnswer", a -> Wallet.signIntentAnswer(m(a.get(0)), (byte[]) a.get(1))); }

    @Test void verifyIntentAnswer() throws Exception {
        each("verifyIntentAnswer", a -> {
            Map<String, Object> r = Wallet.verifyIntentAnswer(a.get(0), a.size() > 1 ? l(a.get(1)) : null);
            if (Boolean.FALSE.equals(r.get("ok")) && ((String) r.get("reason")).startsWith("malformed answer:")) return obj("ok", false, "reason", "malformed answer");
            return r;
        });
    }

    @Test void answerRef() throws Exception { each("answerRef", a -> Wallet.answerRef(a.get(0))); }
    @Test void typedDigest() throws Exception { each("typedDigest", a -> Wallet.typedDigest(s(a.get(0)), s(a.get(1)))); }

    @Test void deviceChallenge() throws Exception {
        each("deviceChallenge", a -> { Map<String, Object> x = m(a.get(0)); return Wallet.deviceChallenge(s(x.get("questionId")), s(x.get("renderedDigest")), n(x.get("y")), s(x.get("actionDigest"))); });
    }

    // ---- numerics ---------------------------------------------------------------------------------------------------------------

    @Test void lnGamma() throws Exception { eachNear("lnGamma", a -> WalletStats.lnGamma(d(a.get(0)))); }
    @Test void betacf() throws Exception { each("betacf", a -> WalletStats.betacf(d(a.get(0)), d(a.get(1)), d(a.get(2)))); }
    @Test void betaInc() throws Exception { each("betaInc", a -> WalletStats.betaInc(d(a.get(0)), d(a.get(1)), d(a.get(2)))); }
    @Test void betaQuantile() throws Exception { eachNear("betaQuantile", a -> WalletStats.betaQuantile(d(a.get(0)), d(a.get(1)), d(a.get(2)))); }
    @Test void clopperPearsonUpper() throws Exception { each("clopperPearsonUpper", a -> WalletStats.clopperPearsonUpper(d(a.get(0)), d(a.get(1)), d(a.get(2)))); }
    @Test void binEnt() throws Exception { each("binEnt", a -> WalletStats.binEnt(d(a.get(0)))); }

    // ---- canaries and fatigue ------------------------------------------------------------------------------------------------------

    @Test void recordCanary() throws Exception { each("recordCanary", a -> WalletNoise.recordCanary(m(a.get(0)), a.get(1), a.get(2))); }
    @Test void estimateNoise() throws Exception { each("estimateNoise", a -> a.size() > 1 ? WalletNoise.estimateNoise(m(a.get(0)), d(a.get(1))) : WalletNoise.estimateNoise(m(a.get(0)))); }
    @Test void cellKey() throws Exception { each("cellKey", a -> WalletNoise.cellKey(s(a.get(0)), ints(a.get(1)))); }

    @Test void boundaryNeighbours() throws Exception {
        each("boundaryNeighbours", a -> {
            List<Map<String, Object>> conf = new ArrayList<>();
            for (Object c : l(a.get(1))) conf.add(m(c));
            return new ArrayList<Object>(WalletNoise.boundaryNeighbours(m(a.get(0)), conf));
        });
    }

    @Test void pickCanary() throws Exception {
        each("pickCanary", a -> {
            Map<String, Object> x = m(a.get(0));
            WalletNoise.CanaryContext c = new WalletNoise.CanaryContext();
            c.omega = m(x.get("omega"));
            for (Object o : l(x.get("confirmed"))) c.confirmed.add(m(o));
            Map<String, Object> kn = m(x.get("knownNo"));
            c.knownNo = (verb, idx) -> (String) kn.get(WalletNoise.cellKey(verb, idx));
            for (Object o : l(x.get("knownYes"))) c.knownYes.add(m(o));
            Set<String> ex = new HashSet<>();
            for (Object o : l(x.get("exclude"))) ex.add(s(o));
            c.exclude = ex;
            List<Object> rands = l(x.get("rands"));
            int[] i = {0};
            c.rand = () -> { if (i[0] >= rands.size()) throw new IllegalStateException("rand exhausted"); return d(rands.get(i[0]++)); };
            if (x.containsKey("rho")) c.rho = d(x.get("rho"));
            c.lowHarmSession = Boolean.TRUE.equals(x.get("lowHarmSession"));
            c.canariesSoFar = d(x.get("canariesSoFar"));
            return WalletNoise.pickCanary(c);
        });
    }

    @Test void etaUnderLoad() throws Exception { each("etaUnderLoad", a -> WalletNoise.etaUnderLoad(d(a.get(0)), d(a.get(1)), d(a.get(2)))); }
    @Test void noiseState() throws Exception { each("noiseState", a -> a.size() > 2 ? WalletNoise.noiseState(m(a.get(0)), d(a.get(1)), m(a.get(2))) : WalletNoise.noiseState(m(a.get(0)), d(a.get(1)))); }
    @Test void admissionPolicy() throws Exception { each("admissionPolicy", a -> a.size() > 1 ? WalletNoise.admissionPolicy(m(a.get(0)), m(a.get(1))) : WalletNoise.admissionPolicy(m(a.get(0)))); }

    @Test void doubleConfirmed() throws Exception {
        each("doubleConfirmed", a -> { List<Map<String, Object>> r = new ArrayList<>(); for (Object o : l(a.get(0))) r.add(m(o)); return WalletNoise.doubleConfirmed(r); });
    }

    @Test void slidingWindow() throws Exception {
        each("slidingWindow", a -> {
            WalletNoise.SlidingWindowCounter c = a.get(0) == null ? new WalletNoise.SlidingWindowCounter() : new WalletNoise.SlidingWindowCounter(d(a.get(0)));
            List<Object> out = new ArrayList<>();
            for (Object opO : l(a.get(1))) {
                List<Object> op = l(opO);
                try { out.add(obj("v", "count".equals(op.get(0)) ? (Object) (long) c.count(d(op.get(1))) : (Object) c.tryAdd(d(op.get(1)), d(op.get(2))))); }
                catch (RuntimeException e) { out.add(obj("err", true)); }
            }
            return out;
        });
    }

    // ---- risk-priced escalation -------------------------------------------------------------------------------------------------------

    @Test void signPricingConfig() throws Exception { each("signPricingConfig", a -> WalletPricing.signPricingConfig(m(a.get(0)), (byte[]) a.get(1))); }
    @Test void pricingConfigError() throws Exception { each("pricingConfigError", a -> WalletPricing.pricingConfigError(a.get(0))); }
    @Test void freshCalibration() throws Exception { each("freshCalibration", a -> WalletPricing.freshCalibration()); }
    @Test void decideEscalation() throws Exception { each("decideEscalation", a -> WalletPricing.decideEscalation(m(a.get(0)), a.get(1), a.get(2))); }
    @Test void signAnswer() throws Exception { each("signAnswer", a -> WalletPricing.signAnswer(m(a.get(0)), (byte[]) a.get(1))); }
    @Test void updateCalibration() throws Exception { each("updateCalibration", a -> WalletPricing.updateCalibration(m(a.get(0)), m(a.get(1)), l(a.get(2)), m(a.get(3)))); }
    @Test void signAutonomyRaise() throws Exception { each("signAutonomyRaise", a -> WalletPricing.signAutonomyRaise(m(a.get(0)), (byte[]) a.get(1))); }
    @Test void applyAutonomyRaise() throws Exception { each("applyAutonomyRaise", a -> WalletPricing.applyAutonomyRaise(m(a.get(0)), m(a.get(1)), (byte[]) a.get(2))); }

    // ---- the outcome space (private port) ----------------------------------------------------------------------------------------------

    @Test void omegaVerbCellCount() throws Exception { OracleCases.each(MODULE, "omega.verbCellCount", a -> WalletOmega.verbCellCount(vs(a.get(0), a.get(1)))); }

    @Test void omegaCellCount() throws Exception {
        OracleCases.each(MODULE, "omega.cellCount", a -> (long) WalletOmega.cellCount(WalletOmega.dim(vs(a.get(0), a.get(1)), (int) n(a.get(2)))));
    }

    @Test void omegaNumCells() throws Exception {
        OracleCases.each(MODULE, "omega.numCells", a -> {
            List<Object> out = new ArrayList<>();
            for (double[] c : WalletOmega.numCells(WalletOmega.dim(vs(a.get(0), a.get(1)), (int) n(a.get(2))))) out.add(obj("lo", c[0], "hi", c[1]));
            return out;
        });
    }

    @Test void omegaLabelOf() throws Exception { OracleCases.each(MODULE, "omega.labelOf", a -> WalletOmega.labelOf(s(a.get(0)))); }

    @Test void omegaDecodeCell() throws Exception {
        OracleCases.each(MODULE, "omega.decodeCell", a -> WalletNoise.idxList(WalletOmega.decodeCell(vs(a.get(0), a.get(1)), d(a.get(2)))));
    }

    @Test void omegaCellStats() throws Exception {
        OracleCases.each(MODULE, "omega.cellStats", a -> {
            double[] r = WalletOmega.cellStats(vs(a.get(0), a.get(1)), ints(a.get(2)), WalletOmega.DEFAULT_HARM);
            return obj("mass", r[0], "harm", r[1]);
        });
    }

    @Test void omegaCellRep() throws Exception { OracleCases.each(MODULE, "omega.cellRep", a -> WalletOmega.cellRep(vs(a.get(0), a.get(1)), ints(a.get(2)))); }

    @Test void omegaCellOf() throws Exception {
        OracleCases.each(MODULE, "omega.cellOf", a -> { int[] r = WalletOmega.cellOf(vs(a.get(0), a.get(1)), m(a.get(2))); return r == null ? null : WalletNoise.idxList(r); });
    }

    // ---- cell coordinates -------------------------------------------------------------------------------------------------------------

    @Test void coordKeyOf() throws Exception { each("coordKeyOf", a -> WalletBox.coordKeyOf(s(a.get(0)))); }
    @Test void resolveCoords() throws Exception { each("resolveCoords", a -> WalletBox.resolveCoords(m(a.get(0)), s(a.get(1)), m(a.get(2))).toMap()); }
    @Test void coordsOfBox() throws Exception { each("coordsOfBox", a -> WalletBox.coordsOfBox(vs(a.get(0), a.get(1)), WalletBox.boxOf(a.get(2)))); }
    @Test void coordsOfCell() throws Exception { each("coordsOfCell", a -> WalletBox.coordsOfCell(vs(a.get(0), a.get(1)), ints(a.get(2)))); }
    @Test void cellInBox() throws Exception { each("cellInBox", a -> WalletBox.cellInBox(WalletBox.boxOf(a.get(0)), ints(a.get(1)))); }

    @Test void boxCells() throws Exception {
        each("boxCells", a -> { List<Object> out = new ArrayList<>(); for (int[] c : WalletBox.boxCells(WalletBox.boxOf(a.get(0)))) out.add(WalletNoise.idxList(c)); return out; });
    }

    @Test void boxSize() throws Exception { each("boxSize", a -> WalletBox.boxSize(WalletBox.boxOf(a.get(0)))); }

    @Test void cellOfAction() throws Exception {
        OracleCases.each(MODULE, "cellOfAction", a -> { WalletBox.CellAtVs r = WalletBox.cellOfAction(m(omegas().get(a.get(0))), m(a.get(1))); return r == null ? null : r.toMap(); });
    }

    @Test void flatIndex() throws Exception { OracleCases.each(MODULE, "flatIndex", a -> WalletBox.flatIndex(vs(a.get(0), a.get(1)), ints(a.get(2)))); }

    // ---- the card ----------------------------------------------------------------------------------------------------------------------

    @Test void cleanText() throws Exception { each("cleanText", a -> WalletCard.cleanText(s(a.get(0)), (int) n(a.get(1)))); }
    @Test void last4() throws Exception { each("last4", a -> WalletCard.last4(s(a.get(0)))); }
    @Test void formatNumber() throws Exception { each("formatNumber", a -> WalletCard.formatNumber(d(a.get(0)), a.size() > 1 ? a.get(1) : null)); }

    @Test void renderCard() throws Exception {
        OracleCases.each(MODULE, "renderCard", a -> {
            Map<String, Object> in = new LinkedHashMap<>(m(sub(a.get(0))));
            Object id = in.remove("omegaId");
            in.put("omega", omegas().get(id));
            return WalletCard.renderCard(in);
        });
    }

    @Test void cardDigest() throws Exception { each("cardDigest", a -> WalletCard.cardDigest(m(a.get(0)))); }
    @Test void cardDigestMatches() throws Exception { each("cardDigestMatches", a -> WalletCard.cardDigestMatches(m(a.get(0)))); }
    @Test void cardText() throws Exception { each("cardText", a -> WalletCard.cardText(m(a.get(0)))); }
    @Test void partialError() throws Exception { each("partialError", a -> WalletCard.partialError(m(a.get(0)), m(a.get(1)))); }
    @Test void normalizeTyped() throws Exception { each("normalizeTyped", a -> WalletCard.normalizeTyped(s(a.get(0)), s(a.get(1)), a.size() > 2 ? a.get(2) : null)); }
    @Test void expectedTyped() throws Exception { each("expectedTyped", a -> WalletCard.expectedTyped(m(a.get(0)), m(a.get(1)))); }

    // ---- clarification --------------------------------------------------------------------------------------------------------------------

    @Test void parseClarifyRequest() throws Exception { each("parseClarifyRequest", a -> WalletClarify.parseClarifyRequest(a.get(0))); }
    @Test void informationGain() throws Exception { each("informationGain", a -> WalletClarify.informationGain(d(a.get(0)), d(a.get(1)), d(a.get(2)))); }

    /** A grant view over the case's table: p by cell key (default 0), vetoed and ceiling key lists. */
    static WalletView tableView(Map<String, Object> v) {
        Map<String, Object> p = m(v.get("p"));
        List<Object> vetoed = l(v.get("vetoed")), ceiling = l(v.get("ceiling"));
        return new WalletView() {
            @Override public double p(String verb, int[] idx) { Object x = p.get(WalletNoise.cellKey(verb, idx)); return x == null ? 0 : d(x); }
            @Override public boolean vetoed(String verb, int[] idx) { return vetoed.contains(WalletNoise.cellKey(verb, idx)); }
            @Override public boolean outsideCeiling(String verb, int[] idx) { return ceiling.contains(WalletNoise.cellKey(verb, idx)); }
            @Override public List<Map<String, Object>> confirmed() {
                List<Map<String, Object>> out = new ArrayList<>();
                if (v.get("confirmed") != null) for (Object c : l(v.get("confirmed"))) out.add(m(c));
                return out;
            }
        };
    }

    @Test void planClarification() throws Exception {
        each("planClarification", a -> {
            Map<String, Object> x = m(a.get(0));
            List<Map<String, Object>> cands = new ArrayList<>();
            for (Object c : l(x.get("candidates"))) cands.add(m(c));
            Set<String> asked = new HashSet<>();
            for (Object k : l(x.get("asked"))) asked.add(s(k));
            return WalletClarify.planClarification(m(x.get("omega")), tableView(m(x.get("view"))), cands, null, asked, d(x.get("etaPos")), d(x.get("etaNeg")), WalletOmega.DEFAULT_HARM).toMap();
        });
    }

    // ---- constants ---------------------------------------------------------------------------------------------------------------------

    @Test void constants() throws Exception {
        each("constants", a -> obj("FRICTION_ORDER", new ArrayList<Object>(Wallet.FRICTION_ORDER), "INTENT_ANSWER_SIG_DOMAIN", Wallet.INTENT_ANSWER_SIG_DOMAIN, "INTENT_ANSWER_REF_DOMAIN", Wallet.INTENT_ANSWER_REF_DOMAIN,
            "INTENT_TYPED_DOMAIN", Wallet.INTENT_TYPED_DOMAIN, "INTENT_DEVICE_CHALLENGE_DOMAIN", Wallet.INTENT_DEVICE_CHALLENGE_DOMAIN, "MIN_HOLD_MS", Wallet.MIN_HOLD_MS,
            "PROVENANCE_ORDER", new ArrayList<Object>(Wallet.PROVENANCE_ORDER), "DEFAULT_FRICTION_THRESHOLDS", Wallet.defaultFrictionThresholds(), "CARD_DOMAIN", WalletCard.CARD_DOMAIN,
            "CLARIFY_REASONS", new ArrayList<Object>(WalletCard.CLARIFY_REASONS), "REASON_LABELS", new LinkedHashMap<String, Object>(WalletCard.REASON_LABELS), "MAX_CANDIDATES", (long) WalletClarify.MAX_CANDIDATES,
            "EMPTY_NOISE", WalletNoise.emptyNoise(), "NOISE_PRIOR", obj("a", WalletNoise.PRIOR_A, "b", WalletNoise.PRIOR_B), "DEFAULT_FATIGUE", WalletNoise.defaultFatigue(), "PPM", WalletPricing.PPM,
            "MAX_MULTIPLIER_PPM", WalletPricing.MAX_MULTIPLIER_PPM, "POPULATION_VOTE_DOMAIN", WalletPopulation.POPULATION_VOTE_DOMAIN, "BETA_MAX", WalletPopulation.BETA_MAX));
    }

    // ---- population priors ------------------------------------------------------------------------------------------------------------------

    static java.util.function.DoubleSupplier seq(List<Object> xs) {
        int[] i = {0};
        return () -> { if (i[0] >= xs.size()) throw new IllegalStateException("rand exhausted"); return d(xs.get(i[0]++)); };
    }

    @Test void gaussianSigma() throws Exception { each("gaussianSigma", a -> WalletPopulation.gaussianSigma(d(a.get(0)), d(a.get(1)), d(a.get(2)))); }
    @Test void gaussian() throws Exception { each("gaussian", a -> WalletPopulation.gaussian(seq(l(a.get(0))))); }
    @Test void rrKeepProbability() throws Exception { each("rrKeepProbability", a -> WalletPopulation.rrKeepProbability(d(a.get(0)))); }
    @Test void randomizedResponse() throws Exception { each("randomizedResponse", a -> WalletPopulation.randomizedResponse(n(a.get(0)), d(a.get(1)), () -> d(a.get(2)))); }
    @Test void debiasRandomizedResponse() throws Exception { each("debiasRandomizedResponse", a -> WalletPopulation.debiasRandomizedResponse(d(a.get(0)), d(a.get(1)), d(a.get(2)))); }

    @Test void populationCellKey() throws Exception {
        OracleCases.each(MODULE, "populationCellKey", a -> WalletPopulation.populationCellKey(s(a.get(0)), vs(a.get(1), a.get(2)), ints(a.get(3))));
    }

    @Test void aggregate() throws Exception {
        each("aggregate", a -> {
            Map<String, Object> opts = m(a.get(2));
            WalletPopulation.Aggregator agg = new WalletPopulation.Aggregator(s(a.get(0)), d(a.get(1)), opts.containsKey("maxCellsPerPrincipal") ? d(opts.get("maxCellsPerPrincipal")) : null, seq(l(a.get(5))));
            List<Object> votes = new ArrayList<>();
            for (Object v : l(a.get(3))) votes.add(agg.contribute(m(v)));
            Map<String, Object> rel = m(a.get(4));
            Object release;
            try {
                release = agg.release(d(rel.get("epsilon")), d(rel.get("delta")), rel.containsKey("qMin") ? d(rel.get("qMin")) : null, rel.containsKey("minCount") ? d(rel.get("minCount")) : null);
            } catch (RuntimeException e) { release = obj("err", true); }
            return obj("votes", votes, "release", release);
        });
    }

    @Test void populationPrior() throws Exception {
        each("populationPrior", a -> {
            WalletPopulation.PriorMix pm = WalletPopulation.populationPrior(m(a.get(0)), d(a.get(1)));
            Set<Integer> in = new HashSet<>();
            for (Object c : l(a.get(4))) in.add((int) n(c));
            return obj("beta", pm.beta, "weight", pm.weight(vs(a.get(2), a.get(3)), in::contains));
        });
    }

    // ---- delivery ------------------------------------------------------------------------------------------------------------------------------

    @Test void siteQuestionNotice() throws Exception {
        each("siteQuestionNotice", a -> WalletDelivery.siteQuestionNotice(m(a.get(0)), a.get(1), a.get(2), a.get(3), a.size() > 4 ? a.get(4) : null));
    }

    @Test void clarificationNotice() throws Exception { each("clarificationNotice", a -> WalletDelivery.clarificationNotice(a.get(0), a.get(1), a.size() > 2 ? a.get(2) : null)); }
    @Test void questionText() throws Exception { each("questionText", a -> WalletDelivery.questionText(m(a.get(0)), s(a.get(1)))); }

    @Test void webhookChannel() throws Exception {
        each("webhookChannel", a -> {
            Map<String, Object> cfg = m(a.get(0));
            List<Object> script = l(a.get(1));
            List<Object> calls = new ArrayList<>();
            int[] i = {0};
            WalletDelivery.Transport tr = (url, headers, body) -> {
                calls.add(obj("url", url, "method", "POST", "headers", new LinkedHashMap<String, Object>(headers), "body", body));
                Map<String, Object> step = i[0] < script.size() ? m(script.get(i[0]++)) : obj("ok", true, "status", 200L);
                if (step.get("throw") != null) throw new RuntimeException((String) step.get("throw"));
                return new WalletDelivery.TransportResult(Boolean.TRUE.equals(step.get("ok")), (int) n(step.get("status")));
            };
            Map<String, String> headers = null;
            if (cfg.get("headers") != null) { headers = new LinkedHashMap<>(); for (Map.Entry<String, Object> e : m(cfg.get("headers")).entrySet()) headers.put(e.getKey(), s(e.getValue())); }
            WalletDelivery.QuestionChannel ch = WalletDelivery.questionWebhookChannel((String) cfg.get("url"), headers, tr);
            List<Object> deliveries = new ArrayList<>();
            for (Object nn : l(a.get(2))) deliveries.add(ch.notify(m(nn)));
            return obj("kind", ch.kind(), "enabled", ch.enabled(), "deliveries", deliveries, "calls", calls);
        });
    }

    @Test void textChannel() throws Exception {
        each("textChannel", a -> {
            List<Object> script = a.get(2) == null ? null : l(a.get(2));
            List<Object> sent = new ArrayList<>();
            int[] i = {0};
            WalletDelivery.TextSender send = script == null ? null : body -> {
                sent.add(body);
                Object st = i[0] < script.size() ? script.get(i[0]) : null;
                i[0]++;
                if (st instanceof Map && m(st).get("throw") != null) throw new RuntimeException((String) m(st).get("throw"));
            };
            WalletDelivery.QuestionChannel ch = WalletDelivery.questionTextChannel(s(a.get(0)), send, s(a.get(1)));
            List<Object> deliveries = new ArrayList<>();
            for (Object nn : l(a.get(3))) deliveries.add(ch.notify(m(nn)));
            return obj("kind", ch.kind(), "enabled", ch.enabled(), "deliveries", deliveries, "sent", sent);
        });
    }

    @Test void dispatcher() throws Exception {
        each("dispatcher", a -> {
            List<WalletDelivery.QuestionChannel> chans = new ArrayList<>();
            for (Object cO : l(a.get(0))) {
                Map<String, Object> c = m(cO);
                if ("webhook".equals(c.get("type"))) chans.add(WalletDelivery.questionWebhookChannel((String) c.get("url"), null, (url, h, body) -> new WalletDelivery.TransportResult(true, 200)));
                else chans.add(WalletDelivery.questionTextChannel(s(c.get("type")), Boolean.TRUE.equals(c.get("enabled")) ? body -> { } : null, "S"));
            }
            return obj("n", (long) chans.size(), "deliveries", new ArrayList<Object>(WalletDelivery.notifyAll(chans, m(a.get(1)))));
        });
    }

    // ---- the question channel (scenarios) ---------------------------------------------------------------------------------------------------------

    @Test void channel() throws Exception { each("channel", a -> runScenario(m(a.get(0)))); }

    static Map<String, Object> runScenario(Map<String, Object> spec) {
        WalletNoise.SlidingWindowCounter hourly = spec.get("windowMs") != null ? new WalletNoise.SlidingWindowCounter(d(spec.get("windowMs"))) : new WalletNoise.SlidingWindowCounter();
        for (Object ts : l(spec.get("hourlyPre"))) hourly.tryAdd(d(ts), 9007199254740991.0);
        double[] t = {d(spec.get("t0"))};
        Map<String, Object>[] counts = new Map[] {m(spec.get("noise"))};
        TrustedChannel.Options o = new TrustedChannel.Options();
        o.omega = m(spec.get("omega"));
        o.session = s(spec.get("session"));
        String mapDigest = s(spec.get("mapDigest"));
        o.mapDigest = () -> mapDigest;
        o.principalSeed = seed(s(spec.get("principal")));
        Map<String, Object> site = m(spec.get("site"));
        o.siteOrigin = s(site.get("origin"));
        o.siteName = s(site.get("name"));
        o.siteKeys = l(site.get("keys"));
        if (spec.containsKey("statementText")) o.statementText = s(spec.get("statementText"));
        if (spec.get("units") != null) o.units = m(spec.get("units"));
        if (spec.get("sensitivity") != null) o.sensitivity = m(spec.get("sensitivity"));
        if (spec.get("identityPaths") != null) for (Object p : l(spec.get("identityPaths"))) o.identityPaths.add(s(p));
        o.view = tableView(m(spec.get("view")));
        o.hourly = hourly;
        o.noise = () -> counts[0];
        o.onNoise = n -> counts[0] = n;
        List<Object> rands = l(spec.get("rands"));
        o.rand = seq(rands);
        o.now = () -> t[0];
        if (spec.get("caps") != null) {
            Map<String, Object> caps = m(spec.get("caps"));
            if (caps.containsKey("perSession")) o.perSession = (int) n(caps.get("perSession"));
            if (caps.containsKey("perHour")) o.perHour = (int) n(caps.get("perHour"));
        }
        if (spec.containsKey("rho")) o.rho = d(spec.get("rho"));
        if (spec.get("fatigue") != null) o.fatigue = m(spec.get("fatigue"));
        if (spec.containsKey("maxPerScreen")) o.maxPerScreen = (int) n(spec.get("maxPerScreen"));
        if (spec.containsKey("maxBoxCells")) o.maxBoxCells = (int) n(spec.get("maxBoxCells"));
        TrustedChannel.DeviceTrust dev = null;
        if (spec.get("device") != null) {
            Map<String, Object> dm = m(spec.get("device"));
            dev = new TrustedChannel.DeviceTrust();
            dev.rpId = s(dm.get("rpId"));
            dev.origins = l(dm.get("origins"));
            dev.credentials = m(dm.get("credentials"));
            dev.signCounts = dm.get("signCounts") == null ? null : new LinkedHashMap<>(m(dm.get("signCounts")));
            o.device = dev;
        }
        if (spec.get("lift") != null) {
            Map<String, Object> add = m(m(spec.get("lift")).get("add"));
            o.lift = act -> { Map<String, Object> v = Wallet.actionValuesOf(act); Map<String, Object> vals = new LinkedHashMap<>(m(v.get("values"))); vals.putAll(add); return obj("verb", v.get("verb"), "values", vals); };
        }
        if (spec.get("liftCand") != null) {
            Map<String, Object> add = m(spec.get("liftCand"));
            o.liftCandidate = c -> { Map<String, Object> vals = new LinkedHashMap<>(m(c.get("values"))); vals.putAll(add); return obj("verb", c.get("verb"), "values", vals); };
        }
        TrustedChannel ch = new TrustedChannel(o);
        List<String> seen = new ArrayList<>();
        List<Object> steps = new ArrayList<>();
        String session = o.session;
        WalletHandlers.ChannelResolver resolver = sid -> session.equals(sid) ? ch : null;
        for (Object stO : l(spec.get("steps"))) {
            Map<String, Object> st = m(stO);
            String op = s(st.get("op"));
            Object r;
            try {
                String qid = st.get("q") != null ? (n(st.get("q")) < seen.size() ? seen.get((int) n(st.get("q"))) : null) : (String) st.get("qid");
                switch (op) {
                    case "time": t[0] = d(st.get("t")); r = obj("t", st.get("t")); break;
                    case "receive": r = ch.receive(m(st.get("ir")), m(st.get("action"))); break;
                    case "next": {
                        Map<String, Object> scr = ch.nextScreen();
                        if (scr != null) for (Object q : l(scr.get("questions"))) seen.add(s(m(q).get("questionId")));
                        r = scr;
                        break;
                    }
                    case "answer": r = ch.answer(qid, m(st.get("response"))); break;
                    case "clarify": r = ch.clarify(st.get("body")); break;
                    case "hQuestion": r = WalletHandlers.question(resolver, st.get("sid") != null ? s(st.get("sid")) : session, st.get("body")); break;
                    case "hClarify": r = WalletHandlers.clarify(resolver, st.get("sid") != null ? s(st.get("sid")) : session, st.get("body")); break;
                    case "summary": r = ch.summary(); break;
                    case "state": r = obj("digest", ch.stateDigest(), "asked", (long) ch.questionsAsked()); break;
                    case "noise": r = obj("noise", ch.noise(), "admission", ch.admission()); break;
                    case "challenge": r = ch.deviceChallengeFor(qid); break;
                    default: throw new IllegalStateException("bad op " + op);
                }
            } catch (RuntimeException e) {
                r = obj("$err", true);
            }
            steps.add(obj("op", op, "r", r));
        }
        return obj("steps", steps, "noise", counts[0], "signCounts", dev == null ? null : dev.signCounts);
    }
}
