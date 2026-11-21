package net.atlasauth.pca;

import static net.atlasauth.pca.MpcSupport.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.mpc.Beaver;
import net.atlasauth.pca.mpc.Beaver.OpenedMsg;
import net.atlasauth.pca.mpc.Compose;
import net.atlasauth.pca.mpc.Enc;
import net.atlasauth.pca.mpc.Field;
import net.atlasauth.pca.mpc.Field.FieldRng;
import net.atlasauth.pca.mpc.Gf128;
import net.atlasauth.pca.mpc.Party;
import net.atlasauth.pca.mpc.Runner;
import net.atlasauth.pca.mpc.Sharing;
import net.atlasauth.pca.mpc.Spdz;
import net.atlasauth.pca.mpc.Spdz.AuthSV;
import net.atlasauth.pca.mpc.Spdz.MacContext;
import net.atlasauth.pca.mpc.Spdz.OpenedValue;
import net.atlasauth.pca.mpc.Spdz.SpdzEngine;
import net.atlasauth.pca.mpc.Spdz.TripleWithPartners;
import net.atlasauth.pca.mpc.SpdzRunner;
import net.atlasauth.pca.mpc.Thermometer;
import org.junit.jupiter.api.Test;

/** Differential tests of the MPC deterministic layer against the TypeScript reference corpus (every draw from a seeded SplitMix64). */
class MpcDiffTest {
    private static final String MOD = "ref-mpc";

    private static List<Object> opened(List<OpenedMsg> l) {
        List<Object> out = new ArrayList<>();
        for (OpenedMsg m : l) out.add(M("label", m.label(), "value", m.value().toString(), "shares", L(m.shares())));
        return out;
    }

    @Test void field() throws Exception {
        OracleCases.each(MOD, "mod", a -> Field.mod(B(a.get(0))).toString());
        OracleCases.each(MOD, "fneg", a -> Field.fneg(B(a.get(0))).toString());
        OracleCases.each(MOD, "fadd", a -> Field.fadd(B(a.get(0)), B(a.get(1))).toString());
        OracleCases.each(MOD, "fsub", a -> Field.fsub(B(a.get(0)), B(a.get(1))).toString());
        OracleCases.each(MOD, "fmul", a -> Field.fmul(B(a.get(0)), B(a.get(1))).toString());
        OracleCases.each(MOD, "fieldRng", a -> { FieldRng g = rng(a.get(0)); List<Object> o = new ArrayList<>(); for (int i = 0; i < I(a.get(1)); i++) o.add(g.next().toString()); return o; });
        OracleCases.each(MOD, "fieldRngDefault", a -> { FieldRng g = new FieldRng(); List<Object> o = new ArrayList<>(); for (int i = 0; i < I(a.get(0)); i++) o.add(g.next().toString()); return o; });
    }

    @Test void sharing() throws Exception {
        OracleCases.each(MOD, "share", a -> L(Sharing.share(B(a.get(0)), I(a.get(1)), rng(a.get(2)))));
        OracleCases.each(MOD, "reconstruct", a -> Sharing.reconstruct(BA(a.get(0))).toString());
        OracleCases.each(MOD, "shareConstant", a -> L(Sharing.shareConstant(B(a.get(0)), I(a.get(1)))));
        OracleCases.each(MOD, "sv", a -> {
            String op = (String) a.get(0);
            BigInteger[] x = BA(a.get(1));
            switch (op) {
                case "add": return L(Sharing.addSV(x, BA(a.get(2))));
                case "sub": return L(Sharing.subSV(x, BA(a.get(2))));
                case "neg": return L(Sharing.negSV(x));
                case "scale": return L(Sharing.scaleSV(x, B(a.get(2))));
                case "addPublic": return L(Sharing.addPublicSV(x, B(a.get(2))));
                case "notBit": return L(Sharing.notBitSV(x));
                default: throw new IllegalArgumentException(op);
            }
        });
    }

    @Test void gf128() throws Exception {
        OracleCases.each(MOD, "gf", a -> {
            String op = (String) a.get(0);
            BigInteger x = B(a.get(1));
            switch (op) {
                case "add": return Gf128.add(x, B(a.get(2))).toString();
                case "mul": return Gf128.mul(x, B(a.get(2))).toString();
                case "mulX": return Gf128.mulX(x).toString();
                case "mulByXi": return Gf128.mulByXi(x, I(a.get(2))).toString();
                default: throw new IllegalArgumentException(op);
            }
        });
    }

    @Test void enc() throws Exception {
        OracleCases.each(MOD, "encBits", a -> Enc.encBits(I(a.get(0))));
        OracleCases.each(MOD, "makeGadget", a -> { FieldRng g = rng(a.get(1)); return L(Enc.makeGadget(I(a.get(0)), g, Boolean.TRUE.equals(a.get(2)))); });
        OracleCases.each(MOD, "plainShare", a -> { Enc.EncShare e = Enc.plainShare(B(a.get(0))); return M("value", e.value().toString(), "bits", L(e.bits())); });
        OracleCases.each(MOD, "plainGadget", a -> L(Enc.plainGadget()));
        OracleCases.each(MOD, "randomBits", a -> L(Enc.randomBits(I(a.get(0)), rng(a.get(1)))));
        OracleCases.each(MOD, "sampleEnc", a -> {
            FieldRng g = rng(a.get(1));
            BigInteger[] gad = Enc.makeGadget(I(a.get(0)), g, true);
            Enc.EncShare e = Enc.sampleEnc(gad, g);
            return M("gadget", L(gad), "e", M("value", e.value().toString(), "bits", L(e.bits())));
        });
        OracleCases.each(MOD, "encValue", a -> Enc.encValue(BA(a.get(0)), IA(a.get(1))).toString());
    }

    @Test void beaver() throws Exception {
        OracleCases.each(MOD, "genTriple", a -> { Beaver.Triple t = Beaver.genTriple(I(a.get(0)), rng(a.get(1))); return M("a", L(t.a()), "b", L(t.b()), "c", L(t.c())); });
        OracleCases.each(MOD, "beaverMul", a -> {
            List<OpenedMsg> op = new ArrayList<>();
            BigInteger[] z = Beaver.beaverMul(BA(a.get(0)), BA(a.get(1)), new Beaver.Triple(BA(a.get(2)), BA(a.get(3)), BA(a.get(4))), op);
            return M("z", L(z), "opened", opened(op));
        });
    }

    @Test void composition() throws Exception {
        OracleCases.each(MOD, "thermometerEncode", a -> L(Thermometer.thermometerEncode(D(a.get(0)), I(a.get(1)))));
        OracleCases.each(MOD, "thermometerDecode", a -> {
            int c = 0;
            for (Object b : (List<?>) a.get(0)) if (b instanceof Json.Num && OracleCases.num(b) == 1.0) c++;
            return c;
        });
        OracleCases.each(MOD, "quantizeR", a -> Party.quantizeR(D(a.get(0)), I(a.get(1))));
        OracleCases.each(MOD, "composeClear", a -> {
            Compose.ComposedDecision d = Compose.composeClear(vectors(a.get(0)), I(a.get(1)));
            return M("allow", d.allow(), "t", d.t(), "rQuant", d.rQuant());
        });
        OracleCases.each(MOD, "assertDecisionVectors", a -> { Compose.assertDecisionVectors(vectors(a.get(0)), I(a.get(1))); return true; });
        OracleCases.each(MOD, "composeSecure", a -> {
            Runner.MpcResult r = Runner.composeSecure(vectors(a.get(0)), I(a.get(1)), B(a.get(2)));
            List<Object> sh = new ArrayList<>();
            for (Runner.SharingRecord s : r.sharings()) sh.add(M("label", s.label(), "party", s.party(), "secret", s.secret().toString(), "shares", L(s.shares())));
            List<Object> held = new ArrayList<>();
            for (BigInteger h : r.views().get(0).heldShares()) held.add(h.toString());
            return M("composed", M("allow", r.composed().allow(), "t", r.composed().t(), "rQuant", r.composed().rQuant()), "parties", r.parties(), "Q", r.Q(),
                "multiplications", r.multiplications(), "opened", opened(r.opened()), "sharings", sh, "heldShares0", held, "viewsLen", r.views().size());
        });
    }

    @Test void spdzAuthShares() throws Exception {
        OracleCases.each(MOD, "setupMac", a -> ctx(Spdz.setupMac(I(a.get(0)), rng(a.get(1)), I(a.get(2)))));
        OracleCases.each(MOD, "macSoundnessBits", a -> a.size() == 1 ? Spdz.macSoundnessBits(I(a.get(0))) : Spdz.macSoundnessBits(I(a.get(0)), B(a.get(1))));
        OracleCases.each(MOD, "authShare", a -> {
            FieldRng g = rng(a.get(1));
            MacContext c = Spdz.setupMac(I(a.get(0)), g);
            return M("ctx", ctx(c), "sv", authSV(Spdz.authShare(B(a.get(2)), c, g)));
        });
        OracleCases.each(MOD, "authConstant", a -> authSV(Spdz.authConstant(B(a.get(2)), Spdz.setupMac(I(a.get(0)), rng(a.get(1))))));
        OracleCases.each(MOD, "authOp", a -> {
            String op = (String) a.get(0);
            FieldRng g = rng(a.get(2));
            MacContext c = Spdz.setupMac(I(a.get(1)), g);
            AuthSV x = Spdz.authShare(B(a.get(3)), c, g);
            AuthSV y = Spdz.authShare(B(a.get(4)), c, g);
            BigInteger k = B(a.get(5));
            if (op.equals("open")) return M("val", Spdz.authValue(x).toString());
            AuthSV res;
            switch (op) {
                case "add": res = Spdz.addAuth(x, y); break;
                case "sub": res = Spdz.subAuth(x, y); break;
                case "neg": res = Spdz.negAuth(x); break;
                case "scale": res = Spdz.scaleAuth(x, k); break;
                case "addPublic": res = Spdz.addPublicAuth(x, k, c); break;
                case "notBit": res = Spdz.notBitAuth(x, c); break;
                default: throw new IllegalArgumentException(op);
            }
            BigInteger val = Spdz.authValue(res);
            List<BigInteger[]> rows = new ArrayList<>();
            rows.add(res.mac());
            rows.addAll(List.of(res.extraMac()));
            boolean ok = true;
            for (int l = 0; l < rows.size(); l++) {
                BigInteger sum = BigInteger.ZERO;
                for (BigInteger m : rows.get(l)) sum = Field.fadd(sum, m);
                ok &= sum.equals(Field.fmul(Spdz.macKeys(c).get(l).alpha(), val));
            }
            return M("res", authSV(res), "val", val.toString(), "okMac", ok);
        });
        OracleCases.each(MOD, "genAuthTriple", a -> {
            FieldRng g = rng(a.get(1));
            return triple(Spdz.genAuthTriple(Spdz.setupMac(I(a.get(0)), g), g));
        });
    }

    private static Object partnered(TripleWithPartners t) {
        List<Object> ps = new ArrayList<>();
        for (var p : t.partners()) ps.add(triple(p));
        return M("keep", triple(t.keep()), "partners", ps);
    }

    @Test void spdzTriples() throws Exception {
        OracleCases.each(MOD, "genTripleWithPartners", a -> {
            if (a.size() == 2) {
                FieldRng g = rng(a.get(1));
                return partnered(Spdz.genTripleWithPartners(Spdz.setupMac(I(a.get(0)), g), g));
            }
            FieldRng g = rng(a.get(0));
            return partnered(Spdz.genTripleWithPartners(Spdz.setupMac(2, g), g, I(a.get(1)), fault(a.get(2))));
        });
        OracleCases.each(MOD, "sacrifice", a -> {
            FieldRng g = rng(a.get(1));
            MacContext c = Spdz.setupMac(I(a.get(0)), g);
            Spdz.DealerFault f = fault(a.get(4));
            List<TripleWithPartners> batch = new ArrayList<>();
            for (int i = 0; i < I(a.get(2)); i++) batch.add(Spdz.genTripleWithPartners(c, g, I(a.get(3)), i == 0 ? f : null));
            List<Object> out = new ArrayList<>();
            for (var t : Spdz.sacrificeVerify(batch, c, g, devs(a.get(5)))) out.add(triple(t));
            return M("certified", out);
        });
    }

    @Test void spdzEngine() throws Exception {
        OracleCases.each(MOD, "engineRun", a -> {
            FieldRng g = rng(a.get(1));
            MacContext c = Spdz.setupMac(I(a.get(0)), g, a.size() > 4 ? I(a.get(4)) : Spdz.MAC_KEYS);
            SpdzEngine e = new SpdzEngine(c, devs(a.get(3)));
            List<Object> outs = new ArrayList<>();
            List<?> values = (List<?>) a.get(2);
            for (int i = 0; i < values.size(); i++) outs.add(e.open(Spdz.authShare(B(values.get(i)), c, g), "v" + i).toString());
            e.macCheck(g);
            return M("outs", outs, "count", e.openCount());
        });
        OracleCases.each(MOD, "macResiduals", a -> {
            List<OpenedValue> op = new ArrayList<>();
            for (Object o : (List<?>) a.get(2)) { Map<String, Object> m = map(o); op.add(new OpenedValue(B(m.get("value")), BAA(m.get("macShares")), "")); }
            return LL(Spdz.macResiduals(B(a.get(0)), BAA(a.get(1)), op, BAA(a.get(3))));
        });
        OracleCases.each(MOD, "beaverAuth", a -> {
            FieldRng g = rng(a.get(1));
            MacContext c = Spdz.setupMac(I(a.get(0)), g);
            SpdzEngine e = new SpdzEngine(c, devs(a.get(4)));
            AuthSV x = Spdz.authShare(B(a.get(2)), c, g);
            AuthSV y = Spdz.authShare(B(a.get(3)), c, g);
            var t = Spdz.genAuthTriple(c, g);
            AuthSV z = Spdz.beaverMulAuth(x, y, t, c, e, "m");
            BigInteger val = Spdz.authValue(z);
            BigInteger out = e.open(z, "out");
            e.macCheck(g);
            return M("z", authSV(z), "val", val.toString(), "out", out.toString(), "opens", e.openCount());
        });
    }

    /** Decodes a composeSecureMalicious config object (Q, seed, deviations, insecureTrustedDealer, dealer). */
    static SpdzRunner.MaliciousMpcConfig config(Map<String, Object> m) {
        SpdzRunner.MaliciousMpcConfig c = new SpdzRunner.MaliciousMpcConfig();
        if (m.get("Q") != null) c.Q = I(m.get("Q"));
        if (m.get("seed") != null) c.seed = B(m.get("seed"));
        if (m.get("deviations") != null) c.deviations = devs(m.get("deviations"));
        c.insecureTrustedDealer = Boolean.TRUE.equals(m.get("insecureTrustedDealer"));
        if (m.get("dealer") != null) {
            Map<String, Object> d = map(m.get("dealer"));
            c.dealer = new SpdzRunner.DealerOptions();
            if (d.get("verifyTriples") != null) c.dealer.verifyTriples = (Boolean) d.get("verifyTriples");
            if (d.get("partners") != null) c.dealer.partners = I(d.get("partners"));
            c.dealer.fault = fault(d.get("fault"));
        }
        return c;
    }

    static Object summary(SpdzRunner.MaliciousMpcResult r) {
        return M("composed", M("allow", r.composed().allow(), "t", r.composed().t(), "rQuant", r.composed().rQuant()), "parties", r.parties(), "Q", r.Q(), "opens", r.opens(),
            "multiplications", r.multiplications(), "offlineMode", r.offlineMode(), "triplesVerified", r.triplesVerified(), "macChecked", r.macChecked());
    }

    @Test void maliciousRunnerTrustedDealer() throws Exception {
        OracleCases.each(MOD, "composeSecureMalicious", a -> summary(SpdzRunner.composeSecureMalicious(vectors(a.get(0)), config(map(a.get(1))))));
    }
}
