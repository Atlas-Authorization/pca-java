package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import net.atlasauth.pca.mpc.Compose;
import net.atlasauth.pca.mpc.Compose.ComposedDecision;
import net.atlasauth.pca.mpc.NetWire.NetAbort;
import net.atlasauth.pca.mpc.Party.DecisionVector;
import net.atlasauth.pca.mpc.Spdz.DealerFault;
import net.atlasauth.pca.mpc.SpdzRunner;
import net.atlasauth.pca.mpc.net.Certs;
import net.atlasauth.pca.mpc.net.Certs.Identity;
import net.atlasauth.pca.mpc.net.Mesh;
import net.atlasauth.pca.mpc.net.Mesh.NodeAddr;
import net.atlasauth.pca.mpc.net.Protocol;
import net.atlasauth.pca.mpc.net.Protocol.Behavior;
import net.atlasauth.pca.mpc.net.Protocol.DealerConfig;
import net.atlasauth.pca.mpc.net.Protocol.PartyConfig;
import net.atlasauth.pca.mpc.net.Protocol.PartyResult;
import org.junit.jupiter.api.Test;

/** The networked SPDZ-style protocol over loopback mutual TLS, trusted-dealer mode: agreement with the in-process engine, and refusals of a lying dealer and lying parties. */
class MpcProtocolTest {
    private static final int Q = 4;

    /** n parties (ids 0..n-1) plus a dealer node (id n), every mesh connected. */
    static Mesh[] cluster(int n, long recvMs) throws Exception {
        int total = n + 1;
        Identity[] ids = new Identity[total];
        List<NodeAddr> nodes = new ArrayList<>();
        for (int i = 0; i < total; i++) {
            ids[i] = Certs.generate("p" + i);
            nodes.add(new NodeAddr(i, "127.0.0.1", MpcMeshTest.freePort(), ids[i].certPem()));
        }
        Mesh[] meshes = new Mesh[total];
        List<CompletableFuture<Void>> conn = new ArrayList<>();
        for (int i = 0; i < total; i++) {
            meshes[i] = new Mesh(MpcMeshTest.cfg(i, nodes, ids[i], 30_000, recvMs));
            final Mesh m = meshes[i];
            conn.add(CompletableFuture.runAsync(m::connect, MpcMeshTest.EX));
        }
        for (CompletableFuture<Void> f : conn) f.get(60, TimeUnit.SECONDS);
        return meshes;
    }

    /** What a node ended with: a result, or the throwable that stopped it. */
    record Outcome(PartyResult result, Throwable error) {
        NetAbort abort() { return error instanceof NetAbort ? (NetAbort) error : null; }
    }

    static List<Outcome> runAll(Mesh[] meshes, List<DecisionVector> in, DealerConfig dealerCfg, Behavior[] behaviors) throws Exception {
        int n = in.size();
        List<Future<Outcome>> fs = new ArrayList<>();
        Callable<Outcome> dealer = () -> {
            try {
                dealerCfg.mesh = meshes[n];
                Protocol.runDealer(dealerCfg);
                return new Outcome(null, null);
            } catch (Throwable t) {
                return new Outcome(null, t);
            }
        };
        fs.add(MpcMeshTest.EX.submit(dealer));
        for (int i = 0; i < n; i++) {
            final int me = i;
            fs.add(MpcMeshTest.EX.submit(() -> {
                try {
                    PartyConfig c = new PartyConfig();
                    c.id = me;
                    c.n = n;
                    c.Q = Q;
                    c.input = in.get(me);
                    c.mesh = meshes[me];
                    c.offline = "trusted-dealer";
                    c.insecureTrustedDealer = true;
                    c.sessionId = meshes[me].sessionId();
                    if (behaviors != null && behaviors[me] != null) {
                        c.behavior = behaviors[me];
                        c.unsafeTestHooks = true;
                    }
                    return new Outcome(Protocol.runParty(c), null);
                } catch (Throwable t) {
                    return new Outcome(null, t);
                }
            }));
        }
        List<Outcome> out = new ArrayList<>();
        for (Future<Outcome> f : fs) out.add(f.get(120, TimeUnit.SECONDS));
        return out.subList(1, out.size()); // the parties; the dealer's own outcome is not asserted
    }

    static DealerConfig dealer(int n) {
        DealerConfig d = new DealerConfig();
        d.insecureTrustedDealer = true;
        d.n = n;
        d.Q = Q;
        d.seed = BigInteger.valueOf(7);
        return d;
    }

    static final List<DecisionVector> INPUTS = List.of(new DecisionVector(1, 1, 1), new DecisionVector(1, 2, 3), new DecisionVector(1, 1, 2));

    @Test void dealerModeAgreesWithTheInProcessEngine() throws Exception {
        List<Outcome> outs = runAll(cluster(3, 60_000), INPUTS, dealer(3), null);
        ComposedDecision clear = Compose.composeClear(INPUTS, Q);
        SpdzRunner.MaliciousMpcConfig rc = new SpdzRunner.MaliciousMpcConfig();
        rc.Q = Q;
        rc.seed = BigInteger.ONE;
        rc.insecureTrustedDealer = true;
        ComposedDecision engine = SpdzRunner.composeSecureMalicious(INPUTS, rc).composed();
        assertEquals(clear, engine);
        String digest = null;
        for (Outcome o : outs) {
            assertNull(o.error(), String.valueOf(o.error()));
            assertEquals(clear, o.result().composed());
            assertEquals("trusted-dealer", o.result().offlineMode());
            assertTrue(o.result().identifiableAbort());
            if (digest == null) digest = o.result().transcriptDigest();
            assertEquals(digest, o.result().transcriptDigest());
        }
    }

    @Test void aWrongProductFromTheDealerIsDetectedAndBlamed() throws Exception {
        DealerConfig d = dealer(3);
        d.fault = new DealerFault(BigInteger.ONE, null);
        List<Outcome> outs = runAll(cluster(3, 30_000), INPUTS, d, null);
        boolean named = false;
        for (Outcome o : outs) {
            assertNull(o.result(), "no party may produce output");
            NetAbort a = o.abort();
            assertNotNull(a, String.valueOf(o.error()));
            if (a.kind.equals("dealer") && Integer.valueOf(3).equals(a.blamed)) named = true;
        }
        assertTrue(named, "an honest party names the dealer");
    }

    @Test void aLyingOpenedShareIsNamedByItsPairwiseTag() throws Exception {
        Behavior[] b = new Behavior[3];
        b[1] = new Behavior("open-lie", "mul0");
        List<Outcome> outs = runAll(cluster(3, 30_000), INPUTS, dealer(3), b);
        boolean named = false;
        for (Outcome o : outs) {
            assertNull(o.result(), "no party may produce output");
            NetAbort a = o.abort();
            if (a != null && a.kind.equals("mac-check") && Integer.valueOf(1).equals(a.blamed)) named = true;
        }
        assertTrue(named, "an honest verifier names party 1");
    }

    @Test void aNonCanonicalFieldElementIsRefused() throws Exception {
        Behavior[] b = new Behavior[3];
        b[2] = new Behavior("noncanonical", "mul0");
        List<Outcome> outs = runAll(cluster(3, 30_000), INPUTS, dealer(3), b);
        boolean named = false;
        for (Outcome o : outs) {
            assertNull(o.result(), "no party may produce output");
            NetAbort a = o.abort();
            if (a != null && a.kind.equals("malformed") && Integer.valueOf(2).equals(a.blamed)) named = true;
        }
        assertTrue(named, "an honest party names party 2");
    }

    /** Runs the dealer-mode protocol with party 1 misbehaving; no party may produce output, and (when expected) an honest party names party 1 with one of the kinds. */
    private void liar(String kind, String round, boolean mustBlame, String... kinds) throws Exception {
        Behavior[] b = new Behavior[3];
        b[1] = new Behavior(kind, round);
        List<Outcome> outs = runAll(cluster(3, 30_000), INPUTS, dealer(3), b);
        boolean named = false;
        for (Outcome o : outs) {
            assertNull(o.result(), kind + ": no party may produce output");
            assertNotNull(o.abort(), kind + ": every party aborts");
            if (Integer.valueOf(1).equals(o.abort().blamed) && java.util.Arrays.asList(kinds).contains(o.abort().kind)) named = true;
        }
        if (mustBlame) assertTrue(named, kind + ": an honest party names party 1");
    }

    @Test void aWrongPairwiseTagIsNamed() throws Exception { liar("bad-tag", "mul1", true, "mac-check"); }

    @Test void aForgedMacShareIsFoundByTheBatchedCheck() throws Exception { liar("mac-lie", "mul1", true, "mac-check", "blame"); }

    @Test void aWrongMacResidualIsNamed() throws Exception { liar("sigma-lie", null, true, "mac-check", "blame"); }

    @Test void aResidualOpeningThatBreaksItsCommitmentIsNamed() throws Exception { liar("bad-sigma-open", null, true, "commitment"); }

    @Test void aCoinOpeningThatBreaksItsCommitmentIsNamed() throws Exception { liar("bad-coin-open", null, true, "commitment"); }

    @Test void aShortArrayIsMalformed() throws Exception { liar("short-array", "mul0", true, "malformed"); }

    @Test void equivocationNeverYieldsADivergentOutput() throws Exception { liar("equivocate", "mul0", false); }

    @Test void testHooksAndDealerOptInAreEnforcedBeforeAnyTraffic() {
        PartyConfig c = new PartyConfig();
        c.id = 0;
        c.n = 3;
        c.Q = Q;
        c.input = INPUTS.get(0);
        c.sessionId = "s";
        c.offline = "trusted-dealer";
        NetAbort a = assertThrows(NetAbort.class, () -> Protocol.runParty(c));
        assertEquals("local", a.kind);
        c.insecureTrustedDealer = true;
        c.behavior = new Behavior("open-lie", "out");
        assertEquals("local", assertThrows(NetAbort.class, () -> Protocol.runParty(c)).kind);
        DealerConfig d = new DealerConfig();
        d.n = 3;
        assertThrows(IllegalArgumentException.class, () -> Protocol.runDealer(d));
    }
}
