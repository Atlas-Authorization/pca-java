package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import net.atlasauth.pca.mpc.Compose;
import net.atlasauth.pca.mpc.Compose.ComposedDecision;
import net.atlasauth.pca.mpc.NetWire.NetAbort;
import net.atlasauth.pca.mpc.Party.DecisionVector;
import net.atlasauth.pca.mpc.SpdzRunner;
import net.atlasauth.pca.mpc.Spdz.DealerFault;
import net.atlasauth.pca.mpc.net.Certs;
import net.atlasauth.pca.mpc.net.Certs.Identity;
import net.atlasauth.pca.mpc.net.LaunchLocal;
import net.atlasauth.pca.mpc.net.LaunchLocal.NodeOutput;
import net.atlasauth.pca.mpc.net.Mesh;
import net.atlasauth.pca.mpc.net.Mesh.NodeAddr;
import net.atlasauth.pca.mpc.net.OtNet;
import net.atlasauth.pca.mpc.net.Protocol.Behavior;
import org.junit.jupiter.api.Test;

/** The no-dealer (OT-based) offline phase and the in-process launcher over loopback mutual TLS, with refusals of lying parties. */
class MpcOfflineNetTest {
    private static final int Q = 4;
    private static final List<DecisionVector> INPUTS = List.of(new DecisionVector(1, 1, 1), new DecisionVector(1, 2, 3), new DecisionVector(1, 1, 2));

    private static LaunchLocal.Options opts(Map<Integer, Behavior> beh) {
        LaunchLocal.Options o = new LaunchLocal.Options();
        o.n = 3;
        o.Q = Q;
        o.vectors = INPUTS;
        o.recvTimeoutMs = 60_000;
        o.killAfterMs = 240_000;
        o.behaviors = beh;
        return o;
    }

    @Test void noDealerAgreesWithTheInProcessEngine() throws Exception {
        LaunchLocal.Launched l = LaunchLocal.launch(opts(Map.of()));
        ComposedDecision clear = Compose.composeClear(INPUTS, Q);
        SpdzRunner.MaliciousMpcConfig rc = new SpdzRunner.MaliciousMpcConfig();
        rc.Q = Q;
        rc.seed = BigInteger.ONE;
        assertEquals(clear, SpdzRunner.composeSecureMalicious(INPUTS, rc).composed());
        String digest = null;
        assertEquals(3, l.outputs().size());
        for (NodeOutput o : l.outputs()) {
            assertNull(o.error(), String.valueOf(o.error()));
            assertEquals(clear, o.result().composed());
            assertEquals("no-dealer", o.result().offlineMode());
            assertTrue(o.result().identifiableAbort());
            if (digest == null) digest = o.result().transcriptDigest();
            assertEquals(digest, o.result().transcriptDigest());
        }
    }

    @Test void trustedDealerThroughTheLauncher() throws Exception {
        LaunchLocal.Options o = opts(Map.of());
        o.offline = "trusted-dealer";
        o.insecureTrustedDealer = true;
        o.dealerSeed = BigInteger.valueOf(11);
        LaunchLocal.Launched l = LaunchLocal.launch(o);
        assertEquals(4, l.outputs().size());
        ComposedDecision clear = Compose.composeClear(INPUTS, Q);
        for (NodeOutput out : l.outputs()) {
            if (out.role().equals("party")) {
                assertNull(out.error(), String.valueOf(out.error()));
                assertEquals(clear, out.result().composed());
            }
        }
    }

    /** The launcher binds first: every node holds the port it advertises, the ports differ, and no probe-and-release reservation remains. */
    @Test void launcherNodesHoldTheirAdvertisedPortsAndNothingIsProbed() throws Exception {
        LaunchLocal.Options o = opts(Map.of());
        Identity[] ids = new Identity[3];
        for (int i = 0; i < ids.length; i++) ids[i] = Certs.generate("lp" + i);
        LaunchLocal.Bound b = LaunchLocal.bind(o, 3, 3, false, ids);
        try {
            java.util.Set<Integer> seen = new java.util.HashSet<>();
            for (int i = 0; i < 3; i++) {
                assertTrue(b.ports()[i] > 0);
                assertEquals(b.ports()[i], b.meshes()[i].boundPort(), "advertised port is the bound port of node " + i);
                assertTrue(seen.add(b.ports()[i]), "ports differ");
                // the port is held by this node: a second bind on it is refused
                final int held = b.ports()[i];
                assertThrows(java.io.IOException.class, () -> new java.net.ServerSocket(held, 1, java.net.InetAddress.getByName("127.0.0.1")).close(), "node " + i + " holds its port");
            }
        } finally {
            for (Mesh m : b.meshes()) m.kill();
        }
        for (java.lang.reflect.Method m : LaunchLocal.class.getDeclaredMethods()) assertNotEquals("reserve" + "Ports", m.getName());
    }

    @Test void theDealerOptInIsRequired() {
        LaunchLocal.Options o = opts(Map.of());
        o.offline = "trusted-dealer";
        assertThrows(IllegalArgumentException.class, () -> LaunchLocal.launch(o));
    }

    private static NetAbort assertNobodySucceedsAndSomeoneNames(LaunchLocal.Launched l, String kind, int blamed) {
        NetAbort named = null;
        for (NodeOutput o : l.outputs()) {
            assertNull(o.result(), "no party may produce output");
            NetAbort a = o.abort();
            if (a != null && a.kind.equals(kind) && Integer.valueOf(blamed).equals(a.blamed)) named = a;
        }
        assertNotNull(named, "an honest party names party " + blamed + " with kind " + kind);
        return named;
    }

    @Test void aWrongOtOperandInATripleProductIsCaughtByTheSacrificeAndAttributed() throws Exception {
        LaunchLocal.Launched l = LaunchLocal.launch(opts(Map.of(1, new Behavior("offline-lie", null))));
        assertNobodySucceedsAndSomeoneNames(l, "mac-check", 1);
    }

    @Test void anInconsistentOtExtensionMatrixIsCaughtByTheKosCheck() throws Exception {
        LaunchLocal.Launched l = LaunchLocal.launch(opts(Map.of(2, new Behavior("ot-u-lie", null))));
        assertNobodySucceedsAndSomeoneNames(l, "ot-check", 2);
    }

    @Test void aBadBaseOtProofIsRefused() throws Exception {
        LaunchLocal.Launched l = LaunchLocal.launch(opts(Map.of(1, new Behavior("ot-proof-lie", null))));
        assertNobodySucceedsAndSomeoneNames(l, "ot-check", 1);
    }

    @Test void aSilentPartyIsBlamedByTimeout() throws Exception {
        LaunchLocal.Options o = opts(Map.of(2, new Behavior("silent", "in-share")));
        o.recvTimeoutMs = 15_000;
        o.killAfterMs = 120_000;
        LaunchLocal.Launched l = LaunchLocal.launch(o);
        boolean named = false;
        for (NodeOutput out : l.outputs()) {
            assertNull(out.result());
            NetAbort a = out.abort();
            if (a != null && a.kind.equals("timeout") && Integer.valueOf(2).equals(a.blamed)) named = true;
        }
        assertTrue(named);
    }

    @Test void aNodeRefusesToStartWithTestHooksOutsideATestEnvironment() throws Exception {
        java.nio.file.Path f = java.nio.file.Files.createTempFile("node-cfg", ".json");
        try {
            java.nio.file.Files.writeString(f, "{\"role\":\"party\",\"id\":0,\"unsafeTestHooks\":true,\"behavior\":{\"kind\":\"crash\",\"round\":\"out\"}}");
            org.junit.jupiter.api.Assumptions.assumeTrue(System.getenv("PCA_MPC_UNSAFE_TEST_HOOKS") == null);
            assertEquals(3, net.atlasauth.pca.mpc.net.PartyMain.run(new String[] {f.toString()}));
            java.nio.file.Files.writeString(f, "{\"role\":\"party\",\"id\":0,\"unsafeTestHooks\":true,\"frameFault\":{}}");
            assertEquals(3, net.atlasauth.pca.mpc.net.PartyMain.run(new String[] {f.toString()}));
        } finally {
            java.nio.file.Files.deleteIfExists(f);
        }
    }

    @Test void pairwiseBaseOtMatchesOverTheNetwork() throws Exception {
        Identity i0 = Certs.generate("ot0");
        Identity i1 = Certs.generate("ot1");
        Mesh[] both = MpcMeshTest.bound(new Identity[] {i0, i1}, 30_000, 30_000);
        Mesh m0 = both[0], m1 = both[1];
        CompletableFuture<OtNet.Result> s = CompletableFuture.supplyAsync(() -> { m0.connect(); return OtNet.runOtSender(m0, 1, 32); }, MpcMeshTest.EX);
        CompletableFuture<OtNet.Result> r = CompletableFuture.supplyAsync(() -> { m1.connect(); return OtNet.runOtReceiver(m1, 0, 32); }, MpcMeshTest.EX);
        OtNet.Result sr = s.get(60, TimeUnit.SECONDS);
        OtNet.Result rr = r.get(60, TimeUnit.SECONDS);
        assertTrue(sr.matched());
        assertTrue(rr.matched());
    }
}
