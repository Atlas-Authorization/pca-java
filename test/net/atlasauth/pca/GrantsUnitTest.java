package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import net.atlasauth.pca.grants.GrantClient;
import net.atlasauth.pca.grants.LeaseStoreConformance;
import org.junit.jupiter.api.Test;

/** The I/O wrappers the oracle cannot reach: the lease store conformance kit and the grant client. */
class GrantsUnitTest {
    @Test void leaseStoreConformanceMemory() throws Exception {
        final AtomicKv[] opened = new AtomicKv[1];
        List<String> passed = LeaseStoreConformance.runLeaseStoreConformance(new LeaseStoreConformance.Kit() {
            @Override public AtomicKv open() { opened[0] = new MemoryAtomicKv(); return opened[0]; }
            @Override public AtomicKv reopen(AtomicKv kv) { return kv; }
            @Override public boolean supportsReopen() { return true; }
        });
        assertEquals(Arrays.asList("spread", "atomic update", "independent leases", "revocation placement", "shard count is pinned", "state survives a restart", "pruning bounds revocations"), passed);
    }

    @Test void grantClientCarriesFreshToken() throws Exception {
        Keys.EdKey as = Keys.edFromSeed(new byte[32]);
        Map<String, Object> state = new LinkedHashMap<>();
        state.put("revocation_epoch", 2L);
        state.put("ledger_tree_size", 3L);
        state.put("budget_version", 4L);
        state.put("policy_revision", 5L);
        state.put("policy_digest", "pd");
        Map<String, Object> tok = Issue.signFreshAt(as, "scope", state, 1_800_000_000_000L);
        AtomicReference<String> seenHeader = new AtomicReference<>();
        HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        srv.createContext("/pca/grants/missing", ex -> {
            byte[] b = "{\"error\":\"not_found\",\"message\":\"no such grant\"}".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(404, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        srv.createContext("/pca/grants", ex -> {
            seenHeader.set(ex.getRequestHeaders().getFirst("pca-fresh-at"));
            byte[] b = "{\"grants\":[]}".getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("pca-fresh-at", Json.canonicalize(tok));
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        srv.start();
        try {
            String base = "http://127.0.0.1:" + srv.getAddress().getPort() + "/";
            GrantClient c = new GrantClient(base, null, as.id(), null);
            assertNull(c.freshAt());
            Map<String, String> q = new LinkedHashMap<>();
            q.put("status", "active");
            assertTrue(c.list(q).get("grants") instanceof List);
            assertNull(seenHeader.get());
            assertNotNull(c.freshAt());
            c.list(null);
            assertNotNull(seenHeader.get());
            GrantClient.ApiError e = assertThrows(GrantClient.ApiError.class, () -> c.inspect("missing"));
            assertEquals(404, e.status);
            assertEquals("not_found", e.code);
            // a token that does not verify under the pinned signer is ignored
            GrantClient strict = new GrantClient(base, null, Keys.edFromSeed(new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}).id(), null);
            strict.list(null);
            assertNull(strict.freshAt());
        } finally {
            srv.stop(0);
        }
    }
}
