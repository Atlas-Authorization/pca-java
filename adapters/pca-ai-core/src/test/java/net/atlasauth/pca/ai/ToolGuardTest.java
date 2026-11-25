package net.atlasauth.pca.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import net.atlasauth.pca.Agent;
import net.atlasauth.pca.Facade;
import net.atlasauth.pca.Keys;
import org.junit.jupiter.api.Test;

public class ToolGuardTest {
    /** A fake prover: records calls, refuses verbs listed in {@code deny}. */
    static final class Fake implements Prover {
        final List<String> proved = new ArrayList<>(), recorded = new ArrayList<>();
        final List<String> deny = new ArrayList<>();
        @Override public Proof prove(String verb, String resource, Map<String, Object> params) {
            if (deny.contains(verb)) throw new PcaDenied("denied by policy", verb, resource);
            proved.add(verb + "@" + resource);
            return new Proof(new LinkedHashMap<>(), "enc-" + verb, Map.of("PCA-Action", "enc-" + verb));
        }
        @Override public void tool(String name, Object output) { recorded.add(name + "=" + output); }
    }

    static final ToolGuard.ToolMapping MAP = (name, args) -> "refund".equals(name) ? new ToolGuard.Action("stripe.refund", "charge:" + args.get("id")) : null;

    @Test void runsTheBodyUnderTheProofAndRecordsTheResult() {
        Fake f = new Fake();
        String out = ToolGuard.runJson(f, MAP, "refund", "{\"id\":\"c1\"}", (a, p) -> "ok:" + p.encoded);
        assertEquals("ok:enc-stripe.refund", out);
        assertEquals(List.of("stripe.refund@charge:c1"), f.proved);
        assertEquals(List.of("refund=ok:enc-stripe.refund"), f.recorded);
    }

    @Test void anUnmappedToolIsRefusedAndNeverRuns() {
        AtomicInteger ran = new AtomicInteger();
        assertThrows(PcaDenied.class, () -> ToolGuard.runJson(new Fake(), MAP, "drop_tables", "{}", (a, p) -> { ran.incrementAndGet(); return "x"; }));
        assertEquals(0, ran.get());
    }

    @Test void aDeniedProofNeverRunsTheTool() {
        Fake f = new Fake();
        f.deny.add("stripe.refund");
        AtomicInteger ran = new AtomicInteger();
        PcaDenied d = assertThrows(PcaDenied.class, () -> ToolGuard.runJson(f, MAP, "refund", "{\"id\":\"c1\"}", (a, p) -> { ran.incrementAndGet(); return "x"; }));
        assertEquals("stripe.refund", d.verb);
        assertEquals(0, ran.get());
        assertTrue(f.recorded.isEmpty());
    }

    @Test void aProverThatCrashesIsARefusal() {
        Prover boom = (v, r, p) -> { throw new IllegalStateException("kaput"); };
        assertThrows(PcaDenied.class, () -> ToolGuard.runJson(boom, MAP, "refund", "{\"id\":\"c1\"}", (a, p) -> "x"));
    }

    @Test void argumentsMustBeAJsonObject() {
        assertEquals(0, ToolGuard.parseArguments("  ").size());
        assertEquals(0, ToolGuard.parseArguments(null).size());
        assertThrows(PcaDenied.class, () -> ToolGuard.parseArguments("[1]"));
        assertThrows(PcaDenied.class, () -> ToolGuard.parseArguments("{nope"));
        assertThrows(PcaDenied.class, () -> ToolGuard.parseArguments("\"s\""));
    }

    @Test void aNullResultCarriesTheProof() {
        Proof p = new Proof(new LinkedHashMap<>(), "E", Map.of());
        assertEquals("{\"pca\":\"E\"}", ToolGuard.content(null, p));
        assertEquals("{\"a\":1}", ToolGuard.content(Map.of("a", 1L), p));
    }

    @Test void theFacadeProverSignsInPolicyAndRefusesOutOfPolicy() {
        Keys.SuiteKey principal = Keys.ed25519(Keys.edFromSeed(new byte[32]));
        byte[] holder = new byte[32];
        holder[0] = 1;
        Map<String, Object> perms = new LinkedHashMap<>();
        perms.put("stripe", new ArrayList<Object>(List.of("refund")));
        Facade.Handle h = Agent.fromPrincipal(new Facade.AgentOptions(principal, "refund order 1", perms)
            .holder(Keys.ed25519(Keys.edFromSeed(holder))).aud("rs").now(System.currentTimeMillis()));
        Prover p = Prover.of(h);
        Proof ok = p.prove("stripe.refund", "charge:ch_1", new LinkedHashMap<>(Map.of("amount", 5L)));
        assertNotNull(ok.encoded);
        assertTrue(ok.headers.containsKey("PCA-Action"));
        assertThrows(PcaDenied.class, () -> p.prove("stripe.charge", "charge:ch_1", new LinkedHashMap<>()));
    }
}
