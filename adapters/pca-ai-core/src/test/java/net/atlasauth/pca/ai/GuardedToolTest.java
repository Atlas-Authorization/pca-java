package net.atlasauth.pca.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

public class GuardedToolTest {
    private static GuardedTool.Tool echo(AtomicInteger ran) {
        return new GuardedTool.Tool() {
            @Override public String name() { return "refund"; }
            @Override public Object call(Map<String, Object> input) { ran.incrementAndGet(); return "refunded " + input.get("id"); }
        };
    }

    @Test void guardsCallDerivesTheResourceHandsOverTheProofAndRecordsTheResult() {
        ToolGuardTest.Fake f = new ToolGuardTest.Fake();
        AtomicInteger ran = new AtomicInteger();
        List<String> seen = new ArrayList<>();
        GuardedTool.Tool t = GuardedTool.withPCA(f, GuardedTool.Spec.of("stripe.refund", a -> "charge:" + a.get("id")).onProof((p, a) -> seen.add(p.encoded + "/" + a.get("id"))), echo(ran));
        assertEquals("refund", t.name());
        assertEquals("refunded c1", t.call(Map.of("id", "c1")));
        assertEquals(List.of("stripe.refund@charge:c1"), f.proved);
        assertEquals(List.of("enc-stripe.refund/c1"), seen);
        assertEquals(List.of("refund=refunded c1"), f.recorded);
    }

    @Test void aDeniedProofNeverRunsTheTool() {
        ToolGuardTest.Fake f = new ToolGuardTest.Fake();
        f.deny.add("stripe.refund");
        AtomicInteger ran = new AtomicInteger();
        GuardedTool.Tool t = GuardedTool.withPCA(f, GuardedTool.Spec.of("stripe.refund", "charge:*"), echo(ran));
        assertThrows(PcaDenied.class, () -> t.call(Map.of("id", "c1")));
        assertEquals(0, ran.get());
        assertTrue(f.recorded.isEmpty());
    }

    @Test void aResourceFunctionThatThrowsIsARefusal() {
        AtomicInteger ran = new AtomicInteger();
        GuardedTool.Tool t = GuardedTool.withPCA(new ToolGuardTest.Fake(), GuardedTool.Spec.of("stripe.refund", a -> { throw new IllegalStateException("no id"); }), echo(ran));
        assertThrows(PcaDenied.class, () -> t.call(Map.of()));
        assertEquals(0, ran.get());
    }

    @Test void specNeedsAVerb() {
        assertThrows(IllegalArgumentException.class, () -> GuardedTool.Spec.of("", "r"));
    }
}
