package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import net.atlasauth.pca.mpc.NetWire;
import net.atlasauth.pca.mpc.NetWire.Frame;
import net.atlasauth.pca.mpc.net.Faults;
import net.atlasauth.pca.mpc.net.Faults.FrameFault;
import net.atlasauth.pca.mpc.net.Faults.Kind;
import net.atlasauth.pca.mpc.net.Mesh.TamperEvent;
import org.junit.jupiter.api.Test;

/** The frame-level tamper hook (the PartyMain frameFault config), driven without a network. */
class MpcNetFrameFaultTest {
    private static TamperEvent ev(int to, String rd, long seq) {
        Frame f = new Frame(1, "data", "sid", seq, rd, java.util.Map.of("k", "v"));
        return new TamperEvent(to, f, NetWire.encodeFrame(f));
    }

    private static List<byte[]> apply(FrameFault ff, TamperEvent e) { return Faults.tamperFor(ff).apply(e); }

    @Test void otherRoundsAndRecipientsPassUntouched() {
        TamperEvent e = ev(1, "mul0", 3);
        assertArrayEquals(e.raw(), apply(new FrameFault(Kind.DROP, "mul1", null, null), e).get(0));
        assertArrayEquals(e.raw(), apply(new FrameFault(Kind.DROP, "mul0", 2, null), e).get(0));
        assertTrue(apply(new FrameFault(Kind.DROP, "mul0", 1, null), e).isEmpty());
    }

    @Test void duplicateSkipSeqWrongRoundAndExtraFieldRewriteTheFrame() {
        TamperEvent e = ev(1, "mul0", 3);
        assertEquals(2, apply(new FrameFault(Kind.DUPLICATE, "mul0", null, null), e).size());
        byte[] skip = apply(new FrameFault(Kind.SKIP_SEQ, "mul0", null, null), e).get(0);
        assertArrayEquals(NetWire.encodeFrame(new Frame(1, "data", "sid", 4L, "mul0", java.util.Map.of("k", "v"))), skip);
        byte[] wr = apply(new FrameFault(Kind.WRONG_ROUND, "mul0", null, null), e).get(0);
        assertArrayEquals(NetWire.encodeFrame(new Frame(1, "data", "sid", 3L, "zzz-mul0", java.util.Map.of("k", "v"))), wr);
        byte[] xb = apply(new FrameFault(Kind.EXTRA_FIELD, "mul0", null, null), e).get(0);
        String extra = new String(xb, 4, xb.length - 4, java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(extra.endsWith("\"x\":1}"));
    }

    @Test void garbageTruncateBitflipAndOversizeKeepTheShape() {
        TamperEvent e = ev(1, "mul0", 3);
        byte[] g = apply(new FrameFault(Kind.GARBAGE, "mul0", null, null), e).get(0);
        assertEquals(e.raw().length, g.length);
        assertEquals((byte) 0x5a, g[g.length - 1]);
        assertEquals(Math.max(5, e.raw().length / 2), apply(new FrameFault(Kind.TRUNCATE, "mul0", null, null), e).get(0).length);
        byte[] b = apply(new FrameFault(Kind.BITFLIP, "mul0", null, null), e).get(0);
        int diff = 0;
        for (int i = 0; i < b.length; i++) if (b[i] != e.raw()[i]) diff++;
        assertEquals(1, diff);
        assertArrayEquals(new byte[] {0x7f, -1, -1, -1}, apply(new FrameFault(Kind.OVERSIZE, "mul0", null, null), e).get(0));
    }

    @Test void reorderHoldsOneFrameThenReleasesItAfterTheNext() {
        var hook = Faults.tamperFor(new FrameFault(Kind.REORDER, "mul0", null, null));
        TamperEvent first = ev(1, "mul0", 3), second = ev(1, "mul1", 4);
        assertTrue(hook.apply(first).isEmpty());
        List<byte[]> out = hook.apply(second);
        assertEquals(2, out.size());
        assertArrayEquals(second.raw(), out.get(0));
        assertArrayEquals(first.raw(), out.get(1));
    }

    @Test void silentFromStopsEverythingAfterTheFirstHit() {
        var hook = Faults.tamperFor(new FrameFault(Kind.SILENT_FROM, "mul0", null, null));
        assertTrue(hook.apply(ev(1, "mul0", 3)).isEmpty());
        assertTrue(hook.apply(ev(1, "mul9", 4)).isEmpty());
    }

    @Test void falseAccuseForgesAnAbortFrame() {
        byte[] a = apply(new FrameFault(Kind.FALSE_ACCUSE, "mul0", null, 2), ev(1, "mul0", 3)).get(0);
        String s = new String(a, 4, a.length - 4, java.nio.charset.StandardCharsets.UTF_8);
        assertTrue(s.contains("\"ty\":\"abort\"") && s.contains("\"blamed\":2"));
    }

    @Test void anUnknownKindIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> Kind.of("nope"));
    }
}
