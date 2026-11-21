package net.atlasauth.pca.mpc.net;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.mpc.NetForensics;
import net.atlasauth.pca.mpc.NetForensics.SlotDisclosure;
import net.atlasauth.pca.mpc.NetWire.NetAbort;

/**
 * Commit-first disclosure exchange for a failed triple (dealer-free mode). Nobody opens before every commitment is in hand
 * (round forensic-c completes first), so no party's disclosure can depend on another's; an opening that does not match its
 * commitment is blamed, a late or absent party times out at the shared deadline.
 */
public final class Forensic {
    private Forensic() {}

    private static final Pattern HEX64 = Pattern.compile("^[0-9a-f]{64}$");

    /** Every OTHER party's verified disclosure. */
    public static Map<Integer, List<SlotDisclosure>> exchangeDisclosures(String sessionId, int id, int n, int tripleIndex, List<SlotDisclosure> mine, int slots, int rows,
        long deadlineMs, Exchanger io) {
        List<Object> wire = NetForensics.wireDisclosure(mine);
        byte[] nb = new byte[32];
        new SecureRandom().nextBytes(nb);
        String nonce = HexFormat.of().formatHex(nb);
        String myCommit = NetForensics.disclosureCommit(sessionId, id, tripleIndex, deadlineMs, nonce, wire);
        Map<Integer, String> commits = io.exchange("forensic-c", p -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("c", myCommit);
            m.put("d", deadlineMs);
            return m;
        }, (p, raw) -> {
            Map<?, ?> o = raw instanceof Map ? (Map<?, ?>) raw : null;
            if (o == null || !(o.get("c") instanceof String) || !HEX64.matcher((String) o.get("c")).matches()) throw io.bad(p, "bad forensic commitment");
            if (!(o.get("d") instanceof Json.Num) || !o.get("d").toString().equals(Long.toString(deadlineMs))) throw io.bad(p, "forensic deadline " + o.get("d") + " differs from the agreed " + deadlineMs);
            return (String) o.get("c");
        }, deadlineMs);
        return io.exchange("forensic-o", p -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("w", wire);
            m.put("nonce", nonce);
            return m;
        }, (p, raw) -> {
            Map<?, ?> o = raw instanceof Map ? (Map<?, ?>) raw : null;
            if (o == null || !(o.get("nonce") instanceof String) || !HEX64.matcher((String) o.get("nonce")).matches()) throw io.bad(p, "bad forensic opening");
            if (!NetForensics.disclosureCommit(sessionId, p, tripleIndex, deadlineMs, (String) o.get("nonce"), o.get("w")).equals(commits.get(p))) {
                throw new NetAbort("commitment", p, id, "party " + p + " opened a forensic disclosure that does not match its commitment");
            }
            List<Integer> peers = new ArrayList<>();
            for (int q = 0; q < n; q++) if (q != p) peers.add(q);
            return NetForensics.parseDisclosure(o.get("w"), slots, rows, peers);
        }, deadlineMs);
    }
}
