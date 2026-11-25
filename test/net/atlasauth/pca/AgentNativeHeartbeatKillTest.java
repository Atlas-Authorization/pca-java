package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** A lease heartbeat is accepted only when its time is within the skew of the clock: NaN, an infinity, a missing or a wrong-typed time or clock never renews. */
public class AgentNativeHeartbeatKillTest {
    static final long NOW = 1_000_000L;
    static final Keys.EdKey HOLDER = Keys.edFromSeed(new byte[32]);

    static Map<String, Object> lease() {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("cap_id", "cap-1");
        a.put("holder", HOLDER.id());
        a.put("now", NOW);
        a.put("ttl_ms", 60_000L);
        return AgentNative.grantLease(a);
    }

    /** A heartbeat for {@link #lease()} carrying {@code at} (any value, or absent when {@code absent}), validly signed by the holder. */
    static Map<String, Object> heartbeat(Object at, boolean absent) {
        Map<String, Object> hb = new LinkedHashMap<>();
        hb.put("cap_id", "cap-1");
        hb.put("seq", 1L);
        if (!absent) hb.put("at", at);
        hb.put("holder", HOLDER.id());
        hb.put("lease_issued_at", NOW);
        Map<String, Object> body = new LinkedHashMap<>(hb);
        if (!absent && !(at instanceof Long)) body.put("at", NOW); // the signature covers a canonical body: a NaN or wrong-typed time is set after signing
        hb.put("sig", Keys.b64u(HOLDER.sign(Pca.canonBytes(Issue.obj("d", "atlas-pca/lease-hb/v2", "b", body)))));
        return hb;
    }

    @Test void aFiniteTimeWithinTheSkewRenews() {
        for (long at : new long[] {NOW, NOW - AgentNative.HEARTBEAT_SKEW_MS, NOW + AgentNative.HEARTBEAT_SKEW_MS}) {
            Map<String, Object> r = AgentNative.renewCapabilityLease(lease(), heartbeat(at, false), NOW);
            assertEquals(Boolean.TRUE, r.get("ok"), "at=" + at + " " + r);
        }
    }

    @Test void aFiniteTimeOutsideTheSkewIsRefused() {
        for (long at : new long[] {NOW - AgentNative.HEARTBEAT_SKEW_MS - 1, NOW + AgentNative.HEARTBEAT_SKEW_MS + 1}) {
            Map<String, Object> r = AgentNative.renewCapabilityLease(lease(), heartbeat(at, false), NOW);
            assertEquals(Boolean.FALSE, r.get("ok"));
            assertEquals("heartbeat outside skew window", r.get("reason"), "at=" + at);
        }
    }

    @Test void aNonFiniteMissingOrWrongTypedHeartbeatTimeIsRefused() {
        for (Object at : new Object[] {Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, "1000000", null}) {
            Map<String, Object> r = AgentNative.renewCapabilityLease(lease(), heartbeat(at, false), NOW);
            assertEquals(Boolean.FALSE, r.get("ok"), "at=" + at);
            assertEquals("heartbeat outside skew window", r.get("reason"), "at=" + at);
        }
        Map<String, Object> r = AgentNative.renewCapabilityLease(lease(), heartbeat(null, true), NOW);
        assertEquals(Boolean.FALSE, r.get("ok"));
        assertEquals("heartbeat outside skew window", r.get("reason"));
    }

    @Test void aNonFiniteMissingOrWrongTypedClockNeverRenews() {
        for (Object now : new Object[] {Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY, "1000000", null}) {
            Map<String, Object> r = AgentNative.renewCapabilityLease(lease(), heartbeat(NOW, false), now);
            assertEquals(Boolean.FALSE, r.get("ok"), "now=" + now);
            assertTrue(String.valueOf(r.get("reason")).contains("invalid clock"), "now=" + now + " " + r);
        }
    }
}
