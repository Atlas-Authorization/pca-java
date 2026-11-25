package net.atlasauth.pca.conformance;

import java.util.Map;

/** Helpers of the PCActn conformance vector harness. */
public final class Conformance {
    private Conformance() {}

    /** The first check, in the map's iteration (evaluation) order, whose status is {@code "fail"}; null when none failed. */
    public static String firstFailedCheck(Map<String, String> checks) {
        for (Map.Entry<String, String> e : checks.entrySet()) if ("fail".equals(e.getValue())) return e.getKey();
        return null;
    }
}
