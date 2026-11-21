package net.atlasauth.pca;

import java.util.List;
import java.util.Map;

/** Public entry points to the package-private monitor-state and accumulation-parameter helpers, for the intent package port. */
public final class IntentTrajectoryBridge {
    private IntentTrajectoryBridge() {}

    /** The closed state set of a monitor declaration. */
    public static List<String> monitorStates(Map<String, Object> monitor) { return IntentAcc.monitorStates(monitor); }

    /** The integer parameters of a schema verb declaration that feed an accumulation unit, sorted. */
    public static List<String> accumulationParams(Map<String, Object> verbDecl, String unit) { return ActionSchema.accumulationParams(verbDecl, unit); }
}
