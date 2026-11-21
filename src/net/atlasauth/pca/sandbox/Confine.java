package net.atlasauth.pca.sandbox;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.revoke.JsVal;

/** Flatten the generated seccomp and Landlock profiles into the flags of a reference confinement helper (it never reads a second source of truth). */
public final class Confine {
    private Confine() {}

    private static String shortName(Object n) { return ((String) n).replaceFirst("^LANDLOCK_ACCESS_", ""); }

    private static String joinShort(List<?> xs) {
        List<String> out = new ArrayList<>();
        for (Object x : xs) out.add(shortName(x));
        return String.join(",", out);
    }

    /** The helper's flags for a policy; run as {@code <helper> <flags> -- <command>}. */
    @SuppressWarnings("unchecked")
    public static List<String> confineArgs(Map<String, Object> policy) {
        Map<String, Object> ll = Profiles.landlockRuleset(policy);
        Map<String, Object> sc = Profiles.seccompProfile(policy);
        Map<String, Object> rules = (Map<String, Object>) ll.get("rules");
        List<Object> netRules = (List<Object>) rules.get("net");
        List<String> args = new ArrayList<>();
        args.add("--fs-handled");
        args.add(joinShort((List<?>) ll.get("handled_access_fs")));
        if (!netRules.isEmpty() || ((Map<String, Object>) policy.get("net")).get("proxy") != null) {
            args.add("--net-handled");
            args.add(joinShort((List<?>) ll.get("handled_access_net")));
        }
        for (Object r : (List<?>) rules.get("fs")) {
            Map<String, Object> m = (Map<String, Object>) r;
            args.add("--fs");
            args.add(m.get("path") + ":" + joinShort((List<?>) m.get("access")));
        }
        for (Object r : netRules) {
            Map<String, Object> m = (Map<String, Object>) r;
            args.add("--net");
            args.add(JsVal.str(m.get("port")) + ":" + joinShort((List<?>) m.get("access")));
        }
        syscallFlags(args, sc);
        return args;
    }

    /** The syscall flags, appended after the filesystem and network flags in the reference's order. */
    @SuppressWarnings("unchecked")
    private static void syscallFlags(List<String> out, Map<String, Object> sc) {
        for (Object s : (List<?>) sc.get("syscalls")) {
            Map<String, Object> m = (Map<String, Object>) s;
            List<?> names = (List<?>) m.get("names");
            if (m.get("args") != null) {
                for (Object a : (List<?>) m.get("args")) {
                    Map<String, Object> am = (Map<String, Object>) a;
                    for (Object n : names) {
                        out.add("--allow-arg");
                        out.add(n + ":" + JsVal.str(am.get("index")) + ":" + JsVal.str(am.get("value")));
                    }
                }
            } else for (Object n : names) {
                out.add("--allow");
                out.add((String) n);
            }
        }
    }
}
