package net.atlasauth.pca.sandbox;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.regex.Pattern;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.revoke.JsVal;

/**
 * Compile the OS policy from what was actually authorized, and generate the seccomp, Landlock and macOS (SBPL) profiles from it.
 * Policies and profiles are JSON trees (maps and lists); the output is byte-identical to the reference's canonical form.
 */
public final class Profiles {
    private Profiles() {}

    /** One authorized operation: the authorization result and the operation it must allow exactly. */
    public static final class AuthorizedOp {
        public final Authorize.AuthorizeResult result;
        public final Authorize.Operation operation;
        public AuthorizedOp(Authorize.AuthorizeResult result, Authorize.Operation operation) { this.result = result; this.operation = operation; }
    }

    // Absolute, normalized, and only characters that need no escaping in a seccomp/Landlock/SBPL string. Refuse, never escape.
    private static final Pattern PATH_RE = Pattern.compile("/[A-Za-z0-9._+@=,:~ /-]*");
    private static final Pattern HOST_RE = Pattern.compile("[a-z0-9]([a-z0-9.-]*[a-z0-9])?");

    private static String checkPath(Object p) {
        if (!(p instanceof String)) throw new IllegalArgumentException("bad_path");
        String s = (String) p;
        if (!PATH_RE.matcher(s).matches() || s.contains("//") || (s.length() > 1 && s.endsWith("/"))) throw new IllegalArgumentException("bad_path");
        for (String seg : s.split("/", -1)) if (seg.equals(".") || seg.equals("..")) throw new IllegalArgumentException("bad_path");
        return s;
    }

    /** {@code for (const x of v ?? [])}: a list iterates; null and the empty string are empty; anything else throws. */
    private static List<?> iter(Object v) {
        if (v == null) return Collections.emptyList();
        if (v instanceof List) return (List<?>) v;
        if (v instanceof String && ((String) v).isEmpty()) return Collections.emptyList();
        throw new JsVal.TypeError("not iterable");
    }

    /**
     * Compile the OS policy from what was actually authorized: only operations that {@code isAuthorizedFor} allows contribute,
     * so a denied or unrelated operation widens nothing. {@code needsOf} maps an operation to its needs (a JSON object) or null.
     */
    public static Map<String, Object> compilePolicy(List<AuthorizedOp> items, Function<Authorize.Operation, Object> needsOf, Object proxyPort) {
        List<Object> needs = new ArrayList<>();
        for (AuthorizedOp it : items) {
            if (!Authorize.isAuthorizedFor(it.result, it.operation)) throw new IllegalArgumentException("not_authorized: result does not allow exactly this operation");
            Object n = needsOf.apply(it.operation);
            if (n != null) needs.add(n);
        }
        return policyFromNeeds(needs, proxyPort);
    }

    /** The pure core of {@link #compilePolicy}: validate, merge, sort. {@code proxyPort} null means no proxy. */
    public static Map<String, Object> policyFromNeeds(Object needs, Object proxyPort) {
        if (!(needs instanceof List)) throw new JsVal.TypeError("needs is not iterable");
        Set<String> read = new TreeSet<>(), write = new TreeSet<>(), exec = new TreeSet<>(), hosts = new TreeSet<>();
        for (Object n : (List<?>) needs) {
            for (Object f : iter(JsVal.member(n, "fs"))) {
                String p = checkPath(JsVal.member(f, "path"));
                Object mode = JsVal.opt(f, "mode");
                if ("x".equals(mode)) exec.add(p);
                else if ("r".equals(mode) || "rw".equals(mode)) {
                    read.add(p);
                    if ("rw".equals(mode)) write.add(p);
                } else throw new IllegalArgumentException("bad_mode");
            }
            for (Object h : iter(JsVal.member(n, "net"))) {
                Object port = JsVal.member(h, "port");
                if (!HOST_RE.matcher(JsVal.strMember(h, "host")).matches() || !JsVal.isSafeInteger(port) && !isHugeInteger(port) || JsVal.num(port) < 1 || JsVal.num(port) > 65535)
                    throw new IllegalArgumentException("bad_net_need");
                hosts.add(JsVal.strMember(h, "host") + ":" + (long) (double) JsVal.num(port));
            }
        }
        if (!hosts.isEmpty() && proxyPort == null) throw new IllegalArgumentException("net_needs_proxy: network access exists only through the egress proxy; pass its port");
        if (proxyPort != null && (!isHugeInteger(proxyPort) && !JsVal.isSafeInteger(proxyPort) || JsVal.num(proxyPort) < 1 || JsVal.num(proxyPort) > 65535)) throw new IllegalArgumentException("bad_proxy_port");
        Map<String, Object> fs = new LinkedHashMap<>();
        fs.put("read", new ArrayList<Object>(read));
        fs.put("write", new ArrayList<Object>(write));
        fs.put("exec", new ArrayList<Object>(exec));
        Map<String, Object> net = new LinkedHashMap<>();
        if (proxyPort == null) net.put("proxy", null);
        else {
            Map<String, Object> px = new LinkedHashMap<>();
            px.put("host", "127.0.0.1");
            px.put("port", Long.valueOf((long) (double) JsVal.num(proxyPort)));
            net.put("proxy", px);
        }
        net.put("hosts", new ArrayList<Object>(hosts));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("v", 1L);
        out.put("fs", fs);
        out.put("net", net);
        return out;
    }

    /** Number.isInteger for a value beyond the safe range (such a port is out of range anyway). */
    private static boolean isHugeInteger(Object o) {
        Double d = JsVal.num(o);
        return d != null && !d.isNaN() && !d.isInfinite() && d == Math.rint(d);
    }

    // ---- profiles -------------------------------------------------------------------------------------------------------

    private static final List<String> BASE = sorted("read", "write", "close", "fstat", "newfstatat", "statx", "lseek", "mmap", "mprotect", "munmap", "mremap", "brk", "madvise", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sigaltstack", "pread64", "pwrite64", "readv", "writev", "openat", "getdents64", "fcntl", "getcwd", "readlink", "readlinkat", "dup", "dup3", "pipe2", "poll", "ppoll", "epoll_create1", "epoll_ctl", "epoll_pwait", "eventfd2", "futex", "set_tid_address", "set_robust_list", "rseq", "arch_prctl", "prlimit64", "sched_yield", "nanosleep", "clock_nanosleep", "clock_gettime", "gettimeofday", "getrandom", "getpid", "gettid", "getuid", "geteuid", "getgid", "getegid", "uname", "tgkill", "exit", "exit_group");
    private static final List<String> NET = sorted("connect", "getsockopt", "setsockopt", "getsockname", "getpeername", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown");
    private static final List<String> EXEC = Arrays.asList("execve", "execveat");

    private static List<String> sorted(String... xs) {
        List<String> l = new ArrayList<>(Arrays.asList(xs));
        Collections.sort(l);
        return Collections.unmodifiableList(l);
    }

    private static Map<String, Object> rule(List<String> names, Object args) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("names", new ArrayList<Object>(names));
        m.put("action", "SCMP_ACT_ALLOW");
        if (args != null) m.put("args", args);
        return m;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object o) { return (Map<String, Object>) o; }

    private static Object proxyOf(Map<String, Object> p) { return obj(p.get("net")).get("proxy"); }

    /** Docker/OCI-format seccomp profile: deny by default; network syscalls only with a proxy; {@code socket} only for AF_INET/AF_INET6; exec only when the grant names a binary. */
    public static Map<String, Object> seccompProfile(Map<String, Object> p) {
        List<Object> syscalls = new ArrayList<>();
        syscalls.add(rule(BASE, null));
        if (proxyOf(p) != null) {
            syscalls.add(rule(NET, null));
            for (long d : new long[] {2, 10}) {
                Map<String, Object> a = new LinkedHashMap<>();
                a.put("index", 0L);
                a.put("value", d);
                a.put("op", "SCMP_CMP_EQ");
                syscalls.add(rule(Collections.singletonList("socket"), new ArrayList<Object>(Collections.singletonList(a))));
            }
        }
        if (!((List<?>) obj(p.get("fs")).get("exec")).isEmpty()) syscalls.add(rule(EXEC, null));
        List<Object> arch = new ArrayList<>();
        for (String a : new String[] {"SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"}) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("architecture", a);
            m.put("subArchitectures", new ArrayList<Object>());
            arch.add(m);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("defaultAction", "SCMP_ACT_ERRNO");
        out.put("defaultErrnoRet", 1L);
        out.put("archMap", arch);
        out.put("syscalls", syscalls);
        return out;
    }

    private static List<String> prefixed(String prefix, String... xs) {
        List<String> l = new ArrayList<>();
        for (String x : xs) l.add(prefix + x);
        return l;
    }

    /** Landlock ruleset (kernel UAPI access-right names; network rules need ABI 4). Handle every right, allow only what the grant names. */
    public static Map<String, Object> landlockRuleset(Map<String, Object> p) {
        List<String> handledFs = prefixed("LANDLOCK_ACCESS_FS_", "EXECUTE", "WRITE_FILE", "READ_FILE", "READ_DIR", "REMOVE_DIR", "REMOVE_FILE", "MAKE_CHAR", "MAKE_DIR", "MAKE_REG", "MAKE_SOCK", "MAKE_FIFO", "MAKE_BLOCK", "MAKE_SYM", "REFER", "TRUNCATE");
        Map<String, Object> fsP = obj(p.get("fs"));
        List<?> read = (List<?>) fsP.get("read"), write = (List<?>) fsP.get("write"), exec = (List<?>) fsP.get("exec");
        Set<String> paths = new TreeSet<>();
        for (Object x : read) paths.add((String) x);
        for (Object x : write) paths.add((String) x);
        for (Object x : exec) paths.add((String) x);
        List<Object> fs = new ArrayList<>();
        for (String path : paths) {
            Set<String> acc = new LinkedHashSet<>();
            if (exec.contains(path)) acc.addAll(Arrays.asList("EXECUTE", "READ_FILE")); // execve opens the binary for reading
            if (read.contains(path)) acc.addAll(Arrays.asList("READ_FILE", "READ_DIR"));
            if (write.contains(path)) acc.addAll(Arrays.asList("WRITE_FILE", "TRUNCATE", "MAKE_REG", "MAKE_DIR", "REMOVE_FILE", "REMOVE_DIR"));
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("path", path);
            m.put("access", new ArrayList<Object>(prefixed("LANDLOCK_ACCESS_FS_", acc.toArray(new String[0]))));
            fs.add(m);
        }
        List<Object> net = new ArrayList<>();
        Object proxy = proxyOf(p);
        if (proxy != null) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("port", obj(proxy).get("port"));
            m.put("access", new ArrayList<Object>(Collections.singletonList("LANDLOCK_ACCESS_NET_CONNECT_TCP")));
            net.add(m);
        }
        Map<String, Object> rules = new LinkedHashMap<>();
        rules.put("fs", fs);
        rules.put("net", net);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("v", 1L);
        out.put("abi_min", 4L);
        out.put("handled_access_fs", new ArrayList<Object>(handledFs));
        out.put("handled_access_net", new ArrayList<Object>(Arrays.asList("LANDLOCK_ACCESS_NET_BIND_TCP", "LANDLOCK_ACCESS_NET_CONNECT_TCP")));
        out.put("rules", rules);
        return out;
    }

    /** macOS sandbox profile (SBPL for sandbox-exec(1)): deny by default; the base lines are what a dynamically linked binary needs to start. */
    public static String macosProfile(Map<String, Object> p) {
        List<String> lines = new ArrayList<>(Arrays.asList(
            "(version 1)", "(deny default)", "(allow sysctl-read)", "(allow process-fork)", "(allow mach-lookup)", "(allow file-read-metadata)",
            "(allow file-read* (literal \"/\") (literal \"/dev/null\") (literal \"/dev/urandom\") (subpath \"/usr/lib\") (subpath \"/System/Library\") (subpath \"/private/var/db/dyld\") (subpath \"/System/Volumes/Preboot/Cryptexes\"))"));
        Map<String, Object> fs = obj(p.get("fs"));
        for (Object x : (List<?>) fs.get("exec")) {
            lines.add("(allow process-exec (literal \"" + x + "\"))");
            lines.add("(allow file-read* (literal \"" + x + "\"))");
        }
        for (Object r : (List<?>) fs.get("read")) lines.add("(allow file-read* (subpath \"" + r + "\"))");
        for (Object w : (List<?>) fs.get("write")) lines.add("(allow file-write* (subpath \"" + w + "\"))");
        Object proxy = proxyOf(p);
        if (proxy != null) lines.add("(allow network-outbound (remote tcp \"localhost:" + JsVal.str(obj(proxy).get("port")) + "\"))");
        return String.join("\n", lines) + "\n";
    }
}
