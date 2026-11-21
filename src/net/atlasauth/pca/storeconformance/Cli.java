package net.atlasauth.pca.storeconformance;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import net.atlasauth.pca.MemoryStateStore;
import net.atlasauth.pca.PcaStateConformance;
import net.atlasauth.pca.StateStore;
import net.atlasauth.pca.StoreConformance;
import net.atlasauth.pca.doctor.Doctor;
import net.atlasauth.pca.doctor.Js;

/**
 * {@code pca-store-conformance --adapter <class|builtin:name> [options]}.
 * Exit codes: 0 pass, 1 a contract violation was found, 3 unresolved (no violation, but not every key could be decided), 2 usage / adapter error.
 */
public final class Cli {
    private Cli() {}

    /** The tests of the reference's pca-state profile (the store behind the real request guard). */
    static final List<String> ALL_PCA_STATE_TESTS = List.of("claim-burst", "claim-concurrent", "claim-durability", "one-instance", "instances", "processes", "crash-after-claim", "retry-after-timeout");

    public static final String USAGE = "pca-store-conformance --adapter <module|builtin:name> [options]\n\n"
        + "  --adapter <path>        module exporting a store adapter (default export, 'adapter' or 'createAdapter(options)')\n"
        + "                          or builtin:in-memory | builtin:durable-file | builtin:bad-* (reference adapters)\n"
        + "  --option k=v            passed to the adapter factory (repeatable)\n"
        + "  --tests a,b             subset of: " + String.join(", ", Kit.ALL_TESTS) + " (default all)\n"
        + "  --clients N             concurrent clients (default 16)\n"
        + "  --duration MS           concurrent run length (default 2000)\n"
        + "  --rounds N              same-key burst rounds (default 20)\n"
        + "  --revisit-keys N        retention run size (default 500)\n"
        + "  --processes N           crash test: client processes alive at once (default 3)\n"
        + "  --kill-every MS         crash test: SIGKILL one client process this often (default 400)\n"
        + "  --budget N              search states per key before it is UNRESOLVED (default 200000)\n"
        + "  --values N              advance tests: counter values are drawn from [0, N) (default 20)\n"
        + "  --seed N                workload PRNG seed, to reproduce a run (default random)\n"
        + "  --json                  print the report as JSON\n"
        + "  --profile pca-state     test the store behind requirePCA instead (a module exporting createPcaStateAdapter(options),\n"
        + "                          or builtin:in-memory | builtin:durable-file | builtin:bad-*); --tests then takes a subset of:\n"
        + "                          " + String.join(", ", ALL_PCA_STATE_TESTS) + "\n"
        + "                          (--rounds = race rounds, default 10; --clients = copies per round, default 16; --processes)\n\n"
        + "Exit: 0 pass, 1 violation found, 3 unresolved, 2 usage or adapter error.";

    private static double num(String flag, String v) {
        double n = v == null ? Double.NaN : Js.toNumber(v);
        if (v == null || Double.isNaN(n) || Double.isInfinite(n) || n < 0) throw new IllegalArgumentException(flag + " needs a non-negative number");
        return n;
    }

    /**
     * The parsed command line as JSON: {@code options}, {@code json}, {@code help}, {@code conf} (clients, durationMs, rounds, revisitKeys, budget,
     * values, seed, tests) and, when given, {@code adapter}, {@code profile}, {@code pcaStateTests}, {@code processes}, {@code killEveryMs}.
     */
    public static Map<String, Object> parseCli(List<String> argv) {
        Map<String, Object> a = new LinkedHashMap<>();
        Map<String, Object> options = new LinkedHashMap<>();
        Map<String, Object> conf = new LinkedHashMap<>();
        a.put("options", options);
        a.put("json", false);
        a.put("help", false);
        a.put("conf", conf);
        List<String> rawTests = null;
        for (int i = 0; i < argv.size(); i++) {
            String f = argv.get(i);
            String nx = i + 1 < argv.size() ? argv.get(i + 1) : null;
            switch (f) {
                case "--adapter": i++; a.put("adapter", nx == null ? Js.UNDEF : nx); break;
                case "--option": {
                    i++;
                    String kv = nx == null ? "" : nx;
                    int eq = kv.indexOf('=');
                    if (eq < 1) throw new IllegalArgumentException("--option needs k=v");
                    options.put(kv.substring(0, eq), kv.substring(eq + 1));
                    break;
                }
                case "--tests": {
                    i++;
                    rawTests = new ArrayList<>();
                    for (String x : (nx == null ? "" : nx).split(",", -1)) if (!x.isEmpty()) rawTests.add(x);
                    break;
                }
                case "--profile": {
                    i++;
                    if (!"pca-state".equals(nx)) throw new IllegalArgumentException("--profile: unknown profile " + (nx == null ? "undefined" : nx) + " (known: pca-state)");
                    a.put("profile", nx);
                    break;
                }
                case "--clients": i++; conf.put("clients", num(f, nx)); break;
                case "--duration": i++; conf.put("durationMs", num(f, nx)); break;
                case "--rounds": i++; conf.put("rounds", num(f, nx)); break;
                case "--revisit-keys": i++; conf.put("revisitKeys", num(f, nx)); break;
                case "--processes": i++; a.put("processes", num(f, nx)); break;
                case "--kill-every": i++; a.put("killEveryMs", num(f, nx)); break;
                case "--budget": i++; conf.put("budget", num(f, nx)); break;
                case "--values": {
                    i++;
                    double n = num(f, nx);
                    if (n != Math.rint(n) || n < 1) throw new IllegalArgumentException("--values needs a positive integer");
                    conf.put("values", n);
                    break;
                }
                case "--seed": {
                    i++;
                    double n = num(f, nx);
                    if (n != Math.rint(n)) throw new IllegalArgumentException("--seed needs a non-negative integer");
                    conf.put("seed", n);
                    break;
                }
                case "--json": a.put("json", true); break;
                case "-h": case "--help": a.put("help", true); break;
                default: throw new IllegalArgumentException("unknown argument " + f);
            }
        }
        if (rawTests != null) {
            boolean pcaState = "pca-state".equals(a.get("profile"));
            List<String> known = pcaState ? ALL_PCA_STATE_TESTS : Kit.ALL_TESTS;
            List<String> bad = new ArrayList<>();
            for (String x : rawTests) if (!known.contains(x)) bad.add(x);
            if (!bad.isEmpty() || rawTests.isEmpty()) throw new IllegalArgumentException("--tests: unknown test(s) " + (bad.isEmpty() ? "(none given)" : String.join(", ", bad)));
            if (pcaState) a.put("pcaStateTests", new ArrayList<Object>(rawTests));
            else conf.put("tests", new ArrayList<Object>(rawTests));
        }
        @SuppressWarnings("unchecked") Map<String, Object> out = (Map<String, Object>) Doctor.json(a);
        return out;
    }

    private static Integer asInt(Object o) { return o == null ? null : (int) Js.toNumber(o); }

    /** Runs the CLI and returns the exit code; {@code print} / {@code printErr} are injectable. */
    @SuppressWarnings("unchecked")
    public static int main(List<String> argv, Consumer<String> print, Consumer<String> printErr) {
        Map<String, Object> args;
        try {
            args = parseCli(argv);
        } catch (RuntimeException e) {
            printErr.accept(e.getMessage() + "\n\n" + USAGE);
            return 2;
        }
        if (Boolean.TRUE.equals(args.get("help"))) {
            print.accept(USAGE);
            return 0;
        }
        String spec = (String) args.get("adapter");
        if (spec == null) {
            printErr.accept("--adapter is required\n\n" + USAGE);
            return 2;
        }
        Map<String, String> options = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : ((Map<String, Object>) args.get("options")).entrySet()) options.put(e.getKey(), (String) e.getValue());
        if ("pca-state".equals(args.get("profile"))) return pcaState(spec, options, args, print, printErr);
        StoreAdapter adapter;
        try {
            adapter = Reference.loadAdapter(spec, options);
        } catch (Exception e) {
            printErr.accept("cannot load adapter: " + e.getMessage());
            return 2;
        }
        try {
            Map<String, Object> conf = (Map<String, Object>) args.get("conf");
            Runner.ConformanceOptions o = new Runner.ConformanceOptions();
            o.clients = asInt(conf.get("clients"));
            if (conf.get("durationMs") != null) o.durationMs = Js.toNumber(conf.get("durationMs"));
            o.rounds = asInt(conf.get("rounds"));
            o.revisitKeys = asInt(conf.get("revisitKeys"));
            o.values = asInt(conf.get("values"));
            if (conf.get("seed") != null) o.seed = (long) Js.toNumber(conf.get("seed"));
            if (conf.get("budget") != null) o.check.budget = Js.toNumber(conf.get("budget"));
            if (conf.get("tests") != null) { o.tests = new ArrayList<>(); for (Object t : (List<Object>) conf.get("tests")) o.tests.add((String) t); }
            Crash.CrashOptions crash = new Crash.CrashOptions();
            crash.adapters = () -> adapter; // every client process opens its own clients on the one shared backend
            crash.processes = asInt(args.get("processes"));
            crash.killEveryMs = asInt(args.get("killEveryMs"));
            o.crash = crash;
            Runner.ConformanceReport r = Runner.runConformance(adapter, o);
            print.accept(Boolean.TRUE.equals(args.get("json")) ? r.json() : r.format());
            return r.status.equals("pass") ? 0 : r.status.equals("fail") ? 1 : 3;
        } catch (Exception e) {
            printErr.accept("conformance run failed: " + e.getMessage());
            return 2;
        } finally {
            try { adapter.teardown(); } catch (Exception ignored) { /* best effort */ }
        }
    }

    /** The pca-state profile: {@code builtin:in-memory} or a class implementing {@link PcaStateConformance.Adapter} (or a factory of one). */
    @SuppressWarnings("unchecked")
    private static int pcaState(String spec, Map<String, String> options, Map<String, Object> args, Consumer<String> print, Consumer<String> printErr) {
        PcaStateConformance.Adapter adapter;
        try {
            if (spec.equals("builtin:in-memory")) {
                final StateStore store = new MemoryStateStore();
                adapter = new PcaStateConformance.Adapter() {
                    @Override public String name() { return "in-memory"; }
                    @Override public StateStore open() { return store; }
                };
            } else if (spec.startsWith("builtin:")) {
                throw new IllegalArgumentException("unknown built-in adapter '" + spec.substring("builtin:".length()) + "' for the pca-state profile (known: in-memory)");
            } else {
                Object inst = Class.forName(spec).getDeclaredConstructor().newInstance();
                Object made = inst instanceof Function ? ((Function<Map<String, String>, Object>) inst).apply(options) : inst;
                if (!(made instanceof PcaStateConformance.Adapter)) throw new IllegalArgumentException(spec + ": does not name a pca-state adapter");
                adapter = (PcaStateConformance.Adapter) made;
            }
        } catch (Exception e) {
            printErr.accept("cannot load adapter: " + e.getMessage());
            return 2;
        }
        try {
            Map<String, Object> conf = (Map<String, Object>) args.get("conf");
            PcaStateConformance.Options o = new PcaStateConformance.Options();
            if (conf.get("rounds") != null) o.rounds = asInt(conf.get("rounds"));
            if (conf.get("clients") != null) o.copies = asInt(conf.get("clients"));
            if (args.get("processes") != null) o.processes = asInt(args.get("processes"));
            StoreConformance.Report r = PcaStateConformance.run(adapter, o);
            if (args.get("pcaStateTests") != null) {
                List<Object> keep = (List<Object>) args.get("pcaStateTests");
                r.results.removeIf(t -> !keep.contains(t.test));
            }
            if (Boolean.TRUE.equals(args.get("json"))) {
                List<Object> rs = new ArrayList<>();
                for (StoreConformance.TestResult t : r.results) { Map<String, Object> m = new LinkedHashMap<>(); m.put("test", t.test); m.put("status", t.status); m.put("note", t.note); rs.add(m); }
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("name", r.name);
                out.put("ok", r.ok());
                out.put("results", rs);
                print.accept(net.atlasauth.pca.Json.canonicalize(out));
            } else print.accept(r.render());
            return r.ok() ? 0 : r.failures().isEmpty() ? 3 : 1;
        } catch (Exception e) {
            printErr.accept("conformance run failed: " + e.getMessage());
            return 2;
        } finally {
            try { adapter.teardown(); } catch (Exception ignored) { /* best effort */ }
        }
    }

    public static void main(String[] args) {
        System.exit(main(Arrays.asList(args), System.out::println, System.err::println));
    }
}
