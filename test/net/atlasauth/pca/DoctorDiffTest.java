package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.doctor.Doctor;
import net.atlasauth.pca.doctor.Doctor.CheckResult;
import org.junit.jupiter.api.Test;

/** Replays the reference oracle for the deployment doctor (see the oracle header for the fake fetch / clock / library tables). */
class DoctorDiffTest {
    private static final String MODULE = "ref-doctor";
    private static final String URL1 = "https://api.example.com";

    @SuppressWarnings("unchecked") private static Map<String, Object> m(Object o) { return (Map<String, Object>) o; }
    @SuppressWarnings("unchecked") private static List<Object> l(Object o) { return (List<Object>) o; }
    private static long lng(Object o) { return Long.parseLong(o.toString()); }

    /** The fake fetch + clock: each call pops the next response of its URL (the last repeats), advances the clock by rtt before answering. */
    private static final class Env {
        long t;
        final Map<String, Object> responses;
        final Map<String, Integer> idx = new HashMap<>();
        final Doctor.Fetch fetch;
        Env(Object spec) { t = lng(m(spec).get("now")); responses = m(m(spec).get("responses")); fetch = fetchOf(); }
        private Doctor.Fetch fetchOf() { return (method, url, headers, timeoutMs) -> {
            Object lst = responses.get(url);
            if (lst == null) throw new Exception("no route " + url);
            List<Object> rs = l(lst);
            int i = idx.getOrDefault(url, 0);
            idx.put(url, i + 1);
            Map<String, Object> r = m(rs.get(Math.min(i, rs.size() - 1)));
            if (r.get("rtt") != null) t += lng(r.get("rtt"));
            if (r.get("throw") != null) throw new Exception((String) r.get("throw"));
            return new Doctor.Response() {
                @Override public int status() { return 200; }
                @Override public String header(String n) { return n.equals("date") ? (String) r.get("date") : n.equals("ratelimit-remaining") ? (String) r.get("rl") : null; }
            };
        }; }
        long now() { return t; }
    }

    private static Doctor.Decision allowed(boolean a, String... reasons) { return new Doctor.Decision(a, new ArrayList<>(List.of(reasons))); }

    /** The named fake library: behaviours enforce | ignore-max | ignore-unknown | deny-all | throws | nonarray-reasons | allow-all. */
    private static java.util.function.Function<String, Doctor.LoadedPca> loader(Object specO) {
        Map<String, Object> spec = m(specO);
        return dir -> {
            if (spec.get("throws") != null) throw new RuntimeException((String) spec.get("throws"));
            String behavior = (String) spec.get("behavior");
            Doctor.Probe p = (cav, amount) -> {
                if (behavior.equals("throws")) throw new Exception("boom");
                if (behavior.equals("allow-all")) return allowed(true);
                if (behavior.equals("deny-all")) return allowed(false, "denied", "7");
                if (behavior.equals("nonarray-reasons")) return allowed(false);
                if (cav.get("type").equals("max_spend")) {
                    if (behavior.equals("ignore-max")) return allowed(true);
                    return amount <= Double.parseDouble(cav.get("usd").toString()) ? allowed(true) : allowed(false, "over max_spend");
                }
                return behavior.equals("ignore-unknown") ? allowed(true) : allowed(false, "unknown caveat type");
            };
            return new Doctor.LoadedPca((String) spec.get("version"), (String) spec.get("path"), p);
        };
    }

    private static Map<String, Object> cfg(Object o) { return m(o); }
    private static List<CheckResult> results(Object o) {
        List<CheckResult> out = new ArrayList<>();
        for (Object x : l(o)) out.add(CheckResult.fromJson(m(x)));
        return out;
    }
    private static Map<String, String> strEnv(Object o) {
        Map<String, String> e = new LinkedHashMap<>();
        for (Map.Entry<String, Object> en : m(o).entrySet()) e.put(en.getKey(), (String) en.getValue());
        return e;
    }
    private static List<String> strs(Object o) { List<String> r = new ArrayList<>(); for (Object x : l(o)) r.add((String) x); return r; }
    private static Object out(List<CheckResult> rs) { List<Object> o = new ArrayList<>(); for (CheckResult r : rs) o.add(r.toJson()); return o; }

    @Test void consts() throws Exception {
        OracleCases.each(MODULE, "consts", a -> {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("USAGE", Doctor.USAGE);
            o.put("CHECK_GROUPS", new ArrayList<Object>(Doctor.CHECK_GROUPS));
            o.put("DEFAULT_REQUIRED", new ArrayList<Object>(Doctor.DEFAULT_REQUIRED));
            o.put("ROOT_CAVEAT_MIN_VERSION", Doctor.ROOT_CAVEAT_MIN_VERSION);
            o.put("DEFAULT_REFERENCE_URL", Doctor.DEFAULT_REFERENCE_URL);
            o.put("SUITES_REMEDIATION", Doctor.SUITES_REMEDIATION);
            o.put("PQ_REMEDIATION", Doctor.PQ_REMEDIATION);
            o.put("CLOCK_REMEDIATION", Doctor.CLOCK_REMEDIATION);
            o.put("PROXY_REMEDIATION", Doctor.PROXY_REMEDIATION);
            o.put("ATOMICITY_REMEDIATION", Doctor.ATOMICITY_REMEDIATION);
            o.put("DURABILITY_REMEDIATION", Doctor.DURABILITY_REMEDIATION);
            o.put("CAVEAT_REMEDIATION", Doctor.CAVEAT_REMEDIATION);
            return o;
        });
    }

    @Test void scrubText() throws Exception { OracleCases.each(MODULE, "scrubText", a -> Doctor.scrubText(a.get(0))); }
    @Test void scrubDeep() throws Exception { OracleCases.each(MODULE, "scrubDeep", a -> Doctor.scrubDeep(a.get(0))); }
    @Test void checkAllowedSuites() throws Exception { OracleCases.each(MODULE, "checkAllowedSuites", a -> Doctor.checkAllowedSuites(cfg(a.get(0))).toJson()); }
    @Test void checkPqBinding() throws Exception { OracleCases.each(MODULE, "checkPqBinding", a -> Doctor.checkPqBinding(cfg(a.get(0))).toJson()); }
    @Test void checkProxyConfig() throws Exception { OracleCases.each(MODULE, "checkProxyConfig", a -> Doctor.checkProxyConfig(cfg(a.get(0))).toJson()); }
    @Test void testNetIp() throws Exception { OracleCases.each(MODULE, "testNetIp", a -> Doctor.testNetIp(Doctor.mulberry32(lng(a.get(0))))); }
    @Test void forgedHeaders() throws Exception { OracleCases.each(MODULE, "forgedHeaders", a -> Doctor.forgedHeaders(Doctor.mulberry32(lng(a.get(0))))); }

    @Test void checkClock() throws Exception {
        OracleCases.each(MODULE, "checkClock", a -> { Env e = new Env(a.get(1)); return Doctor.checkClock(cfg(a.get(0)), e.fetch, e::now).toJson(); });
    }

    @Test void readDate() throws Exception {
        OracleCases.each(MODULE, "readDate", a -> { Env e = new Env(a.get(1)); return Doctor.readDate(URL1, e.fetch, e::now, 1000).toJson(); });
    }

    @Test void checkProxyProbe() throws Exception {
        OracleCases.each(MODULE, "checkProxyProbe", a -> { Env e = new Env(a.get(1)); return Doctor.checkProxyProbe(cfg(a.get(0)), e.fetch, Doctor.mulberry32(7)).toJson(); });
    }

    @Test void compareVersion() throws Exception { OracleCases.each(MODULE, "compareVersion", a -> Doctor.compareVersion((String) a.get(0), (String) a.get(1))); }
    @Test void checkRootCaveats() throws Exception { OracleCases.each(MODULE, "checkRootCaveats", a -> Doctor.checkRootCaveats(cfg(a.get(0)), loader(a.get(1))).toJson()); }
    @Test void checkEnforcement() throws Exception { OracleCases.each(MODULE, "checkEnforcement", a -> Doctor.checkEnforcement(cfg(a.get(0))).toJson()); }
    @Test void configProblems() throws Exception { OracleCases.each(MODULE, "configProblems", a -> new ArrayList<Object>(Doctor.configProblems(cfg(a.get(0))))); }
    @Test void verdictOf() throws Exception { OracleCases.each(MODULE, "verdictOf", a -> Doctor.verdictOf(results(a.get(0)), a.size() > 1 && Boolean.TRUE.equals(a.get(1)))); }

    @Test void formatResults() throws Exception {
        OracleCases.each(MODULE, "formatResults", a -> Doctor.formatResults(results(a.get(0)), (String) a.get(1), Boolean.TRUE.equals(a.get(2))));
    }

    @Test void configFromEnv() throws Exception { OracleCases.each(MODULE, "configFromEnv", a -> Doctor.json(Doctor.configFromEnv(strEnv(a.get(0))))); }

    @Test void mergeConfig() throws Exception {
        OracleCases.each(MODULE, "mergeConfig", a -> { List<Map<String, Object>> cs = new ArrayList<>(); for (Object x : a) cs.add(m(x)); return Doctor.json(Doctor.mergeConfig(cs)); });
    }

    @Test void parseDoctorArgs() throws Exception { OracleCases.each(MODULE, "parseDoctorArgs", a -> Doctor.json(Doctor.parseDoctorArgs(strs(a.get(0))))); }

    @Test void main() throws Exception {
        OracleCases.each(MODULE, "main", a -> {
            List<Object> o = new ArrayList<>(), er = new ArrayList<>();
            int code = Doctor.main(strs(a.get(0)), strEnv(a.get(1)), o::add, er::add, null);
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("code", code);
            r.put("out", o);
            r.put("err", er);
            return r;
        });
    }

    @Test void runDoctor() throws Exception {
        OracleCases.each(MODULE, "runDoctor", a -> {
            Env e = new Env(a.get(2));
            Doctor.DoctorDeps d = new Doctor.DoctorDeps();
            d.fetch = e.fetch;
            d.now = e::now;
            d.loadPca = loader(a.get(3));
            return out(Doctor.runDoctor(cfg(a.get(0)), a.get(1) == null ? null : strs(a.get(1)), d));
        });
    }
}
