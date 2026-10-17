package net.atlasauth.pca;

import static org.junit.jupiter.api.Assertions.*;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.zip.GZIPInputStream;
import org.junit.jupiter.api.Test;

/**
 * Differential kill test for the 0.4.2 SafeRegex.java mutation survivors: every pattern of a TS-generated corpus
 * (tools/pca-audit/java-mutate/k042-saferegex-oracle.mjs over packages/pca/src/safe-regex.ts + predicates.ts) must
 * compile to the EXACT same NFA program (op, x, y, set ranges, negation, instruction for instruction) or be refused
 * alike, get the same isSafeRegexSource verdict, and full-match every recorded subject with the same true / false / null.
 */
class K042SafeRegexOracleTest {
    private static Field PROGRAM, OP, X, Y, SET;

    static String dump(SafeRegex.Compiled c) throws Exception {
        if (PROGRAM == null) {
            PROGRAM = SafeRegex.Compiled.class.getDeclaredField("program");
            PROGRAM.setAccessible(true);
            Class<?> inst = PROGRAM.getType().getComponentType();
            OP = inst.getDeclaredField("op"); OP.setAccessible(true);
            X = inst.getDeclaredField("x"); X.setAccessible(true);
            Y = inst.getDeclaredField("y"); Y.setAccessible(true);
            SET = inst.getDeclaredField("set"); SET.setAccessible(true);
        }
        Object[] prog = (Object[]) PROGRAM.get(c);
        assertEquals(prog.length, c.size(), "Compiled.size()");
        StringBuilder sb = new StringBuilder();
        for (int k = 0; k < prog.length; k++) {
            Object ins = prog[k];
            if (k > 0) sb.append(';');
            sb.append(OP.getInt(ins)).append(',').append(X.getInt(ins)).append(',').append(Y.getInt(ins)).append(',');
            SafeRegex.CharSet cs = (SafeRegex.CharSet) SET.get(ins);
            if (cs == null) { sb.append("-,-"); continue; }
            sb.append(cs.negated ? 1 : 0).append(',');
            if (cs.ranges.length == 0) sb.append('E');
            for (int r = 0; r < cs.ranges.length; r++) {
                if (r > 0) sb.append(':');
                assertEquals(2, cs.ranges[r].length);
                sb.append(cs.ranges[r][0]).append('-').append(cs.ranges[r][1]);
            }
        }
        String s = sb.toString();
        if (s.length() > 1000) s = "H" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        return s;
    }

    static String unhex(String h) {
        if (h.equals("-")) return "";
        StringBuilder sb = new StringBuilder();
        for (int k = 0; k < h.length(); k += 4) sb.append((char) Integer.parseInt(h.substring(k, k + 4), 16));
        return sb.toString();
    }

    static String show(String s) {
        StringBuilder sb = new StringBuilder();
        for (char ch : s.toCharArray()) sb.append(ch >= 0x20 && ch < 0x7f ? String.valueOf(ch) : String.format("\\u%04x", (int) ch));
        return sb.length() > 80 ? sb.substring(0, 80) + "...(" + s.length() + ")" : sb.toString();
    }

    @Test
    void corpusMatchesTheTsReference() throws Exception {
        List<String> fails = new ArrayList<>();
        int patterns = 0, compiled = 0, safe = 0, matches = 0;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(
                new GZIPInputStream(Files.newInputStream(Path.of("test-data/k042-saferegex.txt.gz"))), StandardCharsets.UTF_8))) {
            String line;
            String pat = null;
            SafeRegex.Compiled cur = null;
            boolean firstSubject = false;
            while ((line = r.readLine()) != null) {
                String[] f = line.split(" ");
                if (f[0].equals("P")) {
                    patterns++;
                    pat = unhex(f[1]);
                    boolean wantSafe = f[2].equals("1");
                    String wantProg = f[3];
                    cur = SafeRegex.compile(pat);
                    String got = cur == null ? "N" : dump(cur);
                    if (cur != null) compiled++;
                    if (!got.equals(wantProg)) fails.add("compile /" + show(pat) + "/: want " + abbrev(wantProg) + " got " + abbrev(got));
                    boolean gotSafe = SafeRegex.isSafeSource(pat);
                    if (gotSafe) safe++;
                    if (gotSafe != wantSafe) fails.add("isSafeSource /" + show(pat) + "/: want " + wantSafe + " got " + gotSafe);
                    if (cur == null && SafeRegex.fullMatch(pat, "a") != null) fails.add("fullMatch on refused /" + show(pat) + "/ not null");
                    firstSubject = true;
                } else {
                    matches++;
                    String subj = unhex(f[1]);
                    Boolean want = f[2].equals("N") ? null : f[2].equals("T");
                    if (cur == null) { fails.add("subject for a refused pattern /" + show(pat) + "/"); continue; }
                    Boolean got = SafeRegex.run(cur, subj);
                    if (want != got && (want == null || !want.equals(got)))
                        fails.add("run /" + show(pat) + "/ on \"" + show(subj) + "\": want " + want + " got " + got);
                    if (firstSubject) {
                        Boolean fm = SafeRegex.fullMatch(pat, subj);
                        if (want != fm && (want == null || !want.equals(fm)))
                            fails.add("fullMatch /" + show(pat) + "/ on \"" + show(subj) + "\": want " + want + " got " + fm);
                        firstSubject = false;
                    }
                }
                if (fails.size() >= 3) break; // fail fast (mutation runs)
            }
        }
        if (!fails.isEmpty()) fail(fails.size() + " differences, first: \n" + String.join("\n", fails.subList(0, Math.min(40, fails.size()))));
        // corpus sanity (the generator's own counts): a truncated / regenerated-differently file must not pass silently
        assertEquals(8648, patterns);
        assertEquals(5267, compiled);
        assertEquals(3206, safe);
        assertEquals(572525, matches);
    }

    private static String abbrev(String s) { return s.length() > 160 ? s.substring(0, 160) + "..." : s; }
}
