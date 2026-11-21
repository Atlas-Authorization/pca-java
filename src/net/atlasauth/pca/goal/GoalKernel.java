package net.atlasauth.pca.goal;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import net.atlasauth.pca.Json;

/**
 * The proved goal kernel: typecheck, compileGoal, decideGoal, decidePolicy and renderTape run the Dafny-proved goal compiler
 * ({@code formal/dafny/Goal.dfy}), translated to Java with the pinned Dafny by {@code formal/dafny/build-native.sh java} into
 * {@code src/dafny-goal/} (compiled with the SDK sources). There is no decision logic here: token tapes are converted to the
 * translation's tokens and back, and no Dafny value crosses this boundary.
 *
 * <p>The translation is loaded by name at first use, so the SDK builds before CI has committed it; until then every call throws
 * {@link GoalKernelUnavailable} (there is no fallback). {@link #provedKernel()} plugs it into {@link GoalReview}, and
 * {@code GoalKernel::compileGoal} is the core compiler {@link GoalSelectors#compileSelGoal} takes.
 */
public final class GoalKernel {
    private GoalKernel() {}

    /** The extracted kernel is not on the class path (or does not have the expected entry points). */
    public static final class GoalKernelUnavailable extends RuntimeException {
        GoalKernelUnavailable(Throwable cause) {
            super("pca-goal: the extracted goal kernel is missing (formal/dafny/build-native.sh java writes src/dafny-goal): " + cause, cause);
        }
    }

    private static final long MAX_SAFE = 9007199254740991L;

    private static final class Gen {
        final Method mkKw, mkI, mkS, tokKind, tokKw, tokInt, tokStr, typecheck, compile, decideG, decideP, render, asUnicode, fromList;
        final Object tokType;

        Gen() throws ReflectiveOperationException {
            ClassLoader cl = GoalKernel.class.getClassLoader();
            Class<?> api = Class.forName("GoalApi.__default", true, cl);
            Class<?> seq = Class.forName("dafny.DafnySequence", true, cl);
            mkKw = st(api, "MkKw", 1); mkI = st(api, "MkI", 1); mkS = st(api, "MkS", 1);
            tokKind = st(api, "TokKind", 1); tokKw = st(api, "TokKw", 1); tokInt = st(api, "TokInt", 1); tokStr = st(api, "TokStr", 1);
            typecheck = st(api, "TypecheckT", 2); compile = st(api, "CompileT", 2); render = st(api, "RenderT", 1);
            decideG = st(api, "DecideGoalT", 4); decideP = st(api, "DecidePolicyT", 4);
            asUnicode = st(seq, "asUnicodeString", 1); fromList = st(seq, "fromList", 2);
            tokType = st(mkKw.getReturnType(), "_typeDescriptor", 0).invoke(null);
        }

        private static Method st(Class<?> c, String name, int arity) throws NoSuchMethodException {
            for (Method m : c.getMethods()) if (m.getName().equals(name) && m.getParameterCount() == arity && Modifier.isStatic(m.getModifiers())) return m;
            throw new NoSuchMethodException(c.getName() + "." + name + "/" + arity);
        }
    }

    private static volatile Gen gen;

    private static Gen gen() {
        Gen g = gen;
        if (g != null) return g;
        synchronized (GoalKernel.class) {
            if (gen == null) {
                try { gen = new Gen(); } catch (ReflectiveOperationException | LinkageError e) { throw new GoalKernelUnavailable(e); }
            }
            return gen;
        }
    }

    /** Whether the extracted kernel is loadable. */
    public static boolean available() {
        try { gen(); return true; } catch (GoalKernelUnavailable e) { return false; }
    }

    private static Object inv(Method m, Object... args) {
        try {
            return m.invoke(null, args);
        } catch (InvocationTargetException e) {
            Throwable c = e.getCause();
            if (c instanceof RuntimeException) throw (RuntimeException) c;
            throw new IllegalStateException("pca-goal: goal kernel failed: " + c, c);
        } catch (IllegalAccessException e) {
            throw new GoalKernelUnavailable(e);
        }
    }

    private static long safe(Object v) {
        Long n = G.safeInt(v);
        if (n == null || Math.abs(n) > MAX_SAFE) throw new IrError("goal tape: " + v + " is not a safe integer");
        return n;
    }

    private static Object toDafny(List<Object> tape) {
        Gen g = gen();
        List<Object> toks = new ArrayList<>(tape == null ? 0 : tape.size());
        if (tape != null) for (Object o : tape) {
            List<Object> t = G.l(o);
            if (t == null || t.size() != 2) throw new IrError("goal tape: token expected");
            Object tag = t.get(0), v = t.get(1);
            if ("k".equals(tag)) toks.add(inv(g.mkKw, BigInteger.valueOf(safe(v))));
            else if ("i".equals(tag)) toks.add(inv(g.mkI, BigInteger.valueOf(safe(v))));
            else if ("s".equals(tag)) {
                if (!(v instanceof String)) throw new IrError("goal tape: string token expected");
                toks.add(inv(g.mkS, inv(g.asUnicode, v)));
            } else throw new IrError("goal tape: unknown token tag " + tag);
        }
        return inv(g.fromList, g.tokType, toks);
    }

    private static long big(Object o) {
        try { return ((BigInteger) o).longValueExact(); } catch (ArithmeticException | ClassCastException e) { throw new IrError("malformed compiler output"); }
    }

    private static List<Object> tok(String tag, Object v) { List<Object> x = new ArrayList<>(2); x.add(tag); x.add(v); return x; }

    private static int codePoint(Object c) {
        try { return (Integer) c.getClass().getMethod("value").invoke(c); } catch (ReflectiveOperationException | ClassCastException e) { throw new GoalKernelUnavailable(e); }
    }

    private static List<Object> fromDafny(Object seq) {
        Gen g = gen();
        if (!(seq instanceof Iterable)) throw new GoalKernelUnavailable(new ClassCastException("Dafny sequence is not Iterable"));
        List<Object> out = new ArrayList<>();
        for (Object t : (Iterable<?>) seq) {
            long kind = big(inv(g.tokKind, t));
            if (kind == 0) out.add(tok("k", new Json.Num(Long.toString(big(inv(g.tokKw, t))))));
            else if (kind == 1) out.add(tok("i", new Json.Num(Long.toString(big(inv(g.tokInt, t))))));
            else {
                StringBuilder sb = new StringBuilder();
                for (Object c : (Iterable<?>) inv(g.tokStr, t)) sb.appendCodePoint(codePoint(c));
                out.add(tok("s", sb.toString()));
            }
        }
        return out;
    }

    /**
     * One proved entry point over token tapes: op in typecheck, compile, decideg, decidep, render (act and hist are read by the
     * decide ops). First output token: i0 ok, i1 rejected with reasons, i9 malformed input.
     */
    public static List<Object> call(String op, List<Object> goal, List<Object> ont, List<Object> act, List<Object> hist) {
        // The Dafny runtime's lazy Seq concatenation and the generated recursion use the JVM stack; run on a thread with a large one
        // so a huge string cannot overflow it (the JS runtime's Seq.Concat had that failure; this is the same guard here).
        Object[] box = new Object[2];
        Thread t = new Thread(null, () -> {
            try { box[0] = callHere(op, goal, ont, act, hist); } catch (Throwable e) { box[1] = e; }
        }, "pca-goal-kernel", 1L << 29);
        t.start();
        try { t.join(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException(e); }
        if (box[1] instanceof RuntimeException) throw (RuntimeException) box[1];
        if (box[1] instanceof Error) throw (Error) box[1];
        if (box[1] != null) throw new IllegalStateException((Throwable) box[1]);
        @SuppressWarnings("unchecked") List<Object> out = (List<Object>) box[0];
        return out;
    }

    private static List<Object> callHere(String op, List<Object> goal, List<Object> ont, List<Object> act, List<Object> hist) {
        Gen g = gen();
        switch (op) {
            case "typecheck": return fromDafny(inv(g.typecheck, toDafny(goal), toDafny(ont)));
            case "compile": return fromDafny(inv(g.compile, toDafny(goal), toDafny(ont)));
            case "render": return fromDafny(inv(g.render, toDafny(goal)));
            case "decideg": return fromDafny(inv(g.decideG, toDafny(goal), toDafny(ont), toDafny(act), toDafny(hist)));
            case "decidep": return fromDafny(inv(g.decideP, toDafny(goal), toDafny(ont), toDafny(act), toDafny(hist)));
            default: throw new IllegalArgumentException("goal kernel: unknown op " + op);
        }
    }

    // ---- the typed front door (compiler.ts) ----

    private static long first(List<Object> t) {
        List<Object> x = t.isEmpty() ? null : G.l(t.get(0));
        if (x == null || !"i".equals(x.get(0))) throw new IrError("malformed compiler output");
        return safe(x.get(1));
    }

    private static long at(List<Object> t, int i) { return safe(G.l(t.get(i)).get(1)); }

    private static String str(Object tok) { List<Object> x = G.l(tok); return "s".equals(x.get(0)) ? (String) x.get(1) : ""; }

    private static List<String> reasons(List<Object> t) {
        int n = t.size() > 1 ? (int) at(t, 1) : 0;
        List<String> out = new ArrayList<>();
        for (Object x : t.subList(2, 2 + n)) out.add(str(x));
        return out;
    }

    private static String decision(long n) { return n == 2 ? "allow" : n == 1 ? "escalate" : "deny"; }

    /** Type reasons of a goal against an ontology; empty = well typed. */
    public static List<String> typecheck(Map<String, Object> goal, Map<String, Object> ont) {
        List<Object> out = call("typecheck", GoalCodec.encodeGoal(goal), GoalCodec.encodeOntology(ont), null, null);
        long s = first(out);
        if (s == 0) return new ArrayList<>();
        if (s == 1) return reasons(out);
        throw new IrError("compiler rejected the input tape");
    }

    /** C: Goal -&gt; {ok: true, policy} | {ok: false, reasons}. Ill-typed goals are rejected, never coerced. */
    public static Map<String, Object> compileGoal(Map<String, Object> goal, Map<String, Object> ont) {
        List<Object> out = call("compile", GoalCodec.encodeGoal(goal), GoalCodec.encodeOntology(ont), null, null);
        long s = first(out);
        Map<String, Object> r = new LinkedHashMap<>();
        if (s == 0) { r.put("ok", true); r.put("policy", GoalCodec.decodePolicy(new ArrayList<>(out.subList(1, out.size())))); return r; }
        if (s == 1) { r.put("ok", false); r.put("reasons", new ArrayList<Object>(reasons(out))); return r; }
        throw new IrError("compiler rejected the input tape");
    }

    /** The reference semantics D_G(a, H): "allow" | "escalate" | "deny". */
    public static String decideGoal(Map<String, Object> goal, Map<String, Object> ont, Map<String, Object> act, Map<String, Object> hist) {
        List<Object> out = call("decideg", GoalCodec.encodeGoal(goal), GoalCodec.encodeOntology(ont), GoalCodec.encodeAct(act), GoalCodec.encodeHist(hist));
        if (first(out) != 0) throw new IrError("compiler rejected the input tape");
        return decision(at(out, 1));
    }

    /** The compiled policy's decision: {ok: false, reasons} | {ok: true, decision, witness (null unless allow), witnessChecked}. */
    public static Map<String, Object> decidePolicy(Map<String, Object> goal, Map<String, Object> ont, Map<String, Object> act, Map<String, Object> hist) {
        List<Object> out = call("decidep", GoalCodec.encodeGoal(goal), GoalCodec.encodeOntology(ont), GoalCodec.encodeAct(act), GoalCodec.encodeHist(hist));
        long s = first(out);
        Map<String, Object> r = new LinkedHashMap<>();
        if (s == 1) { r.put("ok", false); r.put("reasons", new ArrayList<Object>(reasons(out))); return r; }
        if (s != 0) throw new IrError("compiler rejected the input tape");
        String d = decision(at(out, 1));
        int n = (int) at(out, 3);
        List<Object> bids = new ArrayList<>();
        for (Object x : out.subList(4, 4 + n)) bids.add(str(x));
        Map<String, Object> w = null;
        if (d.equals("allow")) { w = new LinkedHashMap<>(); w.put("gid", str(out.get(2))); w.put("bids", bids); }
        r.put("ok", true); r.put("decision", d); r.put("witness", w); r.put("witnessChecked", at(out, 4 + n) == 1);
        return r;
    }

    /** The card as a token tape (GoalRender.Render): {@code GoalCodec.decodeGoal(renderTape(g))} equals g. */
    public static List<Object> renderTape(Map<String, Object> goal) {
        List<Object> out = call("render", GoalCodec.encodeGoal(goal), null, null, null);
        if (first(out) != 0) throw new IrError("goal tape rejected");
        return new ArrayList<>(out.subList(1, out.size()));
    }

    /** The review kernel of the reference ({@code provedKernel}): compile, policy digest and the reference decision. */
    public static GoalReview.ReviewKernel provedKernel() {
        return new GoalReview.ReviewKernel() {
            @Override public Map<String, Object> compile(Map<String, Object> goal, Map<String, Object> ont) { return compileGoal(goal, ont); }
            @Override public String policyDigest(Map<String, Object> policy) { return GoalCompiler.policyDigest(policy); }
            @Override public boolean canDecide() { return true; }
            @Override public String decide(Map<String, Object> goal, Map<String, Object> ont, Map<String, Object> act, Map<String, Object> hist) { return decideGoal(goal, ont, act, hist); }
        };
    }

    // ---- harness text syntax (kN, iN, s<hex>.<hex>...) ----

    /** A tape in the differential-harness syntax. */
    public static String tapeToText(List<Object> tape) {
        StringBuilder sb = new StringBuilder();
        for (Object o : tape) {
            List<Object> t = G.l(o);
            if (sb.length() > 0) sb.append(' ');
            if ("s".equals(t.get(0))) {
                sb.append('s');
                String s = (String) t.get(1);
                boolean firstCp = true;
                for (int i = 0; i < s.length(); ) {
                    int cp = s.codePointAt(i);
                    if (!firstCp) sb.append('.');
                    sb.append(Integer.toHexString(cp));
                    firstCp = false;
                    i += Character.charCount(cp);
                }
            } else sb.append(t.get(0)).append(safe(t.get(1)));
        }
        return sb.toString();
    }

    /** Parse the differential-harness syntax. */
    public static List<Object> tapeFromText(String s) {
        List<Object> out = new ArrayList<>();
        for (String x : s.split(" ")) {
            if (x.isEmpty()) continue;
            String b = x.substring(1);
            char c = x.charAt(0);
            if (c == 'k' || c == 'i') out.add(tok(String.valueOf(c), new Json.Num(Long.toString(Long.parseLong(b)))));
            else if (c == 's') {
                StringBuilder sb = new StringBuilder();
                if (!b.isEmpty()) for (String h : b.split("\\.")) sb.appendCodePoint(Integer.parseInt(h, 16));
                out.add(tok("s", sb.toString()));
            } else throw new IrError("goal tape text: bad token " + x);
        }
        return out;
    }
}
