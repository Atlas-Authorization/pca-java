package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The linear-time, budgeted regular-expression matcher of the predicate DSL ({@code re:} resources and the
 * {@code matches} operator), a port of packages/pca/src/safe-regex.ts and regex-budget.ts.
 *
 * <p>A pattern is parsed ONCE by this parser into a Thompson NFA and run by a Pike-style simulation: O(|subject| x |NFA|),
 * no backtracking. SUBSET (anything else is refused, fail closed): literals; {@code .} (not a line terminator); classes
 * {@code [...]} / {@code [^...]} incl. {@code []} (nothing) and {@code [^]} (any code unit), ranges and
 * {@code \d \D \w \W \s \S} inside them; escapes {@code \d \D \w \W \s \S \t \n \v \f \r \0 \xHH \}{@code uHHHH \cX} and
 * escaped punctuation; groups {@code ( )} and {@code (?: )}; alternation; quantifiers {@code * + ? {n} {n,} {n,m}} with an
 * optional lazy {@code ?}; anchors {@code ^ $}. Matching is over UTF-16 code units, exactly like a flagless JS RegExp.
 *
 * <p>The per-document work budget ({@link #withBudget}, {@link #charge}) caps regex evaluations, source characters and NFA
 * steps for one predicate evaluation (64 / 8192 / 5,000,000), poisoning itself on the first refusal.
 */
public final class SafeRegex {
    private SafeRegex() {}

    public static final int MAX_NFA_INSTRUCTIONS = 4096;
    public static final int MAX_REPEAT = 64;
    public static final long MAX_MATCH_STEPS = 2_000_000L;
    public static final int MAX_REGEX_EVALUATIONS_PER_DOCUMENT = 64;
    public static final int MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT = 8192;
    public static final long MAX_REGEX_STEPS_PER_DOCUMENT = 5_000_000L;

    private static final int SET = 0, SPLIT = 1, JMP = 2, BOL = 3, EOL = 4, MATCH = 5;

    /** A set of UTF-16 code units: sorted, merged ranges, optionally negated. */
    static final class CharSet {
        final int[][] ranges;
        final boolean negated;
        CharSet(int[][] ranges, boolean negated) { this.ranges = ranges; this.negated = negated; }
        boolean has(int c) {
            int lo = 0, hi = ranges.length - 1;
            boolean inside = false;
            while (lo <= hi) {
                int mid = (lo + hi) >> 1;
                int[] r = ranges[mid];
                if (c < r[0]) hi = mid - 1;
                else if (c > r[1]) lo = mid + 1;
                else { inside = true; break; }
            }
            return inside != negated;
        }
    }

    private static final int[][] DIGIT = {{0x30, 0x39}};
    private static final int[][] WORD = {{0x30, 0x39}, {0x41, 0x5a}, {0x5f, 0x5f}, {0x61, 0x7a}};
    private static final int[][] SPACE = {{0x09, 0x0d}, {0x20, 0x20}, {0xa0, 0xa0}, {0x1680, 0x1680}, {0x2000, 0x200a},
        {0x2028, 0x2029}, {0x202f, 0x202f}, {0x205f, 0x205f}, {0x3000, 0x3000}, {0xfeff, 0xfeff}};
    private static final int[][] LINE_TERMINATORS = {{0x0a, 0x0a}, {0x0d, 0x0d}, {0x2028, 0x2029}};

    static int[][] normalize(List<int[]> in) {
        List<int[]> s = new ArrayList<>();
        for (int[] r : in) s.add(new int[] {r[0], r[1]});
        s.sort((a, b) -> Integer.compare(a[0], b[0]));
        List<int[]> out = new ArrayList<>();
        for (int[] r : s) {
            int[] last = out.isEmpty() ? null : out.get(out.size() - 1);
            if (last != null && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]);
            else out.add(new int[] {r[0], r[1]});
        }
        return out.toArray(new int[0][]);
    }

    static int[][] complement(int[][] r) {
        List<int[]> out = new ArrayList<>();
        int next = 0;
        for (int[] ab : normalize(Arrays.asList(r))) {
            if (ab[0] > next) out.add(new int[] {next, ab[0] - 1});
            next = ab[1] + 1;
        }
        if (next <= 0xffff) out.add(new int[] {next, 0xffff});
        return out.toArray(new int[0][]);
    }

    // ---- AST ----
    private static final class Node {
        final char k; // 's' set, '^' bol, '$' eol, 'c' cat, 'a' alt, 'r' rep
        CharSet set;
        List<Node> items;
        Node node;
        int min;
        double max; // Infinity for unbounded
        Node(char k) { this.k = k; }
    }

    private static final class Refuse extends RuntimeException {
        Refuse(String m) { super(m, null, false, false); }
    }

    private static final Pattern QUANT = Pattern.compile("^\\{(\\d{1,4})(?:(,)(\\d{0,4}))?\\}");

    private static final class Parser {
        final String s;
        int i = 0;
        Parser(String s) { this.s = s; }
        /** {@code s[i]} as a code unit, or -1 past the end (JS undefined). */
        int at(int k) { return k < s.length() ? s.charAt(k) : -1; }

        Node parse() {
            Node n = alt();
            if (i < s.length()) throw new Refuse("unbalanced )");
            return n;
        }

        Node alt() {
            List<Node> items = new ArrayList<>();
            items.add(cat());
            while (at(i) == '|') { i++; items.add(cat()); }
            if (items.size() == 1) return items.get(0);
            Node n = new Node('a');
            n.items = items;
            return n;
        }

        Node cat() {
            List<Node> items = new ArrayList<>();
            while (i < s.length() && s.charAt(i) != '|' && s.charAt(i) != ')') items.add(quantified());
            Node n = new Node('c');
            n.items = items;
            return n;
        }

        Node quantified() {
            Node atom = atom();
            int c = at(i);
            int min;
            double max;
            if (c == '*') { min = 0; max = Double.POSITIVE_INFINITY; i++; }
            else if (c == '+') { min = 1; max = Double.POSITIVE_INFINITY; i++; }
            else if (c == '?') { min = 0; max = 1; i++; }
            else if (c == '{') {
                Matcher m = QUANT.matcher(s.substring(i, Math.min(s.length(), i + 16)));
                if (!m.find()) throw new Refuse("{ is not a well-formed quantifier");
                min = Integer.parseInt(m.group(1));
                max = m.group(2) == null ? min : m.group(3).isEmpty() ? Double.POSITIVE_INFINITY : Integer.parseInt(m.group(3));
                if (max < min) throw new Refuse("quantifier range out of order");
                i += m.group(0).length();
            } else return atom;
            if (atom.k == '^' || atom.k == '$') throw new Refuse("nothing to repeat (assertion)");
            if ((max != Double.POSITIVE_INFINITY && max > MAX_REPEAT) || min > MAX_REPEAT) throw new Refuse("repeat bound too large");
            if (at(i) == '?') i++;
            Node n = new Node('r');
            n.node = atom;
            n.min = min;
            n.max = max;
            return n;
        }

        Node set(CharSet cs) { Node n = new Node('s'); n.set = cs; return n; }

        Node atom() {
            char c = s.charAt(i);
            switch (c) {
                case '(': {
                    i++;
                    if (at(i) == '?') {
                        if (at(i + 1) != ':') throw new Refuse("lookaround / named groups are not supported");
                        i += 2;
                    }
                    Node n = alt();
                    if (at(i) != ')') throw new Refuse("unterminated group");
                    i++;
                    return n;
                }
                case '[': return cls();
                case '.': i++; return set(new CharSet(LINE_TERMINATORS, true));
                case '^': i++; return new Node('^');
                case '$': i++; return new Node('$');
                case '\\': return set(escapeInner(false).set);
                case '*': case '+': case '?': throw new Refuse("nothing to repeat");
                case '{': throw new Refuse("{ is not a well-formed quantifier");
                default:
                    i++;
                    return set(new CharSet(new int[][] {{c, c}}, false));
            }
        }

        /** After a backslash: the set, whether it is a class escape, and its single code unit (or -1). */
        final class Esc {
            final CharSet set; final boolean cls; final int ch;
            Esc(CharSet set, boolean cls, int ch) { this.set = set; this.cls = cls; this.ch = ch; }
        }
        Esc single(int code) { return new Esc(new CharSet(new int[][] {{code, code}}, false), false, code); }

        Esc escapeInner(boolean inClass) {
            i++;
            int c = at(i);
            if (c < 0) throw new Refuse("trailing backslash");
            i++;
            switch (c) {
                case 'd': return new Esc(new CharSet(DIGIT, false), true, -1);
                case 'D': return new Esc(new CharSet(DIGIT, true), true, -1);
                case 'w': return new Esc(new CharSet(WORD, false), true, -1);
                case 'W': return new Esc(new CharSet(WORD, true), true, -1);
                case 's': return new Esc(new CharSet(SPACE, false), true, -1);
                case 'S': return new Esc(new CharSet(SPACE, true), true, -1);
                case 't': return single(9);
                case 'n': return single(10);
                case 'v': return single(11);
                case 'f': return single(12);
                case 'r': return single(13);
                case '0': {
                    int n = at(i);
                    if (n >= '0' && n <= '9') throw new Refuse("octal escape");
                    return single(0);
                }
                case 'x': {
                    if (i + 2 > s.length() || !isHex(s, i, 2)) throw new Refuse("bad \\x escape");
                    int v = Integer.parseInt(s.substring(i, i + 2), 16);
                    i += 2;
                    return single(v);
                }
                case 'u': {
                    if (i + 4 > s.length() || !isHex(s, i, 4)) throw new Refuse("bad \\u escape");
                    int v = Integer.parseInt(s.substring(i, i + 4), 16);
                    i += 4;
                    return single(v);
                }
                case 'c': {
                    int l = at(i);
                    if (!((l >= 'A' && l <= 'Z') || (l >= 'a' && l <= 'z'))) throw new Refuse("bad \\c escape");
                    i++;
                    return single(l % 32);
                }
                case 'b':
                    if (inClass) return single(8);
                    throw new Refuse("word-boundary assertions are not supported");
                default:
                    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')
                        throw new Refuse("escape \\" + (char) c + " is not supported");
                    return single(c);
            }
        }

        Node cls() {
            i++;
            boolean negated = false;
            if (at(i) == '^') { negated = true; i++; }
            List<int[]> ranges = new ArrayList<>();
            while (true) {
                int c = at(i);
                if (c < 0) throw new Refuse("unterminated class");
                if (c == ']') { i++; break; }
                Esc a = readAtom();
                if (at(i) == '-' && at(i + 1) >= 0 && at(i + 1) != ']') {
                    i++;
                    Esc b = readAtom();
                    if (a.cls || b.cls) {
                        for (int[] r : a.set.ranges) ranges.add(new int[] {r[0], r[1]});
                        ranges.add(new int[] {0x2d, 0x2d});
                        for (int[] r : b.set.ranges) ranges.add(new int[] {r[0], r[1]});
                    } else {
                        if (a.ch > b.ch) throw new Refuse("class range out of order");
                        ranges.add(new int[] {a.ch, b.ch});
                    }
                } else {
                    for (int[] r : a.set.ranges) ranges.add(new int[] {r[0], r[1]});
                }
            }
            Node n = new Node('s');
            n.set = new CharSet(normalize(ranges), negated);
            return n;
        }

        /** A class atom; its {@code set} holds plain (already complemented) ranges. */
        Esc readAtom() {
            int c = s.charAt(i);
            if (c == '\\') {
                Esc e = escapeInner(true);
                int[][] rs = e.set.negated ? complement(e.set.ranges) : e.set.ranges;
                return new Esc(new CharSet(rs, false), e.cls, e.ch);
            }
            i++;
            return new Esc(new CharSet(new int[][] {{c, c}}, false), false, c);
        }
    }

    private static boolean isHex(String s, int from, int n) {
        for (int k = from; k < from + n; k++) {
            char ch = s.charAt(k);
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) return false;
        }
        return true;
    }

    // ---- compile ----
    private static final class Inst {
        final int op; int x, y; final CharSet set;
        Inst(int op, int x, int y, CharSet set) { this.op = op; this.x = x; this.y = y; this.set = set; }
    }

    /** A compiled NFA program. */
    public static final class Compiled {
        final Inst[] program;
        Compiled(Inst[] program) { this.program = program; }
        public int size() { return program.length; }
    }

    private static void emit(Node node, List<Inst> prog) {
        if (prog.size() > MAX_NFA_INSTRUCTIONS) throw new Refuse("pattern too large");
        switch (node.k) {
            case 's': prog.add(new Inst(SET, 0, 0, node.set)); return;
            case '^': prog.add(new Inst(BOL, 0, 0, null)); return;
            case '$': prog.add(new Inst(EOL, 0, 0, null)); return;
            case 'c': for (Node it : node.items) emit(it, prog); return;
            case 'a': {
                List<Integer> jmps = new ArrayList<>();
                for (int i = 0; i < node.items.size(); i++) {
                    if (i < node.items.size() - 1) {
                        int split = prog.size();
                        prog.add(new Inst(SPLIT, split + 1, -1, null));
                        emit(node.items.get(i), prog);
                        jmps.add(prog.size());
                        prog.add(new Inst(JMP, -1, 0, null));
                        prog.get(split).y = prog.size();
                    } else emit(node.items.get(i), prog);
                }
                for (int j : jmps) prog.get(j).x = prog.size();
                return;
            }
            default: { // rep
                for (int i = 0; i < node.min; i++) emit(node.node, prog);
                if (node.max == Double.POSITIVE_INFINITY) {
                    int split = prog.size();
                    prog.add(new Inst(SPLIT, split + 1, -1, null));
                    emit(node.node, prog);
                    prog.add(new Inst(JMP, split, 0, null));
                    prog.get(split).y = prog.size();
                } else {
                    List<Integer> splits = new ArrayList<>();
                    for (int i = node.min; i < node.max; i++) {
                        splits.add(prog.size());
                        prog.add(new Inst(SPLIT, prog.size() + 1, -1, null));
                        emit(node.node, prog);
                    }
                    for (int sp : splits) prog.get(sp).y = prog.size();
                }
                if (prog.size() > MAX_NFA_INSTRUCTIONS) throw new Refuse("pattern too large");
            }
        }
    }

    /** Compile {@code src}, or null when it is outside the subset or too large. Never throws. */
    public static Compiled compile(String src) {
        try {
            if (src == null) return null;
            Node ast = new Parser(src).parse();
            List<Inst> prog = new ArrayList<>();
            emit(ast, prog);
            prog.add(new Inst(MATCH, 0, 0, null));
            if (prog.size() > MAX_NFA_INSTRUCTIONS) return null;
            return new Compiled(prog.toArray(new Inst[0]));
        } catch (RuntimeException | StackOverflowError e) {
            return null;
        }
    }

    /** Full-match {@code subject}: true / false, or null when the work budget would be exceeded. */
    public static Boolean run(Compiled re, String subject) {
        Inst[] prog = re.program;
        int n = subject.length();
        if ((long) prog.length * (n + 1) > MAX_MATCH_STEPS) return null;
        int[] clist = new int[prog.length], nlist = new int[prog.length];
        int[] mark = new int[prog.length];
        Arrays.fill(mark, -1);
        int[] stack = new int[prog.length * 2 + 2];
        int[] gen = {0};
        boolean[] matched = {false};
        gen[0]++;
        int cn = add(prog, stack, mark, gen[0], matched, clist, 0, 0, 0, n);
        for (int pos = 0; pos < n; pos++) {
            int c = subject.charAt(pos);
            gen[0]++;
            int nn = 0;
            for (int k = 0; k < cn; k++) {
                int pc = clist[k];
                if (prog[pc].set.has(c)) nn = add(prog, stack, mark, gen[0], matched, nlist, nn, pc + 1, pos + 1, n);
            }
            int[] t = clist; clist = nlist; nlist = t;
            cn = nn;
            if (cn == 0 && !matched[0]) return false;
        }
        return matched[0];
    }

    private static int add(Inst[] prog, int[] stack, int[] mark, int gen, boolean[] matched, int[] list, int count, int pc0, int pos, int n) {
        int sp = 0;
        stack[sp++] = pc0;
        while (sp > 0) {
            int pc = stack[--sp];
            if (mark[pc] == gen) continue;
            mark[pc] = gen;
            Inst ins = prog[pc];
            switch (ins.op) {
                case JMP: stack[sp++] = ins.x; break;
                case SPLIT: stack[sp++] = ins.y; stack[sp++] = ins.x; break;
                case BOL: if (pos == 0) stack[sp++] = pc + 1; break;
                case EOL: if (pos == n) stack[sp++] = pc + 1; break;
                case MATCH: if (pos == n) matched[0] = true; break;
                default: list[count++] = pc; break;
            }
        }
        return count;
    }

    /** {@code new RegExp('^(?:' + src + ')$').test(subject)} over the subset; null when refused or over budget. */
    public static Boolean fullMatch(String src, String subject) {
        Compiled re = compile(src);
        if (re == null) return null;
        return run(re, subject);
    }

    // ---- the safe-source guard (predicates.ts isSafeRegexSource) ----
    private static final int MAX_REGEX_COST_BITS = 22;
    private static final int UNBOUNDED_QUANTIFIER_BITS = 8;
    private static final int MAX_BOUNDED_REPEAT = 64;
    private static final Pattern GUARD_QUANT = Pattern.compile("^\\{(\\d+)(?:(,)(\\d*))?\\}");

    private static final class Frame { boolean hasQuant, hasAlt; }

    /**
     * The linear-time-safe subset guard: no quantified group containing a quantifier or an alternation, no
     * backreferences / lookaround / named groups, bounded repeats at most 64, a 22-bit backtracking-cost budget, and the
     * source must compile in {@link #compile}.
     */
    public static boolean isSafeSource(String src) {
        if (src == null) return false;
        List<Frame> stack = new ArrayList<>();
        stack.add(new Frame());
        Object prev = null; // null = none, Boolean.TRUE = atom, Frame = a closed group
        int bits = 0;
        int i = 0;
        while (i < src.length()) {
            char ch = src.charAt(i);
            if (ch == '\\') {
                if (i + 1 >= src.length()) return false;
                char n = src.charAt(i + 1);
                if ((n >= '1' && n <= '9') || n == 'k') return false;
                i += 2;
                prev = Boolean.TRUE;
                continue;
            }
            if (ch == '[') {
                int j = i + 1;
                if (j < src.length() && src.charAt(j) == '^') j++;
                for (; j < src.length() && src.charAt(j) != ']'; j++) if (src.charAt(j) == '\\') j++;
                if (j >= src.length()) return false;
                i = j + 1;
                prev = Boolean.TRUE;
                continue;
            }
            if (ch == '(') {
                if (i + 1 < src.length() && src.charAt(i + 1) == '?') {
                    if (!(i + 2 < src.length() && src.charAt(i + 2) == ':')) return false;
                    i += 3;
                } else i += 1;
                stack.add(new Frame());
                prev = null;
                continue;
            }
            if (ch == ')') {
                if (stack.size() < 2) return false;
                Frame f = stack.remove(stack.size() - 1);
                Frame parent = stack.get(stack.size() - 1);
                parent.hasQuant |= f.hasQuant;
                parent.hasAlt |= f.hasAlt;
                prev = f;
                i++;
                continue;
            }
            if (ch == '|') {
                if (++bits > MAX_REGEX_COST_BITS) return false;
                stack.get(stack.size() - 1).hasAlt = true;
                prev = null;
                i++;
                continue;
            }
            boolean isQ = false, unbounded = false;
            int len = 0;
            double max = 0, options = 0;
            if (ch == '*' || ch == '+') { isQ = true; len = 1; unbounded = true; max = Double.POSITIVE_INFINITY; options = Double.POSITIVE_INFINITY; }
            else if (ch == '?') { isQ = true; len = 1; max = 1; options = 2; }
            else if (ch == '{') {
                Matcher m = GUARD_QUANT.matcher(src.substring(i));
                if (!m.find()) return false;
                double lo = Double.parseDouble(m.group(1));
                boolean hasComma = m.group(2) != null;
                double hi = !hasComma ? lo : m.group(3).isEmpty() ? Double.POSITIVE_INFINITY : Double.parseDouble(m.group(3));
                if (hi < lo) return false;
                isQ = true;
                len = m.group(0).length();
                unbounded = hi == Double.POSITIVE_INFINITY;
                max = hi;
                options = hi == Double.POSITIVE_INFINITY ? Double.POSITIVE_INFINITY : hi - lo + 1;
            }
            if (isQ) {
                if (prev == null) return false;
                if (prev instanceof Frame && (((Frame) prev).hasQuant || ((Frame) prev).hasAlt)) return false;
                if (!unbounded && max != Double.POSITIVE_INFINITY && max > MAX_BOUNDED_REPEAT) return false;
                bits += unbounded ? UNBOUNDED_QUANTIFIER_BITS : options > 1 ? ceilLog2((long) options) : 0;
                if (bits > MAX_REGEX_COST_BITS) return false;
                stack.get(stack.size() - 1).hasQuant = true;
                i += len;
                if (i < src.length() && src.charAt(i) == '?') i++;
                prev = null;
                continue;
            }
            i++;
            prev = Boolean.TRUE;
        }
        return stack.size() == 1 && compile(src) != null;
    }

    /** {@code Math.ceil(Math.log2(n))} for an integer n &gt;= 2, computed exactly. */
    static int ceilLog2(long n) { return 64 - Long.numberOfLeadingZeros(n - 1); }

    // ---- per-document budget (regex-budget.ts) ----
    /** One document's regex work budget. */
    static final class Budget {
        int evaluations, chars;
        long steps;
        int refusals;

        boolean charge(String src, int subjectLen) {
            Compiled c = compile(src);
            if (c == null) { refusals++; return false; }
            int ev = evaluations + 1;
            int ch = chars + src.length();
            long st = steps + (long) c.size() * (subjectLen + 1);
            if (ev > MAX_REGEX_EVALUATIONS_PER_DOCUMENT || ch > MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT || st > MAX_REGEX_STEPS_PER_DOCUMENT) {
                evaluations = MAX_REGEX_EVALUATIONS_PER_DOCUMENT + 1; // poison: order-independent refusal
                refusals++;
                return false;
            }
            evaluations = ev;
            chars = ch;
            steps = st;
            return true;
        }
    }

    private static final ThreadLocal<Budget> CURRENT = new ThreadLocal<>();

    /** Run {@code fn} inside the open document budget, or a fresh one when none is open (withRegexBudget). */
    static <T> T withBudget(java.util.function.Supplier<T> fn) {
        if (CURRENT.get() != null) return fn.get();
        CURRENT.set(new Budget());
        try {
            return fn.get();
        } finally {
            CURRENT.remove();
        }
    }

    /** Charge one evaluation of {@code src} against a subject of {@code subjectLen} code units (chargeRegex). */
    static boolean charge(String src, int subjectLen) {
        Budget b = CURRENT.get();
        return (b != null ? b : new Budget()).charge(src, subjectLen);
    }
}
