#!/usr/bin/env python3
"""Coverage map and shard parts for the Java mutation workflow.

The coverage map: PIT's coverage phase (the whole suite, once per PIT run) cost every shard 20-35 minutes. The covmap jobs run it ONCE
per run, over every class and a 1/K share of the test classes each (one mutant-free PIT run per share, exportLineCoverage), and reduce
PIT's linecoverage.xml to class -> covering test classes. A shard then lists as targetTests only the test classes that cover one of
its classes: PIT runs, per mutant, only the tests that cover the mutated line, so every test it would have run is still a target
test (a class-level superset of the line-level set) and the kill power is unchanged; the shard's coverage phase shrinks to those tests.

Shard parts: a slice too costly for one job runs as parts that partition its mutants (method bins over the bytecode method names of
its classes, javap-measured, and mutator bins), and parts that partition its covering test classes (test bins). Mutant parts are
disjoint; test parts see the same mutants and are combined in the merge: a mutant is KILLED when a test of any part failed
under it (a real failing test), else decided by no test in any part (dead minion), else SURVIVED, else NO_COVERAGE.

Subcommands: covmap-prep, covmap-reduce, shard-pom, combine, check-matrix, gen-matrix, selftest. Every one fails loudly on input it
does not understand; nothing here may make a shard run fewer tests than its mutants' covering tests.
"""
import json, math, os, re, string, subprocess, sys
import xml.etree.ElementTree as ET

P = "net.atlasauth.pca"
POM_TESTS = ["MutationHarness", P + ".*Test"]          # the pom's targetTests; asserted against the pom
ALPH = string.ascii_letters + string.digits + "_$<"
ALL = ["CONDITIONALS_BOUNDARY", "CONSTRUCTOR_CALLS", "EMPTY_RETURNS", "EXPERIMENTAL_ARGUMENT_PROPAGATION", "EXPERIMENTAL_BIG_DECIMAL",
       "EXPERIMENTAL_BIG_INTEGER", "EXPERIMENTAL_MEMBER_VARIABLE", "EXPERIMENTAL_NAKED_RECEIVER", "EXPERIMENTAL_SWITCH", "FALSE_RETURNS",
       "INCREMENTS", "INLINE_CONSTS", "INVERT_NEGS", "MATH", "NEGATE_CONDITIONALS", "NON_VOID_METHOD_CALLS", "NULL_RETURNS",
       "PRIMITIVE_RETURNS", "REMOVE_CONDITIONALS_EQUAL_ELSE", "REMOVE_CONDITIONALS_EQUAL_IF", "REMOVE_CONDITIONALS_ORDER_ELSE",
       "REMOVE_CONDITIONALS_ORDER_IF", "REMOVE_INCREMENTS", "REMOVE_SWITCH", "TRUE_RETURNS", "VOID_METHOD_CALLS"]
GRP = {"n": ["NON_VOID_METHOD_CALLS"],
       "c": ["NEGATE_CONDITIONALS", "CONDITIONALS_BOUNDARY", "EXPERIMENTAL_ARGUMENT_PROPAGATION", "EXPERIMENTAL_MEMBER_VARIABLE",
             "EXPERIMENTAL_NAKED_RECEIVER", "EXPERIMENTAL_SWITCH", "EXPERIMENTAL_BIG_DECIMAL", "EXPERIMENTAL_BIG_INTEGER"],
       "r": ["REMOVE_CONDITIONALS_EQUAL_IF", "REMOVE_CONDITIONALS_EQUAL_ELSE", "REMOVE_CONDITIONALS_ORDER_IF", "REMOVE_CONDITIONALS_ORDER_ELSE", "INLINE_CONSTS"]}
GRP["x"] = [m for m in ALL if not any(m in v for v in GRP.values())]
SHARE = {"n": 40, "c": 26, "r": 21, "x": 13}             # mutant share per group (the GoalSemantics split); split evenly inside a group
MUT_W = {m: SHARE[g] / len(v) for g, v in GRP.items() for m in v}
STATUS_RANK = {"KILLED": 6, "TIMED_OUT": 5, "MEMORY_ERROR": 4, "RUN_ERROR": 3, "NON_VIABLE": 2, "SURVIVED": 1, "NO_COVERAGE": 0}
MATRIX_CHUNK = 256


def die(msg):
    print(f"::error::{msg}", flush=True)
    sys.exit(1)


def args(argv):
    out = {}
    for a in argv:
        if not a.startswith("--") or "=" not in a:
            die(f"bad argument {a!r} (want --name=value)")
        k, v = a[2:].split("=", 1)
        out[k] = v
    return out


def glob_re(g):
    # PIT's Glob: * -> .*, ? -> ., everything else literal (so $ and . are literal)
    return re.compile("^" + "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in g) + "$")


def lpt(items, weight, bins):
    """Deterministic longest-processing-time binning: heaviest first, ties by name, into the lightest bin (ties: lowest index)."""
    out, load = [[] for _ in range(bins)], [0.0] * bins
    for it in sorted(items, key=lambda x: (-weight(x), x)):
        b = min(range(bins), key=lambda i: (load[i], i))
        out[b].append(it)
        load[b] += weight(it)
    return out, load


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def write(p, s):
    with open(p, "w", encoding="utf-8") as f:
        f.write(s)


def sub1(pat, repl, s, what):
    s2, n = re.subn(pat, lambda m: repl, s, count=1, flags=re.S)
    if n != 1:
        die(f"{what} not found in pom.xml")
    return s2


def params(xs):
    esc = lambda g: g.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return "".join(f"<param>{esc(x)}</param>" for x in xs)


# ---------------------------------------------------------------- test classes and the coverage map

def listed_tests(test_root):
    """Top-level test classes under the pom's net.atlasauth.pca.*Test glob (a file per class). Nested or unlisted ones stay in the rest share."""
    base = os.path.join(test_root, *P.split("."))
    out = []
    for d, _, fs in os.walk(base):
        for f in fs:
            if f.endswith("Test.java"):
                rel = os.path.relpath(os.path.join(d, f[:-5]), test_root)
                out.append(rel.replace(os.sep, "."))
    if len(out) < 50:
        die(f"only {len(out)} test classes under {base}: wrong test root")
    return sorted(out)


def weights(path):
    w = json.loads(read(path))
    med = sorted(w.values())[len(w) // 2] if w else 1.0
    return lambda t: max(float(w.get(t, med)), 0.05)


def covmap_shares(test_root, wpath, k):
    """K shares: the first K-1 hold explicit test classes (LPT by measured suite time), the last is the pom's own globs minus all of them."""
    tests = listed_tests(test_root)
    bins, load = lpt(tests, weights(wpath), k)
    # the rest share also runs MutationHarness and every class the listing does not see: give it the lightest explicit bin
    order = sorted(range(k), key=lambda i: (load[i], i))
    rest = order[0]
    shares = [sorted(b) for i, b in enumerate(bins) if i != rest] + [sorted(bins[rest])]
    return tests, shares


def test_class_of(name):
    """The defining (top-level) test class of a PIT test name: JUnit 5 names carry [class:...]; anything else is refused."""
    m = re.search(r"\[class:([^\]]+)\]", name)
    if m:
        return m.group(1)
    if ".[" in name:
        return name.split(".[", 1)[0]
    raise ValueError(f"unrecognised PIT test name {name!r}")


def cmd_covmap_prep(a):
    k, part = int(a["of"]), int(a["part"])
    if not 1 <= part <= k:
        die(f"part {part} of {k}")
    pom = read(a["pom"])
    tt = re.search(r"<targetTests>(.*?)</targetTests>", pom, flags=re.S)
    if not tt or re.findall(r"<param>(.*?)</param>", tt.group(1)) != POM_TESTS:
        die(f"the pom's targetTests changed (want {POM_TESTS}): update mutation-parts.py")
    tests, shares = covmap_shares(a["test-root"], a["weights"], k)
    mine = shares[part - 1]
    if part < k:
        pom = sub1(r"<targetTests>.*?</targetTests>", "<targetTests>" + params(mine) + "</targetTests>", pom, "targetTests")
    else:
        others = sorted(t for s in shares[:-1] for t in s)
        pom = pom.replace("</targetTests>", "</targetTests><excludedTestClasses>" + params(others) + "</excludedTestClasses>", 1)
    # every class is a coverage target; the one mutant is a probe no test calls (NO_COVERAGE, no test run): excludedMethods drops
    # every method whose name does not start with Z (no shipped method does), so PIT runs its coverage phase and nothing else
    pom = sub1(r"<targetClasses>.*?</targetClasses>", f"<targetClasses><param>{P}.*</param></targetClasses>", pom, "targetClasses")
    if "<excludedMethods>" in pom:
        die("the pom already sets excludedMethods")
    pom = pom.replace("</targetClasses>", "</targetClasses><excludedMethods>" + params(c + "*" for c in ALPH if c != "Z") + "</excludedMethods>", 1)
    write(a["pom"], pom)
    probe = os.path.join(a["src-dir"], *P.split("."), "CovmapProbe.java")
    if os.path.exists(probe):
        die(f"{probe} exists")
    write(probe, f"package {P};\n\n/** Coverage-map run only (never shipped): the single mutant of a coverage-only PIT run. */\nfinal class CovmapProbe {{\n"
                 "    private CovmapProbe() {}\n    static int Zprobe(int x) { return x + 1; }\n}\n")
    meta = {"sha": os.environ.get("GITHUB_SHA", ""), "part": part, "of": k, "tests": mine if part < k else "rest", "listed": len(tests)}
    write(a["meta"], json.dumps(meta))
    print(f"covmap share {part}/{k}: {len(mine)} listed test class(es){' + every unlisted one (rest)' if part == k else ''}")


def cmd_covmap_reduce(a):
    meta = json.loads(read(a["meta"]))
    share = None if meta["tests"] == "rest" else set(meta["tests"])
    listed = None
    if share is None:
        _, shares = covmap_shares(a["test-root"], a["weights"], meta["of"])
        listed = {t for s in shares[:-1] for t in s}
    cov, blocks, seen = {}, 0, set()
    pomglob = [glob_re(g) for g in POM_TESTS]
    for _, el in ET.iterparse(a["xml"], events=("end",)):
        if el.tag != "block":
            continue
        cls = el.get("classname")
        if not cls:
            die("a linecoverage block without classname")
        blocks += 1
        for t in el.iter("test"):
            tc = test_class_of(t.get("name", ""))
            if share is not None and tc not in share:
                die(f"covmap share {meta['part']}: test {tc} is not in the share (test-name parse or share mismatch)")
            if share is None and (tc in listed or not any(g.match(tc) for g in pomglob)):
                die(f"covmap rest share: test {tc} is listed in another share or outside the pom's targetTests")
            cov.setdefault(cls, set()).add(tc)
            seen.add(tc)
        el.clear()
    if blocks == 0 or not seen:
        die(f"covmap share {meta['part']}: {blocks} covered blocks, {len(seen)} test classes: the coverage run measured nothing")
    meta.update({"blocks": blocks, "testclasses": len(seen), "map": {c: sorted(v) for c, v in sorted(cov.items())}})
    write(a["out"], json.dumps(meta))
    print(f"covmap share {meta['part']}/{meta['of']}: {blocks} covered blocks over {len(cov)} classes by {len(seen)} test classes")


def load_covmap(d, k, test_root, wpath):
    _, shares = covmap_shares(test_root, wpath, k)
    got, cov = {}, {}
    for f in sorted(os.listdir(d)) if os.path.isdir(d) else []:
        if not re.fullmatch(r"covmap-\d+\.json", f):
            continue
        m = json.loads(read(os.path.join(d, f)))
        if m.get("of") != k:
            die(f"{f}: a map of {m.get('of')} shares, want {k}")
        if m.get("sha") != os.environ.get("GITHUB_SHA", m.get("sha")):
            die(f"{f}: coverage map of commit {m.get('sha')}, this run is {os.environ.get('GITHUB_SHA')} (stale map)")
        if m["part"] in got:
            die(f"{f}: share {m['part']} twice")
        want = shares[m["part"] - 1] if m["part"] < k else "rest"
        if m["tests"] != want:
            die(f"{f}: share {m['part']} lists other test classes than this checkout would (stale or foreign map)")
        if not m.get("blocks"):
            die(f"{f}: empty coverage map")
        got[m["part"]] = m
        for c, ts in m["map"].items():
            cov.setdefault(c, set()).update(ts)
    if sorted(got) != list(range(1, k + 1)):
        die(f"coverage map shares {sorted(got)} of {k}: a covmap job failed or its artifact is missing")
    if len(cov) < 200:
        die(f"the coverage map names only {len(cov)} covered classes: the coverage runs did not measure the suite")
    return cov


# ---------------------------------------------------------------- shard parts

def slice_globs(plan, sl):
    if sl.get("rest"):
        named = sorted({c for q in plan["slices"] for c in q.get("classes", [])})
        return [glob_re(P + ".*")], [glob_re(P + "." + c) for c in named]
    return [glob_re(P + "." + c) for c in sl["classes"]], []


def in_slice(cls, inc, exc):
    return any(g.match(cls) for g in inc) and not any(g.match(cls) for g in exc)


def parse_part(s):
    if not s:
        return (1, 1, 1)
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", s)
    if not m:
        die(f"part {s!r}: want j.g.i")
    return tuple(int(x) for x in m.groups())


def counts(sl):
    return sl.get("mparts", 1), sl.get("gparts", 1), sl.get("tparts", 1)


def tags(sl):
    M, G, T = counts(sl)
    if (M, G, T) == (1, 1, 1):
        return [""]
    return [f"{j}.{g}.{i}" for j in range(1, M + 1) for g in range(1, G + 1) for i in range(1, T + 1)]


def javap_methods(classes_dir, inc, exc):
    """bytecode method name -> instruction count, over every class file of the slice (nested types included)."""
    names = []
    base = os.path.join(classes_dir, *P.split("."))
    for d, _, fs in os.walk(base):
        for f in fs:
            if f.endswith(".class"):
                cls = os.path.relpath(os.path.join(d, f[:-6]), classes_dir).replace(os.sep, ".")
                if in_slice(cls, inc, exc):
                    names.append(cls)
    if not names:
        die(f"no class file of the slice under {base}")
    out = subprocess.run(["javap", "-p", "-c", "-cp", classes_dir] + sorted(names), capture_output=True, text=True)
    if out.returncode != 0:
        die(f"javap failed: {out.stderr[:400]}")
    return javap_weights(out.stdout)


def javap_weights(text):
    w, cur, simple = {}, None, None
    for ln in text.split("\n"):
        mc = re.match(r"^(?:[\w.$]+\s+)*(?:class|interface|enum|record)\s+([\w.$]+)", ln)
        if mc and not ln.startswith(" "):
            simple = mc.group(1).split(".")[-1]
            cur = None
            continue
        if ln.startswith("  ") and not ln.startswith("   ") and ln.rstrip().endswith(";"):
            s = ln.strip()
            if s.startswith("static {}"):
                cur = "<clinit>"
            elif "(" in s:
                nm = s.split("(", 1)[0].split()[-1]
                nm = nm.split(".")[-1]
                cur = "<init>" if simple and (nm == simple or nm == simple.split("$")[-1]) else nm
            else:
                cur = None  # a field
            if cur:
                w.setdefault(cur, 0)
            continue
        if cur and re.match(r"^\s+\d+: \w", ln):
            w[cur] += 1
    if not w:
        die("javap printed no method")
    return w


def cmd_shard_pom(a):
    plan = json.loads(read(a["plan"]))
    k = int(a["shard"])
    sl = plan["slices"][k - 1]
    j, g, i = parse_part(a.get("part", ""))
    M, G, T = counts(sl)
    if not (1 <= j <= M and 1 <= g <= G and 1 <= i <= T):
        die(f"shard {k}: part {j}.{g}.{i} outside the plan's {M}.{G}.{T}")
    pom = read(a["pom"])
    inc, exc = slice_globs(plan, sl)
    # (1) method bins: the slice's bytecode method names (minus its own exclusions), LPT by instruction count; a part excludes the others
    if M > 1:
        w = javap_methods(a["classes"], inc, exc)
        own_ex = set(sl.get("exclude_methods") or [])
        names = sorted(n for n in w if n not in own_ex)
        bins, load = lpt(names, lambda n: w[n] + 1, M)
        ex = sorted(set(names) - set(bins[j - 1]))
        print(f"method bin {j}/{M}: {len(bins[j-1])} method name(s), {int(load[j-1])} of {int(sum(load))} instructions: {', '.join(sorted(bins[j-1]))[:600]}")
        if not bins[j - 1]:
            print(f"::notice::shard {k} method bin {j}/{M} is empty (fewer method names than bins): no mutants here")
        if ex:
            if "<excludedMethods>" in pom:
                pom = pom.replace("</excludedMethods>", params(ex) + "</excludedMethods>", 1)
            else:
                pom = pom.replace("</targetClasses>", "</targetClasses><excludedMethods>" + params(ex) + "</excludedMethods>", 1)
    # (2) mutator bins over the slice's mutator list (the pom's, as the plan step left it)
    mm = re.search(r"<mutators>(.*?)</mutators>", pom, flags=re.S)
    if not mm:
        die("mutators not found in pom.xml")
    muts = re.findall(r"<mutator>(.*?)</mutator>", mm.group(1))
    muts = ALL if muts == ["ALL"] else muts
    if not muts or not set(muts) <= set(ALL):
        die(f"unexpected mutator list {muts}")
    if G > 1:
        bins, _ = lpt(muts, lambda m: MUT_W[m], G)
        if not bins[g - 1]:
            die(f"shard {k}: mutator bin {g}/{G} is empty ({len(muts)} mutators): lower gparts in the plan")
        print(f"mutator bin {g}/{G}: {' '.join(sorted(bins[g-1]))}")
        pom = sub1(r"<mutators>.*?</mutators>", "<mutators>" + "".join(f"<mutator>{x}</mutator>" for x in sorted(bins[g - 1])) + "</mutators>", pom, "mutators")
    # (3) target tests: the coverage map's covering test classes of the slice's classes, then the test bin
    if a.get("tests") == "keep":
        print("target tests: kept as the plan step set them (negative-control run)")
        write(a["pom"], pom)
        return
    cov = load_covmap(a["covmap"], int(a["of"]), a["test-root"], a["weights"])
    covering = sorted({t for c, ts in cov.items() if in_slice(c, inc, exc) for t in ts})
    if not covering:
        print(f"::warning::shard {k}: no test covers any class of the slice (every mutant is NO_COVERAGE): the pom's full target tests stay")
    else:
        if T > 1:
            bins, load = lpt(covering, weights(a["weights"]), T)
            mine = bins[i - 1] or [min(covering, key=lambda t: (weights(a["weights"])(t), t))]  # an empty bin re-runs one class: never empty
            print(f"test bin {i}/{T}: {len(mine)} of {len(covering)} covering test class(es), ~{int(load[i-1])} s of suite time")
        else:
            mine = covering
            print(f"target tests: {len(covering)} covering test class(es) (of the whole suite) for the slice's classes")
        pom = sub1(r"<targetTests>.*?</targetTests>", "<targetTests>" + params(mine) + "</targetTests>", pom, "targetTests")
    write(a["pom"], pom)


def mutation_key(el):
    f = lambda t: (el.findtext(t) or "").strip()
    idx = ",".join((x.text or "").strip() for x in el.iter("index"))
    blk = ",".join((x.text or "").strip() for x in el.iter("block"))
    return "\0".join([f("sourceFile"), f("mutatedClass"), f("mutatedMethod"), f("methodDescription"), f("lineNumber"), f("mutator"), idx, blk, f("description")])


def combine_xml(groups):
    """groups: [[xml text of each test part] for each mutant part]. Returns the combined mutations.xml text."""
    out, seen = [], set()
    for parts in groups:
        per = []
        for x in parts:
            root = ET.fromstring(x)
            per.append({mutation_key(e): e for e in root.iter("mutation")})
        keys = set(per[0])
        for p in per[1:]:
            if set(p) != keys:
                raise ValueError(f"test parts of one mutant part mutated different mutants ({len(keys ^ set(p))} differ)")
        if keys & seen:
            raise ValueError(f"{len(keys & seen)} mutant(s) in two mutant parts (the parts must partition the slice)")
        seen |= keys
        for key in sorted(keys):
            best = max((p[key] for p in per), key=lambda e: STATUS_RANK[e.get("status")])
            out.append(ET.tostring(best, encoding="unicode"))
    return '<?xml version="1.0" encoding="UTF-8"?>\n<mutations>\n' + "\n".join(out) + "\n</mutations>\n"


def cmd_combine(a):
    plan = json.loads(read(a["plan"]))
    rep, outd = a["reports"], a["out"]
    files = {}
    for d, _, fs in os.walk(rep):
        for f in fs:
            m = re.fullmatch(r"mutations-(\d+)-(\d+\.\d+\.\d+)\.xml", f)
            if m:
                files[(int(m.group(1)), m.group(2))] = os.path.join(d, f)
    ok, bad = [], 0
    for k, sl in enumerate(plan["slices"], 1):
        t = tags(sl)
        if t == [""]:
            continue
        miss = [x for x in t if (k, x) not in files]
        if miss:
            print(f"::error::shard {k}: part report(s) {', '.join(miss[:12])} missing: the shard has no report")
            bad += 1
            continue
        M, G, T = counts(sl)
        groups = [[read(files[(k, f'{j}.{g}.{i}')]) for i in range(1, T + 1)] for j in range(1, M + 1) for g in range(1, G + 1)]
        try:
            x = combine_xml(groups)
        except ValueError as e:
            print(f"::error::shard {k}: {e}")
            bad += 1
            continue
        oom = 0
        for tg in t:
            o = json.loads(read(files[(k, tg)].replace(f"mutations-{k}-{tg}.xml", f"oom-{k}-{tg}.json")))
            r = json.loads(read(files[(k, tg)].replace(f"mutations-{k}-{tg}.xml", f"runerr-{k}-{tg}.json")))
            if o["count"] > r["count"]:
                print(f"::error::shard {k} part {tg}: {o['count']} out-of-memory exit(s) but {r['count']} RUN_ERROR mutant(s)")
                bad += 1
            oom += o["count"]
        n_re = len(re.findall(r"status='RUN_ERROR'|status=\"RUN_ERROR\"", x))
        os.makedirs(os.path.join(outd, f"shard-{k}"), exist_ok=True)
        write(os.path.join(outd, f"shard-{k}", f"combined-{k}.xml"), x)
        # every part's exits were tied to its own RUN_ERRORs above; a RUN_ERROR another part killed is no longer one, so cap at the combined count
        write(os.path.join(outd, f"shard-{k}", f"oom-{k}.json"), json.dumps({"count": min(oom, n_re)}))
        ok.append(k)
    write(os.path.join(outd, "combined-shards.txt"), "".join(f"{k}\n" for k in ok))
    print(f"combined {len(ok)} multi-part shard(s); {bad} problem(s)")
    if bad:
        sys.exit(1)


# ---------------------------------------------------------------- the workflow's shard matrix

def entries(plan):
    out = []
    for k, sl in enumerate(plan["slices"], 1):
        for t in tags(sl):
            out.append((k, t, sl.get("label", ""), sl.get("module", "")))
    return out


def matrix_lines(plan, module_of):
    lines = []
    for k, t, label, _ in entries(plan):
        lab = label.replace("'", "''")
        extra = f", part: '{t}'" if t else ""
        mod = module_of.get(k)
        extra += f", module: {mod}" if mod else ""
        lines.append(f"          - {{ shard: {k}{extra}, label: '{lab}' }}")
    return lines


def job_blocks(lines):
    starts = [i for i, l in enumerate(lines) if re.match(r"^  [A-Za-z0-9_-]+:\s*$", l)]
    return {lines[s].strip()[:-1]: (s, (starts[n + 1] if n + 1 < len(starts) else len(lines))) for n, s in enumerate(starts)}


def matrix_in_workflow(text):
    got = []
    for m in re.finditer(r"^          - \{ shard: (\d+),(.*)\}\s*$", text, flags=re.M):
        pt = re.search(r"\bpart: '([0-9.]+)'", m.group(2))
        mo = re.search(r"\bmodule: ([\w-]+)", m.group(2))
        got.append((int(m.group(1)), pt.group(1) if pt else "", mo.group(1) if mo else ""))
    return got


def cmd_check_matrix(a):
    plan = json.loads(read(a["plan"]))
    wf = read(a["workflow"])
    got = sorted(matrix_in_workflow(wf))
    mods = {k: mo for k, _, mo in got if mo}
    want = sorted((k, t, mods.get(k, "")) for k, t, _, _ in entries(plan))
    if got != want:
        g, w = set(got), set(want)
        die(f"the shard matrix does not match the plan: {len(w - g)} missing (e.g. {sorted(w - g)[:5]}), {len(g - w)} extra (e.g. {sorted(g - w)[:5]}); regenerate it")
    n = int(re.search(r"^  SHARDS: '(\d+)'", wf, flags=re.M).group(1))
    if n != len(plan["slices"]):
        die(f"SHARDS {n} != {len(plan['slices'])} plan slices")
    for k, sl in enumerate(plan["slices"], 1):
        M, G, T = counts(sl)
        if min(M, G, T) < 1 or (sl.get("module") or k in mods) and (M, G, T) != (1, 1, 1):
            die(f"slice {k}: bad part counts {M}.{G}.{T}")
    print(f"shard matrix: {len(got)} job(s) for {n} shards, matches the plan")


def cmd_gen_matrix(a):
    plan = json.loads(read(a["plan"]))
    path = a["workflow"]
    lines = read(path).split("\n")
    blocks = job_blocks(lines)
    old = sorted((n for n in blocks if re.fullmatch(r"shard\d*", n)), key=lambda n: int(n[5:] or 1))
    mods = {k: mo for k, _, mo in matrix_in_workflow("\n".join(lines)) if mo}
    s0, e0 = blocks["shard"]
    tpl = lines[s0:e0]
    while tpl and (tpl[-1].strip() == "" or tpl[-1].startswith("  #")):
        tpl.pop()
    inc = next(n for n, l in enumerate(tpl) if l.strip() == "include:")
    body_start = next(n for n in range(inc + 1, len(tpl)) if not tpl[n].startswith("          "))
    head, tail = tpl[:inc + 1], tpl[body_start:]
    ml = matrix_lines(plan, mods)
    chunks = [ml[i:i + MATRIX_CHUNK] for i in range(0, len(ml), MATRIX_CHUNK)]
    names = ["shard" if n == 0 else f"shard{n + 1}" for n in range(len(chunks))]
    gen = []
    for n, ch in enumerate(chunks):
        h = list(head)
        h[0] = f"  {names[n]}:"
        gen += h + [f"          # generated by .github/scripts/mutation-parts.py gen-matrix from mutation-plan.json (matrix {n + 1} of {len(chunks)}); label is for the job name only"] + ch + tail + [""]
    # replace the old shard jobs (keeping comment lines that sit between the last one and the next job)
    first, last = blocks[old[0]][0], blocks[old[-1]][1]
    keep_tail = []
    j = last - 1
    while j > first and (lines[j].strip() == "" or lines[j].startswith("  #")):
        keep_tail.insert(0, lines[j])
        j -= 1
    new = lines[:first] + gen + [l for l in keep_tail if l.strip()] + lines[last:]
    txt = "\n".join(new)
    txt = re.sub(r"\bshard(?:, shard\d+)+\b|\bshard(?=, winshard)", ", ".join(names), txt)
    write(path, txt)
    print(f"{len(ml)} matrix entries in {len(chunks)} shard job(s): {', '.join(names)}")


# ---------------------------------------------------------------- self-test

def selftest():
    assert glob_re(P + ".DurableState$*").match(P + ".DurableState$Rec")
    assert not glob_re(P + ".Json").match(P + ".Json$Parser")
    assert glob_re(P + ".*Test").match(P + ".mpc.NetTest") and not glob_re("MutationHarness").match("XMutationHarness")
    b, l = lpt(["a", "b", "c", "d"], {"a": 5, "b": 4, "c": 3, "d": 3}.get, 2)
    assert sorted(sum(b, [])) == ["a", "b", "c", "d"] and l == [8, 7], (b, l)
    assert test_class_of(P + ".JsonTest.[engine:junit-jupiter]/[class:" + P + ".JsonTest]/[method:x()]") == P + ".JsonTest"
    assert test_class_of(P + ".A.[engine:junit-jupiter]/[class:" + P + ".A]/[nested-class:B]/[method:y()]") == P + ".A"
    try:
        test_class_of("garbage"); raise AssertionError("accepted a bad name")
    except ValueError:
        pass
    jp = """Compiled from "Json.java"
public final class net.atlasauth.pca.Json {
  public static final int X;
  private net.atlasauth.pca.Json();
    Code:
       0: aload_0
       1: return
  static java.lang.Object parse(java.lang.String);
    Code:
       0: aload_0
       1: invokestatic  #2
       4: areturn
  private static java.lang.Object lambda$parse$0(int);
    Code:
       0: iload_0
  static {};
    Code:
       0: iconst_1
}
final class net.atlasauth.pca.Json$Parser {
  net.atlasauth.pca.Json$Parser(java.lang.String);
    Code:
       0: return
  double number();
    Code:
       0: dconst_0
       1: dreturn
}
"""
    assert javap_weights(jp) == {"<init>": 3, "parse": 3, "lambda$parse$0": 1, "<clinit>": 1, "number": 2}, javap_weights(jp)
    mk = lambda st, line, mut="MATH": (f"<mutation detected='{str(st=='KILLED').lower()}' status='{st}' numberOfTestsRun='1'><sourceFile>J.java</sourceFile>"
                                       f"<mutatedClass>{P}.J</mutatedClass><mutatedMethod>m</mutatedMethod><methodDescription>()I</methodDescription>"
                                       f"<lineNumber>{line}</lineNumber><mutator>{mut}</mutator><indexes><index>1</index></indexes><blocks><block>0</block></blocks>"
                                       f"<killingTest/><description>d</description></mutation>")
    doc = lambda *ms: "<mutations>" + "".join(ms) + "</mutations>"
    x = combine_xml([[doc(mk("SURVIVED", 1), mk("TIMED_OUT", 2), mk("NO_COVERAGE", 3)), doc(mk("KILLED", 1), mk("SURVIVED", 2), mk("SURVIVED", 3))],
                     [doc(mk("NO_COVERAGE", 9))]])
    st = re.findall(r"status=\"(\w+)\"|status='(\w+)'", x)
    st = [p or q for p, q in st]
    assert st == ["KILLED", "TIMED_OUT", "SURVIVED", "NO_COVERAGE"], st
    for bad in ([[doc(mk("KILLED", 1)), doc(mk("KILLED", 2))]], [[doc(mk("KILLED", 1))], [doc(mk("KILLED", 1))]]):
        try:
            combine_xml(bad); raise AssertionError("combined parts that do not line up")
        except ValueError:
            pass
    sl = {"mparts": 2, "gparts": 1, "tparts": 3}
    assert tags(sl) == ["1.1.1", "1.1.2", "1.1.3", "2.1.1", "2.1.2", "2.1.3"] and tags({}) == [""]
    assert abs(sum(MUT_W.values()) - 100) < 1e-9 and sorted(MUT_W) == sorted(ALL)
    print("mutation-parts selftest: ok")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        die("usage: mutation-parts.py <covmap-prep|covmap-reduce|shard-pom|combine|check-matrix|gen-matrix|selftest> --name=value ...")
    cmd, a = sys.argv[1], args(sys.argv[2:])
    {"covmap-prep": cmd_covmap_prep, "covmap-reduce": cmd_covmap_reduce, "shard-pom": cmd_shard_pom, "combine": cmd_combine,
     "check-matrix": cmd_check_matrix, "gen-matrix": cmd_gen_matrix, "selftest": lambda _: selftest()}.get(cmd, lambda _: die(f"unknown command {cmd}"))(a)
