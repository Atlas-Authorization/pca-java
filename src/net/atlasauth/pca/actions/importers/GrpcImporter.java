package net.atlasauth.pca.actions.importers;

import static net.atlasauth.pca.actions.importers.ImportCommon.*;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import net.atlasauth.pca.Actions.ActionKitError;
import net.atlasauth.pca.AttestCommon;
import net.atlasauth.pca.IntentJs;

/**
 * Protobuf services to drafts, from {@code .proto} text or a binary FileDescriptorSet. {@code service.method} becomes the verb;
 * {@code google.api.http} gives method and path; {@code idempotency_level} gives read / idempotent; field behavior refines params;
 * streaming methods get {@code pca.bulk}. Offline, bounded; the descriptor wire format is read by hand (no protobuf dependency).
 */
public final class GrpcImporter {
    private GrpcImporter() {}

    // ---- model ----

    public static final class PField {
        public String name, type, scope;
        public boolean repeated, optional;
        public String[] map;
        public List<String> behavior = new ArrayList<>();
        Map<String, Object> toJson() {
            Map<String, Object> m = Jx.obj("name", name, "type", type, "scope", scope, "repeated", repeated, "optional", optional);
            if (map != null) m.put("map", Jx.list(map[0], map[1]));
            m.put("behavior", new ArrayList<Object>(behavior));
            return m;
        }
    }

    public static final class PMsg {
        public String full;
        public List<PField> fields = new ArrayList<>();
        public boolean mapEntry;
    }

    public static final class PEnum {
        public String full;
        public List<String> values = new ArrayList<>();
    }

    public static final class PHttp {
        public String method, path, body;
    }

    public static final class PMethod {
        public String name = "", input = "", output = "", scope = "", idem;
        public boolean cs, ss;
        public PHttp http;
    }

    public static final class PService {
        public String full, name;
        public List<PMethod> methods = new ArrayList<>();
    }

    public static final class ProtoModel {
        public final Map<String, PMsg> messages = new LinkedHashMap<>();
        public final Map<String, PEnum> enums = new LinkedHashMap<>();
        public final List<PService> services = new ArrayList<>();

        /** {@code {messages: [[full, {...}]...], enums: [[full, [values]]...], services: [{...}]}}. */
        public Map<String, Object> toJson() {
            List<Object> ms = new ArrayList<>();
            for (PMsg m : messages.values()) {
                List<Object> fs = new ArrayList<>();
                for (PField f : m.fields) fs.add(f.toJson());
                ms.add(Jx.list(m.full, Jx.obj("full", m.full, "fields", fs, "mapEntry", m.mapEntry)));
            }
            List<Object> es = new ArrayList<>();
            for (PEnum e : enums.values()) es.add(Jx.list(e.full, new ArrayList<Object>(e.values)));
            List<Object> ss = new ArrayList<>();
            for (PService s : services) {
                List<Object> mm = new ArrayList<>();
                for (PMethod x : s.methods) {
                    Map<String, Object> o = Jx.obj("name", x.name, "input", x.input, "output", x.output, "cs", x.cs, "ss", x.ss, "scope", x.scope);
                    if (x.http != null) { Map<String, Object> h = Jx.obj("method", x.http.method, "path", x.http.path); if (x.http.body != null) h.put("body", x.http.body); o.put("http", h); }
                    if (x.idem != null) o.put("idem", x.idem);
                    mm.add(o);
                }
                ss.add(Jx.obj("full", s.full, "name", s.name, "methods", mm));
            }
            return Jx.obj("messages", ms, "enums", es, "services", ss);
        }
    }

    private static final Set<String> SCALAR_NAMES = Set.of("double", "float", "int32", "int64", "uint32", "uint64", "sint32", "sint64", "fixed32", "fixed64", "sfixed32", "sfixed64", "bool", "string", "bytes");

    // ---- .proto text ----

    private static final class Tok {
        final String t, v;
        Tok(String t, String v) { this.t = t; this.v = v; }
    }

    private static boolean idStart(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c == '.'; }
    private static boolean idChar(char c) { return idStart(c) || (c >= '0' && c <= '9'); }
    private static boolean numChar(char c) { return c == '-' || c == '+' || c == '.' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }

    private static List<Tok> lex(String src, int maxTokens) {
        List<Tok> out = new ArrayList<>();
        int n = src.length(), i = 0;
        while (i < n) {
            char ch = src.charAt(i);
            Tok push;
            if (Jx.jsSpace(ch)) { i++; continue; }
            if (src.startsWith("//", i)) { while (i < n && src.charAt(i) != '\n') i++; continue; }
            if (src.startsWith("/*", i)) {
                int j = src.indexOf("*/", i + 2);
                if (j < 0) throw new ActionKitError("bad_source", "unterminated comment in proto source");
                i = j + 2;
                continue;
            }
            if (ch == '"' || ch == '\'') {
                int j = i + 1;
                StringBuilder s = new StringBuilder();
                while (j < n && src.charAt(j) != ch) {
                    if (src.charAt(j) == '\n') throw new ActionKitError("bad_source", "unterminated string in proto source");
                    if (src.charAt(j) == '\\') { if (j + 1 < n) s.append(src.charAt(j + 1)); j += 2; } else s.append(src.charAt(j++));
                }
                if (j >= n) throw new ActionKitError("bad_source", "unterminated string in proto source");
                push = new Tok("str", s.toString());
                i = j + 1;
            } else if (idStart(ch)) {
                int j = i + 1;
                while (j < n && idChar(src.charAt(j))) j++;
                push = new Tok("id", src.substring(i, j));
                i = j;
            } else if (ch == '-' || (ch >= '0' && ch <= '9')) {
                int j = i + 1;
                while (j < n && numChar(src.charAt(j))) j++;
                push = new Tok("num", src.substring(i, j));
                i = j;
            } else if ("{}[]()<>=;,:".indexOf(ch) >= 0) { push = new Tok("p", String.valueOf(ch)); i++; }
            else throw new ActionKitError("bad_source", "unexpected character in proto source at offset " + i);
            if (out.size() >= maxTokens) throw new ActionKitError("import_limit", "the proto source has too many tokens");
            out.add(push);
        }
        return out;
    }

    private static final Pattern UPPER_WORD = Pattern.compile("[A-Z_]+");

    private static final class PP {
        int i = 0;
        String pkg = "";
        final List<Tok> toks;
        final ProtoModel m;
        final int maxDepth;
        PP(List<Tok> toks, ProtoModel m, int maxDepth) { this.toks = toks; this.m = m; this.maxDepth = maxDepth; }

        Tok cur() { return i < toks.size() ? toks.get(i) : null; }
        boolean is(String v) { Tok t = cur(); return t != null && !"str".equals(t.t) && t.v.equals(v); }
        boolean eat(String v) { if (is(v)) { i++; return true; } return false; }
        ActionKitError fail(String msg) { return new ActionKitError("bad_source", "proto parse error: " + msg + " near '" + clip(cur() == null ? "<end>" : cur().v, 30) + "'"); }
        void expect(String v) { if (!eat(v)) throw fail("expected '" + v + "'"); }
        String id() { Tok t = cur(); if (t == null || !"id".equals(t.t)) throw fail("expected an identifier"); i++; return t.v; }

        /** Skip to the matching close of an already-opened bracket. */
        void skipTo(String open, String close) {
            int depth = 1;
            while (depth > 0) {
                Tok t = i < toks.size() ? toks.get(i) : null;
                i++;
                if (t == null) throw fail("unterminated block");
                if ("p".equals(t.t)) { if (t.v.equals(open)) depth++; else if (t.v.equals(close)) depth--; }
            }
        }

        void skipStatement() {
            while (cur() != null && !is(";")) {
                if (is("{")) { i++; skipTo("{", "}"); return; }
                i++;
            }
            eat(";");
        }

        void file() {
            while (cur() != null) {
                if (eat(";")) continue;
                String kw = id();
                if (kw.equals("package")) { pkg = id(); expect(";"); }
                else if (kw.equals("message")) message(pkg, 0);
                else if (kw.equals("enum")) enumDef(pkg);
                else if (kw.equals("service")) service();
                else if (kw.equals("extend")) { id(); expect("{"); skipTo("{", "}"); }
                else skipStatement();
            }
        }

        String qual(String scope, String name) { return scope.isEmpty() ? name : scope + "." + name; }

        void enumDef(String scope) {
            String name = id();
            String full = qual(scope, name);
            expect("{");
            List<String> values = new ArrayList<>();
            while (!is("}")) {
                if (cur() == null) throw fail("unterminated enum");
                if (is("option") || is("reserved")) { skipStatement(); continue; }
                values.add(id());
                skipStatement();
            }
            expect("}");
            PEnum e = new PEnum();
            e.full = full;
            e.values = values;
            m.enums.put(full, e);
        }

        /** Field options: collect {@code field_behavior} names; everything else is skipped. */
        List<String> fieldOptions() {
            List<String> behavior = new ArrayList<>();
            if (!eat("[")) return behavior;
            int depth = 1;
            boolean inBehavior = false;
            while (depth > 0) {
                Tok t = i < toks.size() ? toks.get(i) : null;
                i++;
                if (t == null) throw fail("unterminated field options");
                if ("p".equals(t.t)) {
                    if (t.v.equals("[") || t.v.equals("{")) depth++;
                    else if (t.v.equals("]") || t.v.equals("}")) depth--;
                    else if (t.v.equals(",")) inBehavior = false;
                } else if ("id".equals(t.t)) {
                    if (t.v.endsWith("field_behavior")) inBehavior = true;
                    else if (inBehavior && UPPER_WORD.matcher(t.v).matches()) behavior.add(t.v);
                }
            }
            return behavior;
        }

        void field(PMsg msg, String full, String label, boolean oneof) {
            boolean repeated = "repeated".equals(label);
            String type = id();
            String[] map = null;
            if (type.equals("map") && eat("<")) { String k = id(); expect(","); String v = id(); expect(">"); map = new String[] {k, v}; type = "map"; repeated = false; }
            String fname = id();
            expect("=");
            i++; // field number
            List<String> behavior = fieldOptions();
            expect(";");
            PField f = new PField();
            f.name = fname; f.type = type; f.scope = full; f.repeated = repeated; f.optional = "optional".equals(label) || oneof; f.map = map; f.behavior = behavior;
            msg.fields.add(f);
        }

        void message(String scope, int depth) {
            if (depth > maxDepth) throw new ActionKitError("import_limit", "proto message nesting is too deep");
            String name = id();
            String full = qual(scope, name);
            PMsg msg = new PMsg();
            msg.full = full;
            m.messages.put(full, msg);
            expect("{");
            while (!is("}")) {
                if (cur() == null) throw fail("unterminated message");
                if (eat(";")) continue;
                String kw = "id".equals(cur().t) ? cur().v : "";
                if (kw.equals("message")) { i++; message(full, depth + 1); continue; }
                if (kw.equals("enum")) { i++; enumDef(full); continue; }
                if (kw.equals("oneof")) {
                    i++; id(); expect("{");
                    while (!is("}")) {
                        if (cur() == null) throw fail("unterminated oneof");
                        if (is("option")) { skipStatement(); continue; }
                        field(msg, full, null, true);
                    }
                    expect("}");
                    continue;
                }
                if (kw.equals("option") || kw.equals("reserved") || kw.equals("extensions")) { skipStatement(); continue; }
                if (kw.equals("extend")) { i++; id(); expect("{"); skipTo("{", "}"); continue; }
                if (kw.equals("group")) { skipStatement(); continue; }
                if (kw.equals("repeated") || kw.equals("optional") || kw.equals("required")) { i++; field(msg, full, kw, false); continue; }
                field(msg, full, null, false);
            }
            expect("}");
        }

        boolean streamKw() { Tok t = cur(); if (t != null && t.v.equals("stream") && "id".equals(t.t)) { i++; return true; } return false; }

        void service() {
            String name = id();
            String full = qual(pkg, name);
            PService svc = new PService();
            svc.full = full;
            svc.name = name;
            expect("{");
            while (!is("}")) {
                if (cur() == null) throw fail("unterminated service");
                if (eat(";")) continue;
                String kw = id();
                if (!kw.equals("rpc")) { skipStatement(); continue; }
                String mname = id();
                expect("(");
                boolean cs = streamKw();
                String input = id();
                expect(")");
                if (!id().equals("returns")) throw fail("expected 'returns'");
                expect("(");
                boolean ss = streamKw();
                String output = id();
                expect(")");
                PMethod me = new PMethod();
                me.name = mname; me.input = input; me.output = output; me.cs = cs; me.ss = ss; me.scope = pkg;
                if (eat("{")) {
                    while (!is("}")) {
                        if (cur() == null) throw fail("unterminated rpc body");
                        if (!is("option")) { skipStatement(); continue; }
                        i++;
                        String oname;
                        if (eat("(")) { oname = id(); expect(")"); } else oname = id();
                        expect("=");
                        if (is("{")) {
                            i++;
                            int depth = 1;
                            while (depth > 0) {
                                Tok t = i < toks.size() ? toks.get(i) : null;
                                i++;
                                if (t == null) throw fail("unterminated option");
                                if ("p".equals(t.t)) { if (t.v.equals("{")) depth++; else if (t.v.equals("}")) depth--; continue; }
                                if (depth == 1 && oname.endsWith("http") && "id".equals(t.t) && List.of("get", "put", "post", "delete", "patch").contains(t.v) && is(":")) {
                                    i++;
                                    String path = cur() != null && "str".equals(cur().t) ? cur().v : "";
                                    i++;
                                    if (me.http == null) { me.http = new PHttp(); me.http.method = t.v.toUpperCase(java.util.Locale.ROOT); me.http.path = path; }
                                } else if (depth == 1 && oname.endsWith("http") && "id".equals(t.t) && t.v.equals("body") && is(":")) {
                                    i++;
                                    if (cur() != null && "str".equals(cur().t) && me.http != null) me.http.body = cur().v;
                                    i++;
                                }
                            }
                            eat(";");
                        } else {
                            Tok v = cur();
                            i++;
                            if (oname.endsWith("idempotency_level") && v != null) me.idem = v.v;
                            eat(";");
                        }
                    }
                    expect("}");
                    eat(";");
                } else expect(";");
                svc.methods.add(me);
            }
            expect("}");
            m.services.add(svc);
        }
    }

    public static ProtoModel parseProto(String src) { return parseProto(src, 2_000_000); }

    public static ProtoModel parseProto(String src, int maxTokens) {
        ProtoModel m = new ProtoModel();
        new PP(lex(src, maxTokens), m, 32).file();
        return m;
    }

    // ---- binary descriptor set ----

    private static final class Reader {
        final byte[] b;
        int p;
        final int end;
        Reader(byte[] b, int p, int end) { this.b = b; this.p = p; this.end = end; }
        boolean more() { return p < end; }

        double varint() {
            double r = 0, mul = 1;
            for (int k = 0; k < 10; k++) {
                if (p >= end) throw new ActionKitError("bad_source", "truncated descriptor");
                int by = b[p++] & 0xff;
                r += (by & 0x7f) * mul;
                if ((by & 0x80) == 0) return r;
                mul *= 128;
            }
            throw new ActionKitError("bad_source", "overlong varint in descriptor");
        }

        Reader len() {
            double n = varint();
            if (n > end - p) throw new ActionKitError("bad_source", "descriptor length exceeds the buffer");
            Reader r = new Reader(b, p, p + (int) n);
            p += (int) n;
            return r;
        }

        void skip(double wt) {
            if (wt == 0) varint();
            else if (wt == 1) adv(8);
            else if (wt == 2) len();
            else if (wt == 5) adv(4);
            else throw new ActionKitError("bad_source", "unsupported wire type " + AttestCommon.jsNumString(wt) + " in descriptor");
        }

        void adv(int n) { if (n > end - p) throw new ActionKitError("bad_source", "truncated descriptor"); p += n; }
        String str() { Reader r = len(); return decodeUtf8(b, r.p, r.end); }
    }

    /** TextDecoder('utf-8') without fatal: maximal-subpart replacement, and a leading byte order mark is dropped. */
    static String decodeUtf8(byte[] b, int from, int to) {
        StringBuilder out = new StringBuilder();
        int cp = 0, needed = 0, seen = 0, lower = 0x80, upper = 0xBF;
        for (int i = from; i < to; i++) {
            int by = b[i] & 0xff;
            if (needed == 0) {
                if (by <= 0x7F) out.append((char) by);
                else if (by >= 0xC2 && by <= 0xDF) { needed = 1; cp = by & 0x1F; }
                else if (by >= 0xE0 && by <= 0xEF) { if (by == 0xE0) lower = 0xA0; if (by == 0xED) upper = 0x9F; needed = 2; cp = by & 0xF; }
                else if (by >= 0xF0 && by <= 0xF4) { if (by == 0xF0) lower = 0x90; if (by == 0xF4) upper = 0x8F; needed = 3; cp = by & 7; }
                else out.append('�');
            } else {
                if (by < lower || by > upper) { cp = 0; needed = 0; seen = 0; lower = 0x80; upper = 0xBF; out.append('�'); i--; continue; }
                lower = 0x80; upper = 0xBF;
                cp = (cp << 6) | (by & 0x3F);
                if (++seen == needed) { out.appendCodePoint(cp); cp = 0; needed = 0; seen = 0; }
            }
        }
        if (needed != 0) out.append('�');
        return out.length() > 0 && out.charAt(0) == '﻿' ? out.substring(1) : out.toString();
    }

    private static final String[] FTYPES = new String[19];
    static {
        String[] names = {"double", "float", "int64", "uint64", "int32", "fixed64", "fixed32", "bool", "string"};
        for (int i = 0; i < names.length; i++) FTYPES[i + 1] = names[i];
        FTYPES[12] = "bytes"; FTYPES[13] = "uint32"; FTYPES[15] = "sfixed32"; FTYPES[16] = "sfixed64"; FTYPES[17] = "sint32"; FTYPES[18] = "sint64";
    }

    private static final class Tag {
        final double f, wt;
        Tag(double f, double wt) { this.f = f; this.wt = wt; }
    }

    private static Tag tag(Reader r) { double t = r.varint(); return new Tag(Math.floor(t / 8), t % 8); }

    private static final class FieldDesc {
        String name = "", typeName = "";
        double type = 0, label = 1;
        boolean proto3opt;
        List<Double> behavior = new ArrayList<>();
    }

    private static void readEnum(ProtoModel m, Reader r, String scope) {
        String name = "";
        List<String> values = new ArrayList<>();
        while (r.more()) {
            Tag g = tag(r);
            if (g.f == 1 && g.wt == 2) name = r.str();
            else if (g.f == 2 && g.wt == 2) {
                Reader v = r.len();
                while (v.more()) { Tag vg = tag(v); if (vg.f == 1 && vg.wt == 2) values.add(v.str()); else v.skip(vg.wt); }
            } else r.skip(g.wt);
        }
        String full = scope.isEmpty() ? name : scope + "." + name;
        PEnum e = new PEnum();
        e.full = full;
        e.values = values;
        m.enums.put(full, e);
    }

    private static String behaviorName(double b) { return b == 2 ? "REQUIRED" : b == 3 ? "OUTPUT_ONLY" : b == 4 ? "INPUT_ONLY" : b == 5 ? "IMMUTABLE" : ""; }

    private static void readMsg(ProtoModel m, Reader r, String scope, int depth) {
        if (depth > 32) throw new ActionKitError("import_limit", "descriptor message nesting is too deep");
        String name = "";
        List<FieldDesc> fields = new ArrayList<>();
        List<Reader> nested = new ArrayList<>(), enums = new ArrayList<>();
        boolean mapEntry = false;
        while (r.more()) {
            Tag g = tag(r);
            if (g.f == 1 && g.wt == 2) name = r.str();
            else if (g.f == 2 && g.wt == 2) {
                Reader fr = r.len();
                FieldDesc fd = new FieldDesc();
                while (fr.more()) {
                    Tag fg = tag(fr);
                    if (fg.f == 1 && fg.wt == 2) fd.name = fr.str();
                    else if (fg.f == 4 && fg.wt == 0) fd.label = fr.varint();
                    else if (fg.f == 5 && fg.wt == 0) fd.type = fr.varint();
                    else if (fg.f == 6 && fg.wt == 2) fd.typeName = fr.str();
                    else if (fg.f == 17 && fg.wt == 0) fd.proto3opt = fr.varint() == 1;
                    else if (fg.f == 8 && fg.wt == 2) {
                        Reader o = fr.len();
                        while (o.more()) {
                            Tag og = tag(o);
                            if (og.f == 1052 && og.wt == 0) fd.behavior.add(o.varint());
                            else if (og.f == 1052 && og.wt == 2) { Reader pk = o.len(); while (pk.more()) fd.behavior.add(pk.varint()); }
                            else o.skip(og.wt);
                        }
                    } else fr.skip(fg.wt);
                }
                fields.add(fd);
            } else if (g.f == 3 && g.wt == 2) nested.add(r.len());
            else if (g.f == 4 && g.wt == 2) enums.add(r.len());
            else if (g.f == 7 && g.wt == 2) {
                Reader o = r.len();
                while (o.more()) { Tag og = tag(o); if (og.f == 7 && og.wt == 0) mapEntry = o.varint() == 1; else o.skip(og.wt); }
            } else r.skip(g.wt);
        }
        String full = scope.isEmpty() ? name : scope + "." + name;
        PMsg msg = new PMsg();
        msg.full = full;
        msg.mapEntry = mapEntry;
        for (FieldDesc f : fields) {
            PField pf = new PField();
            pf.name = f.name; pf.scope = full; pf.repeated = f.label == 3; pf.optional = f.proto3opt;
            pf.type = !f.typeName.isEmpty() ? f.typeName : (f.type >= 1 && f.type <= 18 && f.type == Math.rint(f.type) && FTYPES[(int) f.type] != null ? FTYPES[(int) f.type] : "bytes");
            for (double b : f.behavior) pf.behavior.add(behaviorName(b));
            msg.fields.add(pf);
        }
        m.messages.put(full, msg);
        for (Reader n : nested) readMsg(m, n, full, depth + 1);
        for (Reader e : enums) readEnum(m, e, full);
    }

    public static ProtoModel parseDescriptorSet(byte[] bytes) {
        ProtoModel m = new ProtoModel();
        Reader top = new Reader(bytes, 0, bytes.length);
        while (top.more()) {
            Tag g = tag(top);
            if (g.f != 1 || g.wt != 2) { top.skip(g.wt); continue; }
            Reader fr = top.len();
            String pkg = "";
            List<Reader> msgs = new ArrayList<>(), enums = new ArrayList<>(), svcs = new ArrayList<>();
            // package may follow the messages in the wire order: collect first, then resolve scopes
            while (fr.more()) {
                Tag fg = tag(fr);
                if (fg.f == 2 && fg.wt == 2) pkg = fr.str();
                else if (fg.f == 4 && fg.wt == 2) msgs.add(fr.len());
                else if (fg.f == 5 && fg.wt == 2) enums.add(fr.len());
                else if (fg.f == 6 && fg.wt == 2) svcs.add(fr.len());
                else fr.skip(fg.wt);
            }
            for (Reader r : msgs) readMsg(m, r, pkg, 0);
            for (Reader r : enums) readEnum(m, r, pkg);
            for (Reader r : svcs) {
                String name = "";
                List<PMethod> methods = new ArrayList<>();
                while (r.more()) {
                    Tag sg = tag(r);
                    if (sg.f == 1 && sg.wt == 2) name = r.str();
                    else if (sg.f == 2 && sg.wt == 2) {
                        Reader mr = r.len();
                        PMethod me = new PMethod();
                        me.scope = pkg;
                        while (mr.more()) {
                            Tag mg = tag(mr);
                            if (mg.f == 1 && mg.wt == 2) me.name = mr.str();
                            else if (mg.f == 2 && mg.wt == 2) me.input = mr.str();
                            else if (mg.f == 3 && mg.wt == 2) me.output = mr.str();
                            else if (mg.f == 5 && mg.wt == 0) me.cs = mr.varint() == 1;
                            else if (mg.f == 6 && mg.wt == 0) me.ss = mr.varint() == 1;
                            else if (mg.f == 4 && mg.wt == 2) {
                                Reader o = mr.len();
                                while (o.more()) {
                                    Tag og = tag(o);
                                    if (og.f == 34 && og.wt == 0) { double lv = o.varint(); me.idem = lv == 1 ? "NO_SIDE_EFFECTS" : lv == 2 ? "IDEMPOTENT" : "IDEMPOTENCY_UNKNOWN"; }
                                    else if (og.f == 72295728 && og.wt == 2) {
                                        Reader h = o.len();
                                        while (h.more()) {
                                            Tag hg = tag(h);
                                            String verb = hg.f == 2 ? "GET" : hg.f == 3 ? "PUT" : hg.f == 4 ? "POST" : hg.f == 5 ? "DELETE" : hg.f == 6 ? "PATCH" : null;
                                            if (verb != null && hg.wt == 2) { if (me.http == null) { me.http = new PHttp(); me.http.method = verb; me.http.path = h.str(); } else h.str(); }
                                            else if (hg.f == 7 && hg.wt == 2) { String bd = h.str(); if (me.http != null) me.http.body = bd; }
                                            else h.skip(hg.wt);
                                        }
                                    } else o.skip(og.wt);
                                }
                            } else mr.skip(mg.wt);
                        }
                        methods.add(me);
                    } else r.skip(sg.wt);
                }
                PService s = new PService();
                s.full = pkg.isEmpty() ? name : pkg + "." + name;
                s.name = name;
                s.methods = methods;
                m.services.add(s);
            }
        }
        return m;
    }

    // ---- model to params ----

    private static String resolveName(ProtoModel m, String name, String scope) {
        if (name.startsWith(".")) return name.substring(1);
        String[] parts = scope.isEmpty() ? new String[0] : scope.split("\\.", -1);
        for (int k = parts.length; k >= 0; k--) {
            StringBuilder cand = new StringBuilder();
            for (int j = 0; j < k; j++) cand.append(parts[j]).append('.');
            cand.append(name);
            String cs = cand.toString();
            if (m.messages.containsKey(cs) || m.enums.containsKey(cs)) return cs;
        }
        return m.messages.containsKey(name) || m.enums.containsKey(name) ? name : null;
    }

    private static final Set<String> WKT_STRING = Set.of("google.protobuf.StringValue", "google.protobuf.BytesValue");
    private static final Set<String> WKT_INT = Set.of("google.protobuf.Int32Value", "google.protobuf.Int64Value", "google.protobuf.UInt32Value", "google.protobuf.UInt64Value");

    private static Map<String, Object> one(ProtoModel m, String type, String scope, Ctx c, List<String> stack, String where, int[] budget) {
        if (SCALAR_NAMES.contains(type)) {
            if (type.contains("int") || type.contains("fixed")) return Jx.obj("type", "integer", "format", "int64");
            if (type.equals("bool")) return Jx.obj("type", "boolean");
            if (type.equals("string")) return Jx.obj("type", "string");
            if (type.equals("bytes")) return Jx.obj("type", "string");
            return Jx.obj("type", "number");
        }
        String abs = type.startsWith(".") ? type.substring(1) : null;
        String eff = abs != null ? abs : type;
        if ("google.protobuf.Timestamp".equals(abs) || type.equals("google.protobuf.Timestamp")) return Jx.obj("type", "string", "format", "date-time");
        if (WKT_STRING.contains(eff)) return Jx.obj("type", "string");
        if (WKT_INT.contains(eff)) return Jx.obj("type", "integer", "format", "int64");
        if (eff.equals("google.protobuf.BoolValue")) return Jx.obj("type", "boolean");
        if (eff.startsWith("google.protobuf.")) return new LinkedHashMap<>();
        String full = resolveName(m, type, scope);
        if (full == null) { addTodo(c, where, "unknown_type", "type '" + clip(type, 60) + "' is not defined in the proto source (declared string)"); return new LinkedHashMap<>(); }
        PEnum en = m.enums.get(full);
        if (en != null) return Jx.obj("type", "string", "enum", new ArrayList<Object>(new LinkedHashSet<>(en.values)));
        return msgSchema(m, full, c, stack, where, budget);
    }

    private static Map<String, Object> fieldSchema(ProtoModel m, PField f, Ctx c, List<String> stack, String where, int[] budget) {
        if (f.map != null) return Jx.obj("type", "object");
        Map<String, Object> s = one(m, f.type, f.scope, c, stack, where, budget);
        return f.repeated ? Jx.obj("type", "array", "items", s) : s;
    }

    private static Map<String, Object> msgSchema(ProtoModel m, String full, Ctx c, List<String> stack, String where, int[] budget) {
        PMsg msg = m.messages.get(full);
        if (msg == null) return new LinkedHashMap<>();
        if (stack.contains(full)) { addTodo(c, where, "cyclic_ref", "message '" + clip(full, 80) + "' is recursive (declared string; refine or drop)"); return new LinkedHashMap<>(); }
        if (stack.size() > c.lim.maxRefDepth || --budget[0] <= 0) { addTodo(c, where, "ref_budget", "message expansion stopped at the bound (declared string; refine or drop)"); return new LinkedHashMap<>(); }
        Map<String, Object> properties = new LinkedHashMap<>();
        List<Object> required = new ArrayList<>();
        List<String> ns = new ArrayList<>(stack);
        ns.add(full);
        for (PField f : msg.fields) {
            if (f.behavior.contains("OUTPUT_ONLY")) continue;
            putProp(properties, f.name, fieldSchema(m, f, c, ns, where + "." + f.name, budget));
            if (f.behavior.contains("REQUIRED")) required.add(f.name);
        }
        return Jx.obj("type", "object", "properties", properties, "required", required);
    }

    public static Map<String, Object> importGrpc(Object source, Map<String, Object> opts) {
        Ctx c = newCtx("grpc", source, opts);
        ProtoModel m;
        if (source instanceof String) m = parseProto((String) source);
        else if (source instanceof byte[]) m = parseDescriptorSet((byte[]) source);
        else throw new ActionKitError("bad_source", "a gRPC source is .proto text or a binary FileDescriptorSet");
        List<PService> svcs = new ArrayList<>(m.services);
        svcs.sort((a, b) -> IntentJs.compareUtf8(a.full, b.full));
        for (PService svc : svcs) {
            List<PMethod> ms = new ArrayList<>(svc.methods);
            ms.sort((a, b) -> IntentJs.compareUtf8(a.name, b.name));
            for (PMethod me : ms) {
                String where = svc.name + "/" + me.name;
                c.root = null;
                Budget bud = newBudget(c);
                String rn = resolveName(m, me.input, me.scope);
                String input = rn != null ? rn : (me.input.startsWith(".") ? me.input.substring(1) : me.input);
                Map<String, Object> schema = msgSchema(m, input, c, new ArrayList<>(), where, new int[] {(int) c.lim.maxRefNodes});
                Map<String, Object> params = new LinkedHashMap<>();
                if (schema.get("properties") != null) flattenObject(schema, c, bud, where, params);
                else if (!m.messages.containsKey(input) && !input.startsWith("google.protobuf.")) addTodo(c, where, "unknown_type", "request type '" + clip(me.input, 60) + "' is not defined in the source (no parameters)");
                String hm = me.http != null ? me.http.method : null;
                String eff = "GET".equals(hm) ? "read" : "DELETE".equals(hm) ? "delete" : "POST".equals(hm) ? "create" : "PUT".equals(hm) || "PATCH".equals(hm) ? "update" : "NO_SIDE_EFFECTS".equals(me.idem) ? "read" : "update";
                boolean natural = "NO_SIDE_EFFECTS".equals(me.idem) || "IDEMPOTENT".equals(me.idem) || "GET".equals(hm) || "PUT".equals(hm) || "DELETE".equals(hm);
                List<String> traits = null;
                if (me.cs || me.ss) { traits = withTrait(traits, "pca.bulk"); addTodo(c, where, "streaming", "a streaming method: acts on many messages (pca.bulk added)"); }
                Draft d = new Draft();
                d.name = svc.name + " " + me.name;
                d.title = camelSplit(me.name);
                d.effects = new ArrayList<>(List.of(eff));
                d.scope = "one";
                d.params = params;
                if (natural) d.idempotency = Jx.obj("mode", "natural");
                if (traits != null) d.traits = traits;
                Map<String, Object> b = Jx.obj("grpc", Jx.obj("service", clip(svc.full, 250), "method", clip(me.name, 250)));
                if (me.http != null && me.http.path != null && !me.http.path.isEmpty()) b.put("http", Jx.obj("method", me.http.method, "path", clip(me.http.path, 250)));
                d.bindings = b;
                emitDef(c, d);
            }
        }
        return finish(c);
    }

    private static String camelSplit(String s) { return s.replaceAll("([a-z0-9])([A-Z])", "$1 $2"); }
}
