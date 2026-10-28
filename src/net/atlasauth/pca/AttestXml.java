package net.atlasauth.pca;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * A small XML reader and a canonicaliser (inclusive C14N; identical to C14N 1.1 for documents without xml:* attributes,
 * which the RIM profile refuses) for the NVIDIA RIM XMLDSig check. Only the subset the profile needs is supported: elements,
 * attributes, namespaces, text, CDATA and the predefined and numeric character references. A comment, processing
 * instruction or DOCTYPE is not interpreted: the first of them (in document order) is recorded as a profile violation, and
 * the verifier refuses the document before any cryptography. Port of the Go attest_xml.go.
 */
public final class AttestXml {
    private AttestXml() {}

    public static final class Attr {
        public String name = "";
        public String prefix = "";
        public String local = "";
        public String ns = "";
        public String value = "";
    }

    public static final class Decl {
        public final String prefix;
        public final String uri;

        Decl(String prefix, String uri) {
            this.prefix = prefix;
            this.uri = uri;
        }
    }

    public static final class Node {
        public boolean elem;
        public String name = "";
        public String prefix = "";
        public String local = "";
        public String ns = "";
        public final List<Attr> attrs = new ArrayList<>();
        public final List<Decl> decls = new ArrayList<>();
        public final List<Node> children = new ArrayList<>();
        public String text = "";
        public Node parent;

        /** The namespace URI bound to the prefix ("" is the default namespace) through the element's ancestors; null when unbound. */
        public String lookupNs(String prefix) {
            for (Node e = this; e != null; e = e.parent) {
                for (Decl d : e.decls) if (d.prefix.equals(prefix)) return d.uri;
            }
            return null;
        }

        void appendText(String t) {
            int k = children.size();
            if (k > 0 && !children.get(k - 1).elem) {
                children.get(k - 1).text += t;
                return;
            }
            Node n = new Node();
            n.text = t;
            n.parent = this;
            children.add(n);
        }

        /** The value of the attribute with this qualified name, or "". */
        public String attr(String name) {
            for (Attr a : attrs) if (a.name.equals(name)) return a.value;
            return "";
        }

        public String textContent() {
            if (!elem) return text;
            StringBuilder sb = new StringBuilder();
            for (Node c : children) sb.append(c.textContent());
            return sb.toString();
        }

        public List<Node> elementChildren() {
            List<Node> out = new ArrayList<>();
            for (Node c : children) if (c.elem) out.add(c);
            return out;
        }

        public List<Node> elementChildrenNs(String ns, String local) {
            List<Node> out = new ArrayList<>();
            for (Node c : elementChildren()) if (c.ns.equals(ns) && c.local.equals(local)) out.add(c);
            return out;
        }

        /** Counts the descendant elements with the given namespace and local name. */
        public int descendantsNs(String ns, String local) {
            int total = 0;
            for (Node c : elementChildren()) {
                if (c.ns.equals(ns) && c.local.equals(local)) total++;
                total += c.descendantsNs(ns, local);
            }
            return total;
        }

        public void removeChild(Node c) {
            for (int i = 0; i < children.size(); i++) {
                if (children.get(i) == c) {
                    children.remove(i);
                    return;
                }
            }
        }

        /** The in-scope namespace bindings of the element (its own declarations included). */
        public Map<String, String> scope() {
            List<Node> chain = new ArrayList<>();
            for (Node e = this; e != null; e = e.parent) chain.add(e);
            Map<String, String> out = new HashMap<>();
            for (int i = chain.size() - 1; i >= 0; i--) for (Decl d : chain.get(i).decls) out.put(d.prefix, d.uri);
            return out;
        }

        void resolveNames() {
            int i = name.indexOf(':');
            prefix = i >= 0 ? name.substring(0, i) : "";
            local = i >= 0 ? name.substring(i + 1) : name;
            String uri = lookupNs(prefix);
            if (!prefix.isEmpty() && uri == null) throw new AttestException("namespace prefix " + prefix + " is not bound");
            ns = uri == null ? "" : uri;
            for (Attr a : attrs) {
                if (a.prefix.isEmpty()) continue;
                String u = lookupNs(a.prefix);
                if (u == null) throw new AttestException("namespace prefix " + a.prefix + " is not bound");
                a.ns = u;
            }
        }
    }

    public static final class Doc {
        public Node root;
        /** The first comment / PI / DOCTYPE / xml:* attribute in document order, as the profile violation text; "" when none. */
        public String violation = "";
    }

    static boolean isXmlSpace(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

    private static boolean asciiDigits(String s, int from, boolean hex) {
        if (from >= s.length()) return false;
        for (int i = from; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean ok = (c >= '0' && c <= '9') || (hex && ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')));
            if (!ok) return false;
        }
        return true;
    }

    static String xmlDecode(String s) {
        if (s.indexOf('&') < 0) return s;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); ) {
            if (s.charAt(i) != '&') {
                sb.append(s.charAt(i));
                i++;
                continue;
            }
            int j = s.indexOf(';', i);
            if (j < 0) throw new AttestException("unterminated entity reference");
            String ent = s.substring(i + 1, j);
            i = j + 1;
            switch (ent) {
                case "lt": sb.append('<'); break;
                case "gt": sb.append('>'); break;
                case "amp": sb.append('&'); break;
                case "quot": sb.append('"'); break;
                case "apos": sb.append('\''); break;
                default: {
                    if (!ent.startsWith("#")) throw new AttestException("undefined entity &" + ent + ";");
                    boolean hex = ent.startsWith("#x");
                    int from = hex ? 2 : 1;
                    long n = -1;
                    // strconv.ParseInt(.., base, 32) also takes a sign; a signed value is never a legal character below
                    if (asciiDigits(ent, from, hex)) {
                        String digits = ent.substring(from).replaceFirst("^0+(?=.)", "");
                        if (digits.length() <= 8) n = Long.parseLong(digits, hex ? 16 : 10);
                    }
                    boolean legal = n == 0x9 || n == 0xa || n == 0xd || (n >= 0x20 && n <= 0xd7ff) || (n >= 0xe000 && n <= 0xfffd) || (n >= 0x10000 && n <= 0x10ffff);
                    if (!legal) throw new AttestException("invalid character reference &" + ent + ";");
                    sb.appendCodePoint((int) n);
                }
            }
        }
        return sb.toString();
    }

    /** Parses the XML subset; AttestException on anything malformed. */
    public static Doc parseXml(String s) {
        Doc doc = new Doc();
        Node cur = null;
        int i = 0;
        while (i < s.length()) {
            if (s.charAt(i) != '<') {
                int end = s.indexOf('<', i);
                if (end < 0) end = s.length();
                String txt = s.substring(i, end);
                i = end;
                if (cur == null) {
                    for (int k = 0; k < txt.length(); k++) {
                        if (!isXmlSpace(txt.charAt(k))) throw new AttestException("text outside the document element");
                    }
                    continue;
                }
                cur.appendText(xmlDecode(txt));
                continue;
            }
            if (s.startsWith("<!--", i)) {
                int j = s.indexOf("-->", i + 4);
                if (j < 0) throw new AttestException("unterminated comment");
                note(doc, "XML comments are not permitted");
                i = j + 3;
            } else if (s.startsWith("<?", i)) {
                int j = s.indexOf("?>", i);
                if (j < 0) throw new AttestException("unterminated processing instruction");
                note(doc, "XML processing instructions are not permitted");
                i = j + 2;
            } else if (s.startsWith("<![CDATA[", i)) {
                int j = s.indexOf("]]>", i);
                if (j < 0 || cur == null) throw new AttestException("misplaced or unterminated CDATA section");
                cur.appendText(s.substring(i + 9, j));
                i = j + 3;
            } else if (s.startsWith("<!DOCTYPE", i)) {
                int depth = 0;
                int j = i;
                for (; j < s.length(); j++) {
                    char c = s.charAt(j);
                    if (c == '[') depth++;
                    else if (c == ']') depth--;
                    else if (c == '>' && depth <= 0) break;
                }
                if (j >= s.length()) throw new AttestException("unterminated DOCTYPE");
                note(doc, "DTD / DOCTYPE is not permitted");
                i = j + 1;
            } else if (s.startsWith("</", i)) {
                int j = s.indexOf('>', i);
                if (j < 0 || cur == null) throw new AttestException("unexpected end tag");
                int e = j;
                while (e > i + 2 && " \t\r\n".indexOf(s.charAt(e - 1)) >= 0) e--;
                String name = s.substring(i + 2, e);
                if (!name.equals(cur.name)) throw new AttestException("end tag </" + name + "> does not match <" + cur.name + ">");
                cur = cur.parent;
                i = j + 1;
            } else {
                StartTag st = parseStartTag(s.substring(i), doc);
                i += st.n;
                st.node.parent = cur;
                if (cur == null) {
                    if (doc.root != null) throw new AttestException("more than one document element");
                    doc.root = st.node;
                } else {
                    cur.children.add(st.node);
                }
                st.node.resolveNames();
                if (!st.selfClose) cur = st.node;
            }
        }
        if (cur != null) throw new AttestException("element <" + cur.name + "> is not closed");
        if (doc.root == null) throw new AttestException("no document element");
        return doc;
    }

    private static void note(Doc doc, String v) {
        if (doc.violation.isEmpty()) doc.violation = v;
    }

    private static final class StartTag {
        Node node;
        boolean selfClose;
        int n;
    }

    /** Reads one start tag at the beginning of rest; n is the number of chars consumed. */
    private static StartTag parseStartTag(String rest, Doc doc) {
        int i = 1;
        int j = i;
        while (j < rest.length() && !isXmlSpace(rest.charAt(j)) && rest.charAt(j) != '/' && rest.charAt(j) != '>') j++;
        String name = rest.substring(i, j);
        if (name.isEmpty()) throw new AttestException("malformed start tag");
        Node node = new Node();
        node.elem = true;
        node.name = name;
        Set<String> seen = new HashSet<>();
        i = j;
        StartTag st = new StartTag();
        st.node = node;
        while (true) {
            while (i < rest.length() && isXmlSpace(rest.charAt(i))) i++;
            if (i >= rest.length()) throw new AttestException("unterminated start tag");
            if (rest.charAt(i) == '>') {
                st.n = i + 1;
                return st;
            }
            if (rest.charAt(i) == '/') {
                if (i + 1 < rest.length() && rest.charAt(i + 1) == '>') {
                    st.selfClose = true;
                    st.n = i + 2;
                    return st;
                }
                throw new AttestException("malformed start tag");
            }
            int k = i;
            while (k < rest.length() && !isXmlSpace(rest.charAt(k)) && rest.charAt(k) != '=' && rest.charAt(k) != '>' && rest.charAt(k) != '/') k++;
            String aname = rest.substring(i, k);
            while (k < rest.length() && isXmlSpace(rest.charAt(k))) k++;
            if (aname.isEmpty() || k >= rest.length() || rest.charAt(k) != '=') throw new AttestException("malformed attribute");
            k++;
            while (k < rest.length() && isXmlSpace(rest.charAt(k))) k++;
            if (k >= rest.length() || (rest.charAt(k) != '"' && rest.charAt(k) != '\'')) throw new AttestException("unquoted attribute value");
            char q = rest.charAt(k);
            int e = rest.indexOf(q, k + 1);
            if (e < 0) throw new AttestException("unterminated attribute value");
            String raw = rest.substring(k + 1, e);
            if (raw.indexOf('<') >= 0) throw new AttestException("'<' in an attribute value");
            String val = xmlDecode(raw);
            i = e + 1;
            if (!seen.add(aname)) throw new AttestException("attribute " + aname + " is repeated");
            if (aname.toLowerCase(Locale.ROOT).startsWith("xml:")) note(doc, "xml:* attribute '" + aname + "' is not permitted (C14N 1.1 profile)");
            if (aname.equals("xmlns")) {
                node.decls.add(new Decl("", val));
            } else if (aname.startsWith("xmlns:")) {
                node.decls.add(new Decl(aname.substring(6), val));
            } else {
                Attr a = new Attr();
                int c = aname.indexOf(':');
                a.name = aname;
                a.prefix = c >= 0 ? aname.substring(0, c) : "";
                a.local = c >= 0 ? aname.substring(c + 1) : aname;
                a.value = val;
                node.attrs.add(a);
            }
        }
    }

    static String xmlEscapeText(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char r = s.charAt(i);
            switch (r) {
                case '&': sb.append("&amp;"); break;
                case '<': sb.append("&lt;"); break;
                case '>': sb.append("&gt;"); break;
                case '\r': sb.append("&#xD;"); break;
                default: sb.append(r);
            }
        }
        return sb.toString();
    }

    static String xmlEscapeAttr(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char r = s.charAt(i);
            switch (r) {
                case '&': sb.append("&amp;"); break;
                case '<': sb.append("&lt;"); break;
                case '"': sb.append("&quot;"); break;
                case '\t': sb.append("&#x9;"); break;
                case '\n': sb.append("&#xA;"); break;
                case '\r': sb.append("&#xD;"); break;
                default: sb.append(r);
            }
        }
        return sb.toString();
    }

    /**
     * The inclusive canonical form of the subtree at n, omitting the subtree skip (the enveloped-signature transform).
     * parentScope is the in-scope bindings of n's ancestors: an apex element renders every in-scope namespace.
     */
    public static String canonicalize(Node n, Map<String, String> parentScope, Node skip) {
        StringBuilder sb = new StringBuilder();
        c14nElement(sb, n, parentScope, new HashMap<String, String>(), skip);
        return sb.toString();
    }

    private static void c14nElement(StringBuilder sb, Node n, Map<String, String> parentScope, Map<String, String> rendered, Node skip) {
        Map<String, String> scope = new HashMap<>(parentScope);
        for (Decl d : n.decls) scope.put(d.prefix, d.uri);
        List<String> emit = new ArrayList<>();
        for (Map.Entry<String, String> e : scope.entrySet()) {
            String p = e.getKey();
            String uri = e.getValue();
            if (p.equals("xml") || (uri.isEmpty() && !p.isEmpty())) continue;
            String r = rendered.get(p);
            if (r == null) r = "";
            if (r.equals(uri)) continue;
            emit.add(p);
        }
        emit.sort(Json::compareUtf8);
        Map<String, String> newRendered = new HashMap<>(rendered);
        sb.append('<').append(n.name);
        for (String p : emit) {
            if (p.isEmpty()) sb.append(" xmlns=\"").append(xmlEscapeAttr(scope.get(p))).append('"');
            else sb.append(" xmlns:").append(p).append("=\"").append(xmlEscapeAttr(scope.get(p))).append('"');
            newRendered.put(p, scope.get(p));
        }
        List<Attr> attrs = new ArrayList<>(n.attrs);
        attrs.sort((a, b) -> {
            boolean an = a.ns.isEmpty();
            boolean bn = b.ns.isEmpty();
            if (an != bn) return an ? -1 : 1;
            return Json.compareUtf8(a.ns + a.local, b.ns + b.local);
        });
        for (Attr a : attrs) sb.append(' ').append(a.name).append("=\"").append(xmlEscapeAttr(a.value)).append('"');
        sb.append('>');
        for (Node c : n.children) {
            if (c == skip) continue;
            if (c.elem) c14nElement(sb, c, scope, newRendered, skip);
            else sb.append(xmlEscapeText(c.text));
        }
        sb.append("</").append(n.name).append('>');
    }
}
