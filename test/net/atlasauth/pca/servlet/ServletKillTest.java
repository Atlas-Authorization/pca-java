package net.atlasauth.pca.servlet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import net.atlasauth.pca.Json;
import net.atlasauth.pca.Pca;
import net.atlasauth.pca.spring.PcaInterceptor;

public class ServletKillTest {
    static final String VEC = "valid-raw-json-format-insensitive";
    static String json, aud, grantRef;
    static Map<String, Object> grant;
    static long now;
    static Clock clock;

    @SuppressWarnings("unchecked")
    static synchronized void init() throws Exception {
        if (json != null) return;
        Map<String, Object> core = (Map<String, Object>) Json.parseLenient(java.nio.file.Files.readString(java.nio.file.Path.of("conformance/vectors.json")));
        for (Object x : (java.util.List<Object>) core.get("vectors")) {
            Map<String, Object> v = (Map<String, Object>) x;
            if (VEC.equals(v.get("name"))) {
                json = (String) v.get("pcactn_json");
                grant = (Map<String, Object>) v.get("grant");
                aud = (String) ((Map<String, Object>) v.get("context")).get("aud");
                now = Json.asLong(((Map<String, Object>) v.get("context")).get("now"));
            }
        }
        grantRef = (String) ((Map<String, Object>) Json.parse(json)).get("grant_ref");
        clock = Clock.fixed(Instant.ofEpochMilli(now), ZoneOffset.UTC);
    }
    static GrantResolver resolver() { return ref -> grantRef.equals(ref) ? grant : null; }
    static String hdr(String text) { return Base64.getUrlEncoder().withoutPadding().encodeToString(text.getBytes(StandardCharsets.UTF_8)); }

    // ------------------------------------------------------------------ PcaResult
    @Test void resultShapes() {
        PcaResult a = PcaResult.of(PcaResult.Outcome.ABSENT, "none");
        assertEquals(PcaResult.Outcome.ABSENT, a.outcome());
        assertNull(a.verdict()); assertNull(a.pcactn());
        assertEquals("none", a.detail());
        assertFalse(a.allowed());
        assertEquals(401, a.status());
        assertNull(a.error());
        assertEquals("PCA realm=\"pca\"", a.wwwAuthenticate());
        assertEquals("{\"error\":\"pca_required\",\"error_description\":\"none\"}", a.jsonBody());
        assertEquals("{\"error\":\"pca_required\"}", PcaResult.of(PcaResult.Outcome.ABSENT, "").jsonBody());
        assertEquals("", PcaResult.of(PcaResult.Outcome.ABSENT, null).detail());
        assertEquals("", new PcaResult(PcaResult.Outcome.ABSENT, null, null, null).detail());

        PcaResult u = PcaResult.of(PcaResult.Outcome.UNDECODABLE, "bad \"x\" \\ y");
        assertEquals(401, u.status());
        assertEquals("invalid_request", u.error());
        assertEquals("PCA realm=\"pca\", error=\"invalid_request\"", u.wwwAuthenticate());
        assertEquals("{\"error\":\"invalid_request\",\"error_description\":\"bad \\\"x\\\" \\\\ y\"}", u.jsonBody());
        assertEquals("PCA realm=\"pca\", error=\"invalid_request\"", PcaResult.of(PcaResult.Outcome.UNDECODABLE, "").wwwAuthenticate());
        assertEquals("{\"error\":\"invalid_request\"}", PcaResult.of(PcaResult.Outcome.UNDECODABLE, "").jsonBody());

        PcaResult g = PcaResult.of(PcaResult.Outcome.UNKNOWN_GRANT, "nogrant");
        assertEquals(401, g.status());
        assertEquals("invalid_grant", g.error());
        assertEquals("PCA realm=\"pca\", error=\"invalid_grant\"", g.wwwAuthenticate());
        assertEquals("{\"error\":\"invalid_grant\",\"error_description\":\"nogrant\"}", g.jsonBody());

        Pca.Verdict v = net.atlasauth.pca.VerdictFactory.empty();
        PcaResult d = new PcaResult(PcaResult.Outcome.DENIED, v, "pc", "detail-text");
        assertEquals(403, d.status());
        assertEquals("insufficient_authority", d.error());
        assertSame(v, d.verdict());
        assertEquals("pc", d.pcactn());
        // verdict reason wins for DENIED when present, else detail
        assertEquals("PCA realm=\"pca\", error=\"insufficient_authority\"", d.wwwAuthenticate());
        v = net.atlasauth.pca.VerdictFactory.failed("audience", "aud \"q\"");
        d = new PcaResult(PcaResult.Outcome.DENIED, v, "pc", "detail-text");
        assertEquals("PCA realm=\"pca\", error=\"insufficient_authority\"", d.wwwAuthenticate());
        assertEquals("{\"error\":\"insufficient_authority\",\"error_description\":\"audience: aud \\\"q\\\"\"}", d.jsonBody());
        // a verdict reason is ignored for non-DENIED outcomes
        PcaResult ok = new PcaResult(PcaResult.Outcome.ALLOW, v, "pc", "okdetail");
        assertTrue(ok.allowed());
        assertEquals(401, ok.status());
        assertNull(ok.error());
        assertEquals("{\"error\":\"pca_required\",\"error_description\":\"okdetail\"}", ok.jsonBody());
        PcaResult u2 = new PcaResult(PcaResult.Outcome.UNDECODABLE, v, null, "ud");
        assertEquals("{\"error\":\"invalid_request\",\"error_description\":\"ud\"}", u2.jsonBody());
        // DENIED with null verdict falls back to detail
        assertEquals("{\"error\":\"insufficient_authority\",\"error_description\":\"dd\"}", new PcaResult(PcaResult.Outcome.DENIED, null, null, "dd").jsonBody());
        // DENIED, verdict present but empty reason -> detail
        assertEquals("{\"error\":\"insufficient_authority\",\"error_description\":\"dd\"}", new PcaResult(PcaResult.Outcome.DENIED, net.atlasauth.pca.VerdictFactory.empty(), null, "dd").jsonBody());
        assertEquals("{\"error\":\"insufficient_authority\"}", new PcaResult(PcaResult.Outcome.DENIED, net.atlasauth.pca.VerdictFactory.empty(), null, "").jsonBody());
        assertEquals(5, PcaResult.Outcome.values().length);
    }

    @Test void jsonEscaping() {
        PcaResult r = PcaResult.of(PcaResult.Outcome.UNDECODABLE, "a\"b\\c\nd\re\tf\u0001g\u001fh \u007fé");
        assertEquals("{\"error\":\"invalid_request\",\"error_description\":\"a\\\"b\\\\c\\nd\\re\\tf\\u0001g\\u001fh \u007fé\"}", r.jsonBody());
        // 0.4.2 audit: request-derived text (CR/LF included) never reaches the header
        assertEquals("PCA realm=\"pca\", error=\"invalid_request\"", r.wwwAuthenticate());
        // the backslash is escaped before the quote (no double escaping of the quote's backslash)
        assertEquals("{\"error\":\"invalid_request\",\"error_description\":\"\\\\\\\"\"}", PcaResult.of(PcaResult.Outcome.UNDECODABLE, "\\\"").jsonBody());
        String longMsg = "x".repeat(500);
        assertEquals("{\"error\":\"invalid_request\",\"error_description\":\"" + longMsg + "\"}", PcaResult.of(PcaResult.Outcome.UNDECODABLE, longMsg).jsonBody());
        assertEquals("{\"error\":\"invalid_request\",\"error_description\":\"\\t\\t\\t\\t\\t\\t\\t\\t\\t\\t\\t\"}", PcaResult.of(PcaResult.Outcome.UNDECODABLE, "\t".repeat(11)).jsonBody());
    }

    // ------------------------------------------------------------------ PcaCore
    @Test void core() throws Exception {
        init();
        GrantResolver res = resolver();
        PcaResult r = PcaCore.authorize(null, null, aud, now, res);
        assertEquals(PcaResult.Outcome.ABSENT, r.outcome());
        assertEquals("no PCA-Action header and no PCActn body", r.detail());
        // 0.4.1: only an absent or EMPTY header is "no header"; a whitespace-only value is present and not strict base64url
        assertEquals(PcaResult.Outcome.UNDECODABLE, PcaCore.authorize("  ", new byte[0], aud, now, res).outcome());
        assertEquals(PcaResult.Outcome.ABSENT, PcaCore.authorize("", new byte[0], aud, now, res).outcome());
        assertEquals("no PCA-Action header and no PCActn body", PcaCore.authorize("", new byte[0], aud, now, res).detail());
        assertEquals("PCA-Action is not canonical base64url", PcaCore.authorize("!!", null, aud, now, res).detail());
        assertEquals(PcaResult.Outcome.UNDECODABLE, PcaCore.authorize("!!", null, aud, now, res).outcome());
        r = PcaCore.authorize(hdr("{"), null, aud, now, res);
        assertEquals(PcaResult.Outcome.UNDECODABLE, r.outcome());
        assertEquals("PCActn is not strict JSON: expected key at 1", r.detail());
        // 0.4.1: surrounding whitespace is NOT tolerated (strict header: nothing is trimmed), and the body is not consulted
        r = PcaCore.authorize("  " + hdr(json) + " \n", "garbage".getBytes(), aud, now, res);
        assertEquals(PcaResult.Outcome.UNDECODABLE, r.outcome());
        assertEquals("PCA-Action is not canonical base64url", r.detail());
        // header wins over body
        r = PcaCore.authorize(hdr(json), "garbage".getBytes(), aud, now, res);
        assertTrue(r.allowed(), r.detail());
        assertNotNull(r.verdict()); assertTrue(r.verdict().allow);
        assertTrue(r.pcactn() instanceof Map);
        assertEquals("", r.detail());
        assertEquals(PcaResult.Outcome.ALLOW, r.outcome());
        // body transport
        byte[] body = ("{\"pcactn\":" + json + "}").getBytes(StandardCharsets.UTF_8);
        r = PcaCore.authorize(null, body, aud, now, res);
        assertTrue(r.allowed(), r.detail());
        r = PcaCore.authorize("   ", body, aud, now, res);
        assertEquals(PcaResult.Outcome.UNDECODABLE, r.outcome()); // 0.4.1: a whitespace-only header is present, not absent
        r = PcaCore.authorize("", body, aud, now, res);
        assertTrue(r.allowed(), r.detail());
        r = PcaCore.authorize(null, "{".getBytes(), aud, now, res);
        assertEquals(PcaResult.Outcome.UNDECODABLE, r.outcome());
        assertEquals("request body is not strict JSON: expected key at 1", r.detail());
        r = PcaCore.authorize(null, "[1]".getBytes(), aud, now, res);
        assertEquals(PcaResult.Outcome.ABSENT, r.outcome());
        assertEquals("no PCActn in request", r.detail());
        r = PcaCore.authorize(null, "{\"x\":1}".getBytes(), aud, now, res);
        assertEquals(PcaResult.Outcome.ABSENT, r.outcome());
        assertEquals("no \"pcactn\" field in request body", r.detail());
        r = PcaCore.authorize(null, "{\"pcactn\":null}".getBytes(), aud, now, res);
        assertEquals("no \"pcactn\" field in request body", r.detail());
        r = PcaCore.authorize(null, new byte[1], aud, now, res);
        assertEquals(PcaResult.Outcome.UNDECODABLE, r.outcome());
        // 0.4.2 audit: invalid UTF-8 in the body is REJECTED (strict decoder, as the header path), never replaced by U+FFFD
        byte[] bad = "{\"pcactn\":{\"grant_ref\":\"__\"}}".getBytes(StandardCharsets.UTF_8);
        bad[24] = (byte) 0xff; bad[25] = (byte) 0xfe;
        String[] seenBad = new String[1];
        r = PcaCore.authorize(null, bad, aud, now, ref -> { seenBad[0] = ref; return null; });
        assertEquals(PcaResult.Outcome.UNDECODABLE, r.outcome());
        assertEquals("request body is not valid UTF-8", r.detail());
        assertNull(seenBad[0]);
        // an overlong encoding ("/" as C0 AF) and a lone surrogate (ED A0 80) are refused too
        assertEquals("request body is not valid UTF-8", PcaCore.authorize(null, new byte[] {'{', (byte) 0xC0, (byte) 0xAF, '}'}, aud, now, res).detail());
        assertEquals("request body is not valid UTF-8", PcaCore.authorize(null, new byte[] {'{', (byte) 0xED, (byte) 0xA0, (byte) 0x80, '}'}, aud, now, res).detail());
        // grant resolution
        r = PcaCore.authorize(null, "{\"pcactn\":\"x\"}".getBytes(), aud, now, res);
        assertEquals(PcaResult.Outcome.UNKNOWN_GRANT, r.outcome());
        assertEquals("PCActn has no grant_ref", r.detail());
        r = PcaCore.authorize(null, "{\"pcactn\":{\"grant_ref\":5}}".getBytes(), aud, now, res);
        assertEquals("PCActn has no grant_ref", r.detail());
        r = PcaCore.authorize(null, "{\"pcactn\":{}}".getBytes(), aud, now, res);
        assertEquals("PCActn has no grant_ref", r.detail());
        r = PcaCore.authorize(hdr(json), null, aud, now, ref -> null);
        assertEquals(PcaResult.Outcome.UNKNOWN_GRANT, r.outcome());
        assertEquals("no capability registered for grant_ref", r.detail());
        r = PcaCore.authorize(hdr(json), null, aud, now, ref -> { throw new IllegalStateException("boom"); });
        assertEquals(PcaResult.Outcome.UNKNOWN_GRANT, r.outcome());
        assertEquals("grant resolver failed", r.detail());
        // the resolver receives exactly the grant_ref
        String[] seen = new String[1];
        PcaCore.authorize(hdr(json), null, aud, now, ref -> { seen[0] = ref; return grant; });
        assertEquals(grantRef, seen[0]);
        // denial carries the verdict
        r = PcaCore.authorize(hdr(json), null, "other", now, res);
        assertEquals(PcaResult.Outcome.DENIED, r.outcome());
        assertFalse(r.verdict().allow);
        assertEquals("audience: aud does not match this resource server / instance", r.detail());
        assertTrue(r.pcactn() instanceof Map);
        assertEquals("pca", PcaCore.ATTRIBUTE);
        assertEquals("PCA-Action", PcaCore.HEADER);
        // the `now` argument is honoured
        r = PcaCore.authorize(hdr(json), null, aud, now + 10_000_000, res);
        assertEquals(PcaResult.Outcome.DENIED, r.outcome());
        assertEquals("validity: the PCActn has expired", r.detail());
    }

    // ------------------------------------------------------------------ PcaFilter
    @Test void filterBasics() throws Exception {
        init();
        assertEquals("audience", assertThrows(NullPointerException.class, () -> new PcaFilter(null, resolver(), clock)).getMessage());
        assertEquals("resolver", assertThrows(NullPointerException.class, () -> new PcaFilter(aud, null, clock)).getMessage());
        assertEquals("clock", assertThrows(NullPointerException.class, () -> new PcaFilter(aud, resolver(), null)).getMessage());
        assertEquals("pca", PcaFilter.ATTRIBUTE);
        // default clock is the system clock: the fixture (year 2027) is in the future => denied (not a NPE)
        PcaFilter sys = new PcaFilter(aud, resolver());
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("PCA-Action", hdr(json));
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        sys.doFilter(req, resp, chain);
        assertEquals(403, resp.getStatus());
        assertNull(chain.getRequest());
    }

    @Test void filterNonHttp() throws Exception {
        init();
        PcaFilter f = new PcaFilter(aud, resolver(), clock);
        ServletRequest sr = (ServletRequest) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {ServletRequest.class}, (p, m, a) -> { throw new IllegalStateException(m.getName()); });
        ServletResponse sp = (ServletResponse) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {ServletResponse.class}, (p, m, a) -> { throw new IllegalStateException(m.getName()); });
        boolean[] called = new boolean[1];
        FilterChain chain = (a, b) -> { called[0] = true; assertSame(sr, a); assertSame(sp, b); };
        f.doFilter(sr, sp, chain);
        assertTrue(called[0]);
        // an HTTP request with a non-HTTP response is also passed through
        called[0] = false;
        MockHttpServletRequest hr = new MockHttpServletRequest();
        FilterChain chain2 = (a, b) -> { called[0] = true; assertSame(hr, a); assertSame(sp, b); };
        f.doFilter(hr, sp, chain2);
        assertTrue(called[0]);
        called[0] = false;
        MockHttpServletResponse hp = new MockHttpServletResponse();
        FilterChain chain3 = (a, b) -> { called[0] = true; assertSame(sr, a); assertSame(hp, b); };
        f.doFilter(sr, hp, chain3);
        assertTrue(called[0]);
    }

    @Test void filterHeaderTransportDoesNotTouchBody() throws Exception {
        init();
        PcaFilter f = new PcaFilter(aud, resolver(), clock);
        MockHttpServletRequest req = new MockHttpServletRequest() {
            @Override public ServletInputStream getInputStream() { throw new AssertionError("body must not be read when the header is present"); }
        };
        req.addHeader("PCA-Action", hdr(json));
        MockHttpServletResponse resp = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        f.doFilter(req, resp, chain);
        assertSame(req, chain.getRequest());
        assertTrue(req.getAttribute("pca") instanceof PcaResult);
        assertEquals(200, resp.getStatus());
    }

    @Test void filterBodyTransport() throws Exception {
        init();
        PcaFilter f = new PcaFilter(aud, resolver(), clock);
        byte[] body = ("{\"pcactn\":" + json + "}").getBytes(StandardCharsets.UTF_8);
        for (String blank : new String[] {null, ""}) {
            MockHttpServletRequest req = new MockHttpServletRequest();
            if (blank != null) req.addHeader("PCA-Action", blank);
            req.setContent(body);
            MockHttpServletResponse resp = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();
            f.doFilter(req, resp, chain);
            HttpServletRequest down = (HttpServletRequest) chain.getRequest();
            assertNotNull(down, "blank=" + blank);
            assertFalse(down == req);
            assertTrue(down.getAttribute("pca") instanceof PcaResult);
            assertEquals(body.length, down.getContentLength());
            assertEquals((long) body.length, down.getContentLengthLong());
            ServletInputStream in = down.getInputStream();
            assertTrue(in.isReady());
            assertFalse(in.isFinished());
            int first = in.read();
            assertEquals(body[0] & 0xff, first);
            byte[] buf = new byte[body.length];
            int n = in.read(buf, 0, 5);
            assertEquals(5, n);
            assertEquals(body[1], buf[0]);
            assertEquals(body[5], buf[4]);
            byte[] rest = in.readAllBytes();
            assertEquals(body.length - 6, rest.length);
            assertTrue(in.isFinished());
            assertEquals(-1, in.read());
            assertThrows(UnsupportedOperationException.class, () -> in.setReadListener(null));
            assertArrayEquals(body, down.getInputStream().readAllBytes());
            BufferedReader rd = down.getReader();
            assertEquals(new String(body, StandardCharsets.UTF_8), rd.lines().collect(java.util.stream.Collectors.joining("\n")));
        }
        // 0.4.1: a whitespace-only header is PRESENT (not trimmed): 401 not-base64url, the body is not consulted
        {
            MockHttpServletRequest req = new MockHttpServletRequest();
            req.addHeader("PCA-Action", "   ");
            req.setContent(body);
            MockHttpServletResponse resp = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();
            f.doFilter(req, resp, chain);
            assertNull(chain.getRequest());
            assertEquals(401, resp.getStatus());
            assertTrue(resp.getContentAsString().contains("not canonical base64url"), resp.getContentAsString());
        }
        // the PCActn body is UTF-8 only (0.4.2 audit: strict decoder): a Latin-1 body (é = lone 0xE9) is refused, 401
        MockHttpServletRequest req = new MockHttpServletRequest();
        StringBuilder asc = new StringBuilder();
        for (char ch : json.toCharArray()) asc.append(ch < 0x80 ? String.valueOf(ch) : String.format("\\u%04x", (int) ch));
        byte[] latin = ("{\"pcactn\":" + asc + ",\"x\":\"é\"}").getBytes(StandardCharsets.ISO_8859_1);
        req.setContent(latin);
        req.setCharacterEncoding("ISO-8859-1");
        MockFilterChain chain = new MockFilterChain();
        MockHttpServletResponse r1 = new MockHttpServletResponse();
        new PcaFilter(aud, resolver(), clock).doFilter(req, r1, chain);
        assertNull(chain.getRequest());
        assertEquals(401, r1.getStatus());
        assertTrue(r1.getContentAsString().contains("request body is not valid UTF-8"), r1.getContentAsString());
        // the downstream reader honours the declared encoding (UTF-8 bytes of é read as ISO-8859-1 are "Ã©"), falls back
        // to UTF-8 for unknown names
        req = new MockHttpServletRequest();
        req.setContent(("{\"pcactn\":" + asc + ",\"x\":\"é\"}").getBytes(StandardCharsets.UTF_8));
        req.setCharacterEncoding("ISO-8859-1");
        chain = new MockFilterChain();
        r1 = new MockHttpServletResponse();
        new PcaFilter(aud, resolver(), clock).doFilter(req, r1, chain);
        HttpServletRequest down = (HttpServletRequest) chain.getRequest();
        assertNotNull(down, r1.getContentAsString());
        assertTrue(down.getReader().lines().collect(java.util.stream.Collectors.joining("\n")).endsWith("\"x\":\"\u00c3\u00a9\"}"));
        req = new MockHttpServletRequest();
        req.setContent(("{\"pcactn\":" + json + ",\"x\":\"é\"}").getBytes(StandardCharsets.UTF_8));
        req.setCharacterEncoding("bogus-charset");
        chain = new MockFilterChain();
        new PcaFilter(aud, resolver(), clock).doFilter(req, new MockHttpServletResponse(), chain);
        down = (HttpServletRequest) chain.getRequest();
        assertNotNull(down);
        assertTrue(down.getReader().lines().collect(java.util.stream.Collectors.joining("\n")).endsWith("\"x\":\"é\"}"));
        // reader without a declared encoding (wrapper over a request returning null encoding)
        req = new MockHttpServletRequest();
        req.setContent(("{\"pcactn\":" + json + ",\"x\":\"é\"}").getBytes(StandardCharsets.UTF_8));
        req.setCharacterEncoding((String) null);
        chain = new MockFilterChain();
        new PcaFilter(aud, resolver(), clock).doFilter(req, new MockHttpServletResponse(), chain);
        down = (HttpServletRequest) chain.getRequest();
        assertTrue(down.getReader().lines().collect(java.util.stream.Collectors.joining("\n")).endsWith("\"x\":\"é\"}"));
    }

    @Test void filterChallenge() throws Exception {
        init();
        PcaFilter f = new PcaFilter(aud, resolver(), clock);
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        resp.setHeader("X-Stale", "1");
        resp.getWriter().write("stale-body");
        resp.setStatus(200);
        MockFilterChain chain = new MockFilterChain();
        f.doFilter(req, resp, chain);
        assertNull(chain.getRequest());
        assertEquals(401, resp.getStatus());
        assertNull(resp.getHeader("X-Stale"));
                assertEquals("PCA realm=\"pca\"", resp.getHeader("WWW-Authenticate"));
        assertEquals("application/json;charset=UTF-8", resp.getContentType());
        String bodyText = "{\"error\":\"pca_required\",\"error_description\":\"no PCA-Action header and no PCActn body\"}";
        assertEquals(bodyText, resp.getContentAsString());
        assertEquals(bodyText.getBytes(StandardCharsets.UTF_8).length, resp.getContentLength());
        assertEquals(String.valueOf(bodyText.length()), resp.getHeader("Content-Length"));
        // denied: 403 + reason
        req = new MockHttpServletRequest();
        req.addHeader("PCA-Action", hdr(json));
        resp = new MockHttpServletResponse();
        new PcaFilter("other", resolver(), clock).doFilter(req, resp, new MockFilterChain());
        assertEquals(403, resp.getStatus());
        assertEquals("PCA realm=\"pca\", error=\"insufficient_authority\"", resp.getHeader("WWW-Authenticate"));
        // multi-byte detail: the content length counts bytes
        req = new MockHttpServletRequest();
        resp = new MockHttpServletResponse();
        new PcaFilter(aud, ref -> { throw new RuntimeException(); }, clock).doFilter(req, resp, new MockFilterChain());
        assertEquals(resp.getContentAsByteArray().length, resp.getContentLength());
    }

    // ------------------------------------------------------------------ PcaInterceptor
    @Test void interceptor() throws Exception {
        init();
        assertEquals("audience", assertThrows(NullPointerException.class, () -> new PcaInterceptor(null, resolver(), clock)).getMessage());
        assertEquals("resolver", assertThrows(NullPointerException.class, () -> new PcaInterceptor(aud, null, clock)).getMessage());
        assertEquals("clock", assertThrows(NullPointerException.class, () -> new PcaInterceptor(aud, resolver(), null)).getMessage());
        assertEquals("pca", PcaInterceptor.ATTRIBUTE);
        PcaInterceptor sys = new PcaInterceptor(aud, resolver());
        MockHttpServletRequest req = new MockHttpServletRequest();
        req.addHeader("PCA-Action", hdr(json));
        MockHttpServletResponse resp = new MockHttpServletResponse();
        assertFalse(sys.preHandle(req, resp, new Object()));
        assertEquals(403, resp.getStatus());

        PcaInterceptor it = new PcaInterceptor(aud, resolver(), clock);
        req = new MockHttpServletRequest();
        req.addHeader("PCA-Action", hdr(json));
        resp = new MockHttpServletResponse();
        assertTrue(it.preHandle(req, resp, new Object()));
        assertTrue(((PcaResult) req.getAttribute("pca")).allowed());
        assertEquals(200, resp.getStatus());

        req = new MockHttpServletRequest();
        resp = new MockHttpServletResponse();
        resp.setHeader("X-Stale", "1");
        resp.getWriter().write("stale-body");
        assertFalse(it.preHandle(req, resp, new Object()));
        assertEquals(401, resp.getStatus());
        assertNull(resp.getHeader("X-Stale"));
        assertEquals("PCA realm=\"pca\"", resp.getHeader("WWW-Authenticate"));
        assertEquals("application/json;charset=UTF-8", resp.getContentType());
        String bodyText = "{\"error\":\"pca_required\",\"error_description\":\"no PCA-Action header and no PCActn body\"}";
        assertEquals(bodyText, resp.getContentAsString());
        assertEquals(bodyText.length(), resp.getContentLength());
        assertNull(req.getAttribute("pca"));
        // the interceptor never reads a body
        req = new MockHttpServletRequest() {
            @Override public ServletInputStream getInputStream() { throw new AssertionError("no body read"); }
        };
        req.setContent(("{\"pcactn\":" + json + "}").getBytes(StandardCharsets.UTF_8));
        resp = new MockHttpServletResponse();
        assertFalse(it.preHandle(req, resp, new Object()));
        assertEquals(401, resp.getStatus());
        Map<String, Object> unused = new LinkedHashMap<>();
        assertTrue(unused.isEmpty());
    }
}
