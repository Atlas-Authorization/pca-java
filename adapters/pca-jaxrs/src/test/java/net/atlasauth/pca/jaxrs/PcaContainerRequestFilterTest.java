package net.atlasauth.pca.jaxrs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.ws.rs.NameBinding;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.Test;

import net.atlasauth.pca.ArgProvenance;
import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.servlet.PcaResult;
import net.atlasauth.pca.spring.Protect;

class PcaContainerRequestFilterTest {
    static final Map<String, Object> PROOF = parse("/proof.json");
    static final ArgProvenance.Recorder MEDIATOR = ArgProvenance.Recorder.create("refund-assistant", "k1");
    static final Clock CLOCK = Clock.fixed(Instant.ofEpochMilli(Json.asLong(PROOF.get("now"))), ZoneOffset.UTC);

    @SuppressWarnings("unchecked")
    static Map<String, Object> parse(String name) {
        try (InputStream in = PcaContainerRequestFilterTest.class.getResourceAsStream(name)) {
            return (Map<String, Object>) Json.parseLenient(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String b64(Object json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(Json.canonicalizeStrict(json).getBytes(StandardCharsets.UTF_8));
    }

    static Authorize.Operation refund() {
        return Authorize.Operation.of("payments.send", "payments/acme", Map.of("amount", 50L, "currency", "usd"));
    }

    @SuppressWarnings("unchecked")
    static PcaContainerRequestFilter filter(PcaContainerRequestFilter.OperationMapper mapper) {
        Map<String, Map<String, Object>> byId = new HashMap<>();
        try (InputStream in = PcaContainerRequestFilterTest.class.getResourceAsStream("/grants.json")) {
            for (Object g : (List<Object>) Json.parseLenient(new String(in.readAllBytes(), StandardCharsets.UTF_8)))
                byId.put(String.valueOf(((Map<String, Object>) g).get("id")), (Map<String, Object>) g);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        Authorize.Options options = Protect.protect(new Protect.Config("payments-rs", (r, b) -> null).grants(byId::get).clock(CLOCK)
            .provenance(new ArgProvenance.Options().mediators(List.of(MEDIATOR.pin())))).options();
        return new PcaContainerRequestFilter("payments-rs", byId::get, CLOCK, options, mapper);
    }

    /** A request context that answers headers and records abortWith / setProperty. */
    static final class Call {
        final Map<String, String> headers = new HashMap<>();
        final Map<String, Object> props = new HashMap<>();
        Response aborted;

        ContainerRequestContext context() {
            return (ContainerRequestContext) Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[] {ContainerRequestContext.class},
                (p, m, a) -> {
                    switch (m.getName()) {
                        case "getHeaderString": return headers.get(String.valueOf(a[0]));
                        case "setProperty": props.put((String) a[0], a[1]); return null;
                        case "abortWith": aborted = (Response) a[0]; return null;
                        default: throw new UnsupportedOperationException(m.getName());
                    }
                });
        }
    }

    @Test void refusesARequestWithoutProof() {
        Call c = new Call();
        filter(r -> refund()).filter(c.context());
        assertNotNull(c.aborted);
        assertEquals(401, c.aborted.getStatus());
        assertEquals("PCA realm=\"pca\"", c.aborted.getHeaderString("WWW-Authenticate"));
        assertNull(c.props.get("pca"));
    }

    @Test void aMapperThatThrowsOrReturnsNullDenies() {
        for (PcaContainerRequestFilter.OperationMapper m : List.<PcaContainerRequestFilter.OperationMapper>of(r -> null, r -> { throw new IllegalStateException(); })) {
            Call c = new Call();
            c.headers.put("PCA-Action", b64(PROOF.get("pcactn")));
            filter(m).filter(c.context());
            assertNotNull(c.aborted);
            assertEquals(403, c.aborted.getStatus());
            assertNull(c.props.get("pca"));
        }
    }

    @Test void runsTheSignedOperationOnceAndRefusesTheReplay() {
        PcaContainerRequestFilter f = filter(r -> refund());
        Call c = new Call();
        c.headers.put("PCA-Action", b64(PROOF.get("pcactn")));
        c.headers.put("PCA-Provenance", b64(ArgProvenance.principalDirect(MEDIATOR, refund())));
        f.filter(c.context());
        assertNull(c.aborted);
        assertTrue(((PcaResult) c.props.get("pca")).allowed());
        Call again = new Call();
        again.headers.putAll(c.headers);
        f.filter(again.context());
        assertNotNull(again.aborted);
        assertEquals(403, again.aborted.getStatus());
        assertTrue(new String((byte[]) again.aborted.getEntity(), StandardCharsets.UTF_8).contains("replay:"));
    }

    @Test void nameBindingIsWiredToTheFilter() {
        assertTrue(PcaProtected.class.isAnnotationPresent(NameBinding.class));
        assertTrue(PcaContainerRequestFilter.class.isAnnotationPresent(PcaProtected.class));
    }
}
