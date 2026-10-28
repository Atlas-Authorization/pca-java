package example;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import net.atlasauth.pca.Authorize;
import net.atlasauth.pca.Json;
import net.atlasauth.pca.servlet.PcaFilter;
import net.atlasauth.pca.spring.Protect;

@Configuration
public class PcaConfig {
    static final String AUDIENCE = "payments-rs";

    /** The grants this server accepts come from its own store (here a file), never from the request. */
    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> loadGrants() throws IOException {
        try (InputStream in = PcaConfig.class.getResourceAsStream("/grants.json")) {
            return (List<Map<String, Object>>) Json.parseLenient(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
    }

    /** The operation THIS route executes, from the parsed request body. A proof signed for other params or another verb is refused. */
    @SuppressWarnings("unchecked")
    static Authorize.Operation operationFor(jakarta.servlet.http.HttpServletRequest request, byte[] body) {
        if (!"/refunds".equals(request.getRequestURI())) return null;
        Map<String, Object> params = (Map<String, Object>) Json.parse(new String(body, StandardCharsets.UTF_8));
        return Authorize.Operation.of("payments.send", "payments/acme", params);
    }

    @Bean
    Protect.Protected protection(ObjectProvider<Clock> clock) throws IOException {
        return Protect.protect(new Protect.Config(AUDIENCE, PcaConfig::operationFor)
            .grants(loadGrants())
            .clock(clock.getIfAvailable(Clock::systemUTC)));
    }

    @Bean
    FilterRegistrationBean<PcaFilter> pcaFilter(Protect.Protected protection) {
        FilterRegistrationBean<PcaFilter> reg = new FilterRegistrationBean<>(protection.filter());
        reg.addUrlPatterns("/refunds");
        return reg;
    }
}
