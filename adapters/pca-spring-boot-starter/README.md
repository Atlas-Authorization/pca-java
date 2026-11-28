# pca-spring-boot-starter

Spring Boot 3.x auto-configuration for the PCA Java library. Add the module, set `pca.audience`, and provide the two things only your
application knows. Install the library first (`mvn -Dmaven.test.skip=true install` in the pca-java root), then this module
(`mvn install`); the core library gains no dependency from it.

```yaml
pca:
  audience: payments-rs
  store: memory            # memory | jdbc (uses your DataSource; jdbc.create-table: true creates the replay table)
  grants-location: classpath:pca/grants.json   # JSON array of the grants this server accepts (or define a GrantResolver bean)
  mode: interceptor        # interceptor | security (security exposes a PcaSecurity bean; needs pca-spring-security)
  path-patterns: /**
  exclude-path-patterns: /health
```

```java
@Bean PcaFilter.OperationMapper operation() {   // the operation YOUR route executes; null denies
    return (request, body) -> "/refunds".equals(request.getRequestURI()) ? Authorize.Operation.of("payments.send", "payments/acme", params(request)) : null;
}
```

- Same protection as `Protect.protect`: the full authorize pipeline, replay store, revocation, single-step plan; refusals are
  `401`/`403` with the `WWW-Authenticate` challenge. Nothing is enforced until `pca.audience` is set; with it set, a missing
  operation mapper, grants source or (for `store: jdbc`) `DataSource` fails the startup rather than starting open.
- Every bean is `@ConditionalOnMissingBean`: define your own `StateStore`, `GrantResolver`, `Protect.Protected` or `PcaInterceptor`. Optional beans picked up
  when present: `Clock`, `ArgProvenance.Options`, `Authorize.RevocationCheck`.
- Security mode: `http.with(pcaSecurity, Customizer.withDefaults())` with the injected `PcaSecurity` bean; a `pca` method-security bean is registered too.
- A custom `pca.jdbc.table` skips the SQLite file pre-open that the default-table path performs.
