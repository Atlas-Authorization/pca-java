# pca-spring-security

Spring Security 6.2+ adapter for the PCA Java library. It verifies the `PCA-Action` header with the same decision as
`PcaInterceptor` (`Authorize.authorize`, bound to the operation your mapper derives from the request, fail closed, `401`/`403`
with the same challenge and JSON body) and exposes the verified action as an `Authentication`.

Install the library first (from the root of the pca-java repository: `mvn -Dmaven.test.skip=true install`), then build this
module with `mvn test`. The core library gains no dependency from it.

```java
@Bean
SecurityFilterChain chain(HttpSecurity http) throws Exception {
    return http.csrf(c -> c.disable())
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .with(PcaSecurity.pca("payments-rs", resolver, options, (request, body) -> operationFor(request)), Customizer.withDefaults())
        .authorizeHttpRequests(a -> a.requestMatchers("/refunds").hasAuthority("PCA_payments.send").anyRequest().denyAll())
        .build();
}
```

- `options`: build with `Protect.protect(...).options()` (replay store, revocation, single-step plan) or `Authorize.Options` directly.
- Authorities come from the operation the proof was bound to: `PCA_<verb>` and `PCA_<verb>:<resource>`. The principal name is the `grant_ref`;
  `PcaPrincipal.result()` is the full `PcaResult`, also set as the `"pca"` request attribute.
- Method security: register `new PcaMethodSecurity()` as a bean named `pca`, then
  `@PreAuthorize("@pca.hasVerb(authentication, 'payments.send')")` (or `hasAuthority('PCA_payments.send')`).
- `matching(RequestMatcher)` limits which requests must carry a proof; by default every request in the chain must.
- Header transport only: the body is never read (the mapper gets an empty body), as with `PcaInterceptor`.
