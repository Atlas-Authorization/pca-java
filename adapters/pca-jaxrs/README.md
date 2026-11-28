# pca-jaxrs

Jakarta REST (JAX-RS 3.1, Jakarta EE 10) adapter for the PCA Java library, plus a note on plain servlets.

**Servlet.** The core `net.atlasauth.pca.servlet.PcaFilter` is built against `jakarta.servlet` 6.0 (the Jakarta EE 10 servlet API), so it
runs unchanged in any EE 10 container (Tomcat 10.1, Jetty 12, WildFly 27+, Payara 6). Register it with `web.xml` or `FilterRegistration`.
It is the only option when the PCActn travels in the request body (it buffers the body).

**JAX-RS.** `PcaContainerRequestFilter` has the protection semantics of `PcaInterceptor` (full `Authorize.authorize` for the operation your
mapper derives, header transport, fail closed, `401`/`403` with `WWW-Authenticate` and the JSON body). `@PcaProtected` is the
name-binding annotation: put it on the resource classes or methods to guard.

```java
Authorize.Options options = Protect.protect(new Protect.Config("payments-rs", (r, b) -> null).grants(grants)).options();
// register one instance (constructor arguments: it is not auto-discovered)
resourceConfig.register(new PcaContainerRequestFilter("payments-rs", grants::get, options,
    ctx -> operationFor(ctx.getUriInfo().getPath())));   // null (or a throw) denies

@Path("/refunds") @PcaProtected
public class RefundResource { @POST public Response refund(...) {...} }
```

On an allow the `PcaResult` is the `"pca"` request property (`ctx.getProperty("pca")`). The entity is never read: derive the operation from
the path, query and headers. Install the library first (`mvn -Dmaven.test.skip=true install` in the pca-java root), then `mvn test` here.
The core library gains no dependency from this module. In a servlet container that already provides the servlet and Spring-free runtime, exclude
`jakarta.servlet-api` and `spring-webmvc` from the `pca-mutation` dependency.
