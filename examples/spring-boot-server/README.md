# Spring Boot resource server with PCA

A minimal Spring Boot 3.3.5 server (Java 17) whose `POST /refunds` route is guarded by `Protect.protect(...)`. A request runs only
if it carries a proof that was signed for exactly this operation. This project has its own build and is not part of the
library artifact.

## Run the test

Install the library into your local Maven repository first (from the root of the pca-java repository), then test the example:

```sh
mvn -Dmaven.test.skip=true install
cd examples/spring-boot-server
mvn test
```

`RefundsSmokeTest` sends a recorded, valid proof to `/refunds` and expects `200`. Sending the same proof again is a replay and
is refused with `403`; the body names the check and carries a `doc` link to the page that explains it:

```json
{"error":"insufficient_authority","error_description":"replay: 1 is not greater than last seen 1 (replay)","decision":"deny","doc":"https://github.com/Atlas-Authorization/pca/blob/main/docs/reference/refusals.md#replay"}
```

## What to read

- `PcaConfig` builds the guard: the audience, the grants this server accepts (loaded from its own store, never from the
  request), and the function that derives the operation from the request. `Protect.protect` adds an in-memory replay store,
  revocation (`protection.revoke(grantId)`) and the single-step plan.
- `RefundController` is an ordinary controller; it is reached only when the filter allowed the request.

For several server instances, pass a shared store with `.stateStore(new PcaJdbcStateStore(...))` instead of the in-memory default.
The recorded proof is time-limited, so the test pins the server clock to the time it was made; a real server uses the system clock.
