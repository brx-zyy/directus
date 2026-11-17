# Collaborative WebSocket permission cache omits client IP

**Status:** Strong candidate; cache-key collision is directly testable, but end-to-end exploitation still needs verification  
**Affected component:** Collaborative editing WebSocket permission checks  
**Relevant files:**
- `api/src/websocket/collab/permissions-cache.ts`
- `api/src/websocket/collab/verify-permissions.ts`
- `api/src/permissions/lib/fetch-policies.ts`
- `api/src/permissions/utils/filter-policies-by-ip.ts`

## Summary

The collaborative editing permission cache keys entries by user, collection, item, and action:

```ts
return `${accountability.user || 'public'}:${collection}:${item || 'singleton'}:${action}`;
```

It does not include the client IP address.

However, permission policy selection is IP-sensitive. `fetchPolicies()` passes `ip` into `_fetchPolicies()`, which filters access rows using `filterPoliciesByIp(accessRows, ip)`. The collaborative permission verifier calls `permissionCache.get()` before fetching policies.

Consequently, two WebSocket connections authenticated as the same user, targeting the same collection/item/action, but originating from different IP addresses can collide in the process-wide permission cache. If an allowed-IP connection populates the cache first, a connection from an IP that should not receive the IP-restricted policy may reuse the cached allowed fields without evaluating its own IP policy set.

## Attack preconditions

- Collaborative editing is enabled and reachable.
- The victim account has a policy whose access is restricted by IP.
- The same account can establish connections from both an allowed and a disallowed network.
- Both connections request permission checks for the same collection, item, and action while the cache entry remains live.

## Expected behavior

Permission results for different client IP addresses must not share a cache entry when IP access rules can affect the selected policies.

## Source-level evidence

1. `PermissionCache.getCacheKey()` includes user, collection, item, and action, but omits `accountability.ip`.
2. `verifyPermissions()` checks the permission cache before calling `fetchPolicies()`.
3. `fetchPolicies()` includes IP in its cache key and filters policy access rows by the supplied IP.
4. Collaborative room access and field checks call `verifyPermissions()`.

## Regression test

A regression test was added to `api/src/websocket/collab/permissions-cache.test.ts`. It stores a permission result for one IP and expects a different IP to miss the cache. The current cache-key implementation is expected to fail this test.

## Controlled reproduction outline

1. Configure an account with a collaborative-editing permission policy restricted to a specific allowed IP range.
2. From an allowed IP, authenticate as that account and open a collaborative room for a test item, causing the permission cache to populate.
3. From a disallowed IP, authenticate as the same account and request access to the same room/item.
4. Compare behavior with a fresh process/cache and with the allowed-IP request performed first.
5. Verify whether the disallowed connection reuses the cached allowed fields and can read/edit fields that its IP-restricted policy should deny.

Use only a test instance and test account. Do not attempt this against a third-party deployment.

## Recommended remediation

Include the normalized client IP (and any other policy-varying accountability dimensions) in the permission cache key, or scope this cache to the client connection. Add an integration test that exercises the allowed-IP-then-disallowed-IP order against actual policy evaluation.

## Reporting caveat

The missing IP dimension and the cache lookup order are confirmed by source inspection. The impact depends on collaborative editing's real-world use of IP-restricted policies and should be demonstrated with an end-to-end test before external submission.
