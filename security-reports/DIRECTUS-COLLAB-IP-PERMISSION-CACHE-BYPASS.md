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

Consequently, two WebSocket connections authenticated as the same user, targeting the same collection/item/action, but originating from different IP addresses can collide in the process-wide permission cache. A key exploitation scenario is a user who has general read access (so both connections can join the room) but has update permission restricted to an allowed IP range. If an allowed-IP connection populates the update-permission cache first, a connection from a disallowed IP may reuse those cached update fields without evaluating its own IP policy set.

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
2. Give the account general read permission for the test item, but grant update permission for a sensitive test field only from the allowed IP range.
3. From an allowed IP, authenticate as that account, open the collaborative room, and trigger an update-permission check for the test field so the cache is populated.
4. From a disallowed IP, authenticate as the same account and join the same room. The general read permission should allow the join.
5. Attempt to update the field whose update policy is restricted to the allowed IP range.
6. Compare behavior with a fresh process/cache and with the allowed-IP update check performed first.

Use only a test instance and test account. Do not attempt this against a third-party deployment.

## Recommended remediation

Include the normalized client IP (and any other policy-varying accountability dimensions) in the permission cache key, or scope this cache to the client connection. Add an integration test that exercises the allowed-IP-then-disallowed-IP order against actual policy evaluation.

## Reporting caveat

The missing IP dimension, IP-sensitive policy selection, and cache lookup order are confirmed by source inspection. The room-join path separately validates read access, so the realistic scenario requires read access at both IPs and update access restricted to the allowed IP. The regression tests still need to be checked in CI, and an end-to-end WebSocket test must demonstrate that a disallowed-IP client can update the protected field before external submission.


## Validation status

- Original implementation: the permission-cache test fails because a result stored for one IP is returned for a different IP. The verifier-level test also returns `private_field` to the disallowed-IP accountability instead of an empty field list.
- Fix experiment: branch [`security-audit/collab-ip-cache-fix`](https://github.com/brx-zyy/directus/tree/security-audit/collab-ip-cache-fix) adds the client IP to the cache key.
- GitHub Actions on the fix branch: both collaborative permission-cache regression tests passed, and the file/TUS SQLite E2E suite passed.
- Still outstanding: a real WebSocket integration test with an IP-restricted update policy, general read access from both IPs, and an attempted protected-field update from the disallowed IP.
