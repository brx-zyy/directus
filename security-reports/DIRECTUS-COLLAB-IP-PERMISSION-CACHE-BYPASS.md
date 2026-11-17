# Advisory Details

**Title:** Collaborative editing permission cache may reuse IP-restricted permissions across client IPs

**Summary**

The collaborative-editing permission cache key includes the user, collection, item, and action, but omits the client IP. The policy-fetching path applies IP-based policy filtering. Therefore, a cached permission result generated for an allowed IP can collide with a permission check from a different IP for the same user and resource.

**Validation status: NOT CONFIRMED end-to-end.** Unit-level tests exercise the cache collision using mocked policy results. No real WebSocket session has yet demonstrated that a client from a disallowed IP can modify a protected field.

## Details

In `api/src/websocket/collab/permissions-cache.ts`, the original cache key is:

```ts
return `${accountability.user || 'public'}:${collection}:${item || 'singleton'}:${action}`;
```

The key does not include `accountability.ip`.

The collaborative permission verifier checks this cache before fetching policies. The policy-fetching path, however, passes the client IP into policy filtering. This creates a mismatch: the policy result can depend on IP while the cache identity does not.

A plausible scenario requires careful conditions:

- The same user has general read access from both client IPs, so both clients can join the collaborative room.
- The user's update permission for a sensitive field is granted only from an allowed IP range.
- The allowed-IP connection causes the update permission result to be cached first.
- A connection from a disallowed IP then requests the same user's update permission for the same collection/item/action while that cache entry remains valid.

The room-join path independently validates read access. Thus, this report does not claim that a disallowed IP can join a room without read permission.

## Proof of concept

**Status: unit-level cache collision reproduced; real WebSocket field modification not yet reproduced.**

The candidate regression test in `api/src/websocket/collab/verify-permissions.test.ts` creates two accountability objects for the same user but different IPs. It mocks policy fetching so the allowed IP receives `private_field` and the disallowed IP receives no fields. The test then calls `verifyPermissions()` for both clients and expects the second result to be empty. With the original cache key, the second lookup can reuse the first result.

To complete an end-to-end reproduction, use a disposable Directus instance:

1. Enable collaborative editing.
2. Create a test user and a test item containing a sensitive field such as `private_field`.
3. Configure general read permission for the item from both test client IPs.
4. Configure update permission for `private_field` only from the allowed test IP range.
5. Connect to the collaborative room as that user from the allowed IP and trigger the update-permission check to populate the cache.
6. Connect as the same user from a disallowed IP and join the same room using the general read permission.
7. Attempt to modify `private_field` from the disallowed-IP connection.
8. Record the WebSocket messages and persisted item value. Repeat with a fresh process/cache and reverse the connection order.

**Expected secure behavior:** the disallowed-IP client cannot update `private_field`.

**Suspected vulnerable behavior:** if the cache collision is exploitable in the full room update path, the disallowed-IP client may reuse the allowed-IP field permission and update the field. This outcome has not yet been observed.

## Impact

If the full WebSocket path accepts the cached permission, a user connecting from a network that is not authorized for a restricted update could modify fields that should only be writable from an allowed IP range. The impact is an IP-policy authorization bypass for collaborative editing. Actual exploitability and severity remain unverified pending the WebSocket reproduction.

## Suggested remediation

Include the normalized client IP and any other policy-varying accountability dimensions in the permission cache key, or scope the cache to the connection. Add an integration test that uses actual IP-filtered policies and attempts a protected-field update over WebSocket.

## Test evidence

- Source inspection confirms the cache key omits IP while policy selection uses IP.
- The candidate unit test models two IP-specific policy outcomes; it does not establish behavior of the real policy database or WebSocket update pipeline.
- The fix branch `security-audit/collab-ip-cache-fix` adds the IP to the cache key.
- GitHub Actions run [44078592178](https://github.com/brx-zyy/directus/actions/runs/44078592178) passed the focused cache tests on the **fix branch**. This validates the proposed fix against the unit tests, not end-to-end exploitability on the original implementation.
- No successful protected-field modification from a disallowed IP has been captured.
