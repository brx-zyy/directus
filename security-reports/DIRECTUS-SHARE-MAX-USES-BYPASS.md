# Directus share max-uses enforcement bypass

**Status:** Candidate finding; source-level behavior identified, independent database-backed reproduction still required  
**Affected component:** Share authentication endpoint `POST /shares/auth`  
**Source:** `api/src/services/shares.ts`, `SharesService.login()`  
**Suggested severity:** Low to Medium, pending confirmation of intended semantics and practical impact

## Summary

The share login query allows a share to authenticate when its usage counter has already reached its configured maximum. The query currently applies:

```ts
subQuery.whereNull('max_uses').orWhere('max_uses', '>=', this.knex.ref('times_used'));
```

For a share configured with `max_uses = 1` and `times_used = 1`, the predicate is true. The login proceeds, increments the counter to 2, and issues another access token and refresh token. In general, the predicate permits a login while `times_used === max_uses`, yielding one more successful login than the configured limit.

## Additional race condition

The check and increment are separate database operations:

1. Select the share if the usage predicate passes.
2. Calculate `(record.share_times_used ?? 0) + 1` in application code.
3. Update the row by share ID without a conditional usage predicate or atomic increment expression.
4. Issue tokens.

Concurrent requests can therefore read the same counter value and both pass. Both then write the same next counter value and issue sessions. This is a potential lost-update race that may permit more than one extra login under concurrency. Its exact impact depends on database isolation and needs a database-backed concurrency test.

## Reproduction (controlled test instance only)

1. Create a share for a test item and configure `max_uses = 1`, with no password and valid start/end dates.
2. Confirm `times_used = 0`.
3. Send one unauthenticated request:

   ```http
   POST /shares/auth
   Content-Type: application/json

   {"share":"<TEST_SHARE_UUID>","mode":"json"}
   ```

4. Confirm the response contains `access_token` and `refresh_token`; the share counter becomes 1.
5. Send the identical request again.
6. Observe whether the second request also returns tokens even though `times_used` was already 1 before it began.

Expected behavior: request 5 is rejected once the configured maximum has been reached.  
Current source behavior: the SQL predicate accepts equality (`max_uses >= times_used`), so the second request is eligible and proceeds.

For a race test, reset the counter to zero and issue multiple requests concurrently against a one-use test share. Record successful responses and the final `times_used` value. Do not run this against a production share.

## Evidence

The application UI independently treats the limit as exhausted when `max_uses - times_used` reaches zero (`app/src/routes/shared/shared.vue` and `app/src/views/private/components/share-item.vue`). This corroborates that equality should be rejected by the authentication endpoint.

The relevant source is in `api/src/services/shares.ts`, in `SharesService.login()`:

- The eligibility query uses `max_uses >= times_used`.
- The counter update uses a value calculated from the previously selected record.
- The update is filtered only by share ID.
- Access and refresh tokens are generated after the update.

A regression assertion was added on the audit branch to require a strict greater-than predicate. GitHub Actions failed that assertion and printed the generated SQL containing `("max_uses" is null or "max_uses" >= "times_used")`. A separate fix branch changes the predicate to strict greater-than, and the isolated share-service regression test passes there.

## Recommended remediation

- Reject at equality by using `max_uses > times_used`.
- Make checking and consuming a use atomic. For example, perform a conditional update equivalent to:

  ```sql
  UPDATE directus_shares
  SET times_used = times_used + 1
  WHERE id = ? AND (max_uses IS NULL OR times_used < max_uses)
  ```

  Then require exactly one affected row before issuing tokens.
- Add a database-backed integration test for the exact-limit case and a concurrent-login test.

## Reporting caveats

This report is not yet a fully verified security submission. The source and generated SQL demonstrate the off-by-one condition, but a clean database-backed endpoint reproduction and confirmation of intended `max_uses` semantics are still needed. The mocked unit test is not, by itself, proof of the concurrency impact.
