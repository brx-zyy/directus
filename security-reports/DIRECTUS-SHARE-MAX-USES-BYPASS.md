# Advisory Details

**Title:** Share usage limit may permit one additional authentication

**Summary**

The share-login eligibility query uses `max_uses >= times_used`. When the usage counter is already equal to the configured maximum, the predicate still matches. The UI treats equality as exhausted, so this appears to be an off-by-one enforcement defect.

**Validation status: NOT CONFIRMED end-to-end.** Source inspection identifies the condition, but no database-backed request to `POST /shares/auth` has yet demonstrated that the second login actually receives tokens. The existing passing CI run is for the proposed fix branch and its service-level tests, not a vulnerable endpoint reproduction.

## Details

In `api/src/services/shares.ts`, `SharesService.login()` selects the share using:

```ts
subQuery.whereNull('max_uses').orWhere('max_uses', '>=', this.knex.ref('times_used'));
```

For `max_uses = 1` and `times_used = 1`, the equality branch evaluates true. If the row is selected, the method increments the counter and proceeds to generate an access token and refresh token.

The Directus UI independently treats `max_uses - times_used === 0` as exhausted in `app/src/routes/shared/shared.vue` and `app/src/views/private/components/share-item.vue`. This supports the interpretation that the API should reject equality.

A separate possible race exists because the service reads the counter and later writes a value calculated from that stale row, with the update filtered only by share ID. Concurrent over-consumption has not been demonstrated and is not claimed as confirmed impact here.

## Proof of concept

**Status: reproduction procedure prepared; result not yet verified against a real database-backed endpoint.**

Use a disposable Directus test instance only.

1. Create a share for a disposable test item with `max_uses = 1`, no password, and valid start/end dates.
2. Confirm the database row has `times_used = 0`.
3. Send:
   ```http
   POST /shares/auth
   Content-Type: application/json

   {"share":"<TEST_SHARE_UUID>","mode":"json"}
   ```
4. Confirm the first request succeeds and the row becomes `times_used = 1`.
5. Send the identical request again.
6. Record the HTTP status, response body, and database counter.

**Expected secure behavior:** the second request is rejected because the maximum has already been reached.

**Suspected vulnerable behavior:** the second request is accepted because the SQL condition permits `max_uses === times_used`. This outcome must be observed before submitting this as a confirmed vulnerability.

## Impact

If the endpoint behaves as the query suggests, a share configured for N uses may allow N+1 successful authentications, exceeding the owner's configured access limit. This could extend access to shared content beyond the intended number of uses. Severity depends on how share limits are used operationally.

## Suggested remediation

Use a strict less-than condition for eligibility and consume a use atomically, e.g. a conditional update equivalent to:

```sql
UPDATE directus_shares
SET times_used = times_used + 1
WHERE id = ?
  AND (max_uses IS NULL OR times_used < max_uses)
```

Require exactly one affected row before issuing tokens. Add database-backed endpoint and concurrent-request regression tests.

## Test evidence

- The original source contains the `>=` comparison.
- The proposed fix branch `security-audit/share-limit-fix` changes it to strict greater-than.
- GitHub Actions run [44078710187](https://github.com/brx-zyy/directus/actions/runs/44078710187) passed the isolated share-service suite (7/7) on the **fix branch**. This validates the proposed regression test/fix, not exploitability on the original endpoint.
- No successful second-login response from the original implementation has been captured.
