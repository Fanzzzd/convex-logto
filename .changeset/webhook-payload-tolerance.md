---
"convex-logto": minor
---

Stop dropping a Logto webhook delivery over a field the library never reads.

`isLogtoWebhookPayload` type-checked roughly fifteen advisory fields — `hookId`,
`userAgent`, `ip`, `path`, `method`, `status`, `matchedRoute`, and most of the
User entity — and one mismatch made the route answer 400 *before* it recorded
the delivery or revoked sessions. Logto retries a 5xx, not a 4xx, so a single
drifted field meant permanent, first-attempt loss of every `User.*` event for
that user, taking the deletion and suspension revocation path with it. A
`userAgent: null`, a missing `hookId`, an `identities: []` or a stringified
`status` was enough.

The predicate now accepts on exactly what the library consumes: a known `User.*`
event, a string `createdAt` for the replay window, and a usable user id (with
the existing rule that a `User.Deleted` carrying both `data.id` and
`params.userId` must not contradict itself). A field that drifted out of its
declared type is dropped from the entity handed to sync handlers rather than
rejected, so a handler still receives the declared `LogtoUserEntity` shape while
the raw value stays reachable on the payload it also receives. Fields Logto adds
later pass through untouched, as before.

One rejection is new, not relaxed: a `User.Deleted` whose entity carries an
`id` that is not a string. That id is one the library *does* consume, and an
unreadable one could be naming a different user than the route params — a
destructive event must not run on a guess. A `User.Deleted` whose entity simply
names no one (`data: {}`) is now accepted, since it carries the same
information as the documented `data: null` shape.

`LogtoWebhookPayload["hookId"]` is now optional, for the same reason as the
rest: nothing reads it, so nothing should turn on it.
