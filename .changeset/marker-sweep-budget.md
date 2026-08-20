---
"convex-logto": patch
---

Give the revocation-watermark sweep its own transaction.

Collecting a watermark proves it governs no surviving session, and that proof
reads a `sessions` document — the largest this component stores. Running a
hundred of those lookups inside `gc`, which had already spent most of its
16 MiB read budget on the transaction and dead-session sweeps, could exceed the
limit and fail the whole garbage collection, not just the watermark part. The
sweep is now a separate scheduled mutation with a batch bounded the way the
revocation drain is, and it continues durably only when a full batch was
actually collected — a batch that skipped everything found nothing collectable,
and rescheduling on that would spin on the same rows. The two tables it drains
are counted separately, so a run that fills *both* batches — subject watermarks
and `sid` watermarks together, which is exactly the backlogged case — keeps
going instead of reading the combined total as a partial batch and stopping.
