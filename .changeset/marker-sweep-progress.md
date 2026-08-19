---
"convex-logto": patch
---

Keep the revocation-watermark sweep going when both tables are backlogged.

The sweep continued only when its combined deletion count equalled one batch, so
a run that filled *both* batches — subject watermarks and `sid` watermarks
together, which is exactly the backlogged case — counted sixteen and stopped.
Each table's deletions are now counted separately, and either one filling its
batch continues the chain.
