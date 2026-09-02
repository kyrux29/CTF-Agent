# Local Power knowledge

Place operator-owned, historical CTF technique notes as UTF-8 Markdown files
under `knowledge/writeups/`. They are intentionally Git-ignored: do not commit
private writeups, flags, credentials, challenge attachments, or live contest
material.

CTFMesh reads this directory only for an opt-in Power retrieval after the
AutoPrompter receipt. It pins each source digest, redacts flag-shaped strings
from the model-facing excerpt, and gives top results to one selected racer only.
`contest_offline` disables loading and retrieval entirely.
