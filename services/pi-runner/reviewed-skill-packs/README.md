# Reviewed Pi skill library

This directory is the **only** place a Power Pi session can read supplemental
skill guidance. It is copied into the Pi runner image at build time; it is not
a challenge mount and Pi native skill discovery remains disabled.

## Add a skill

1. Create `services/pi-runner/reviewed-skill-packs/<skill-id>/SKILL.md` as
   UTF-8 Markdown. Keep it focused on a CTF technique and do not include a
   flag, API key, cookie, live target, executable code, or challenge-local
   instructions.
2. Add a manifest item in `manifest.json`. Its `id` must be lowercase,
   `path` must be exactly `<skill-id>/SKILL.md`, and `roles` can contain
   `racer`, `autoprompter`, or both.
3. Set `enabled` to `true` only for packs that every selected role should load.
   A Power session has a maximum of eight enabled packs and 12 KiB of rendered
   guidance. Disabled packs remain available for future activation without
   consuming model context.
4. Rebuild the local runner:

   ```bash
   docker compose --profile power up -d --build pi-runner-live
   ```

Existing sessions retain their initial prompt and skill digest. New sessions
use the rebuilt library. To keep an audit trail, commit the skill and manifest
change together with its focused Pi runner test.

The loader follows only explicit manifest entries, rejects symlinks and hidden
discovery, and redacts flag/key-shaped text before it can enter a model prompt.
It never reads `.pi`, `.agents`, `AGENTS.md`, or any file in a challenge.
