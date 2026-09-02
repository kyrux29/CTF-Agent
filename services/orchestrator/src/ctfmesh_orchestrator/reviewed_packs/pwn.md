# Pwn checklist — reviewed pack v1

Scope: use only the allocated challenge binary, declared tube target, and typed
workspace sessions. Never infer an address, output, or success without an observation.

1. Identify architecture, protections, input surface, and relevant local files.
2. Use `gdb` or a bounded local reproduction to confirm control flow and offsets.
3. Keep payload generation in `/work`; re-check every received byte from the scoped tube.
4. Change approach after a coordinator bump or repeated non-observations.
5. Submit only a complete candidate contained in an immutable observation artifact.
