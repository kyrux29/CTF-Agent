# web-path-traversal

Local M5 evaluation target for a path-normalization and control-probe workflow.
It is started only with Docker Compose profile `m5`; the controller generates a
new flag for each reset and the target reads it from a private read-only volume.
