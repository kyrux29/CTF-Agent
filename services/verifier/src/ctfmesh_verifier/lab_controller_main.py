"""Dedicated module entrypoint for the isolated M5 lab controller."""

from .lab_controller import main

if __name__ == "__main__":  # pragma: no cover - exercised by Docker smoke.
    main()
