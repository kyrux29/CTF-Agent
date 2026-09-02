"""Module entrypoint for the M5 independent verifier worker."""

from .worker import main

if __name__ == "__main__":  # pragma: no cover - exercised by Docker entrypoint.
    main()
