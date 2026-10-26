"""App scanners (MOBILE / DESKTOP): static checks on app packages. Never executes them."""

from . import android, apple, windows  # noqa: F401  (import = register app.* scanners)
