"""Scanner modules register themselves against a TargetKind at import time.

Importing this package imports every scanner subpackage, so the engine sees all
registered scanners. Phase 1 ships web/; code/, mobile/, desktop/ get added here
the same way in later phases.
"""

from . import web  # noqa: F401  (import = register web.* scanners)
from . import code  # noqa: F401  (import = register code.* scanners)
