"""
tests/d48_break.py

D48 (Phase 3c-3g): the pytest plugin that breaks one selector clause.

Loaded with `-p d48_break` by `tests/test_selector_clauses.py`, in a
subprocess, with `AIL_D48_CLAUSE` naming which clause of `D48_CLAUSES` to
break. It is inert with that variable unset, so a normal run never sees it.

**Why a plugin and not a textual edit of the file.** A mutation applied by
rewriting the source has to write a mutated copy somewhere. Written next to
the original it is collectable by a concurrent run; written elsewhere it
computes a different `REPO_ROOT` from its own `__file__` and every path in
the module resolves to the wrong tree. Replacing the module attribute after
import avoids both. It works because every selector in scope is looked up as
a module global at call time: `write_routes()` resolves `_service_routes`
when it runs, not when it was defined, so rebinding the name reaches the
caller.

**Why after collection rather than at configure time.** The target module is
imported during collection, and an import overwrites whatever was set before
it. `pytest_collection_modifyitems` is the first hook that runs with the
module object in `sys.modules` and before any test body executes.
"""

import importlib
import os


def pytest_collection_modifyitems(session, config, items):
    clause_id = os.environ.get("AIL_D48_CLAUSE", "")
    if not clause_id:
        return

    import test_selector_clauses as registry

    clause = registry.clause_by_id(clause_id)
    module = importlib.import_module(clause.module)
    original = getattr(module, clause.attribute)
    setattr(module, clause.attribute, clause.broken(original))

    # `bounded_read_sites` is lru_cached. A break installed after something
    # has already walked the tree would be invisible, and the falsifier would
    # pass against a cached answer the unbroken selector produced, which is
    # this check reporting a green it did not earn.
    walk = getattr(module, "bounded_read_sites", None)
    if walk is not None and hasattr(walk, "cache_clear"):
        walk.cache_clear()

    # Printed so a subprocess transcript pasted into a report says what was
    # broken, rather than the reader taking the harness's word for it.
    print(f"D48: broke {clause.module}.{clause.attribute} ({clause.clause})")
