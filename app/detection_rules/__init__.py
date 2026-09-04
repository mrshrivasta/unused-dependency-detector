"""
Detection Rules — Unused Dependency Detector
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects a REAL "context" dict built by app.security_engine.ScanEngine
from a real dependency manifest (package.json / requirements.txt) and real
source files it actually read on disk, and returns a list of Finding dicts
(possibly empty — never None) for the conditions it detects. Rules never talk
to the filesystem themselves; they are pure functions over the context dict,
which makes them independently unit-testable with synthetic data.

Context dict shape produced by the Security Engine (see security_engine for
the real builder):

    {
        "ecosystem": "javascript" | "python" | "both" | "none",
        "manifest_paths": [str, ...],           # real manifest file(s) found
        "declared_runtime": {"lodash", ...},     # raw declared names (package.json "dependencies" / requirements.txt)
        "declared_dev": {"eslint", ...},         # raw declared names (package.json "devDependencies")
        "imported_names": {"lodash", ...},       # raw-ish names actually seen imported in real source (already normalized)
        "import_counts": {"lodash": 3, ...},     # how many times each normalized import name was seen
        "scripts_text": "eslint . && jest",      # lowercased blob of package.json "scripts" values (textual reference check)
        "representative_file": "/path/to/manifest/or/source",
        "files_scanned": 12,
    }

Every rule is intentionally conservative and documented so results can be
independently verified by reading the manifest and grepping the source tree
by hand.
"""

# Severity scale used consistently across the whole project
SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_INFO = "informational"


def normalize(name):
    """Normalize a dependency/import name for comparison across ecosystems.

    Lower-cases the name and folds '-', '.' into '_' so that, e.g., a Python
    package declared as ``Foo-Bar`` in requirements.txt can be matched against
    an ``import foo_bar`` statement. This is a best-effort heuristic, not a
    guarantee — see the documented limitation in the README/engine docstring.
    """
    if not name:
        return ""
    return name.strip().lower().replace("-", "_").replace(".", "_")


def rule_unused_runtime_dependency(ctx):
    """UDD-001: A package declared as a real runtime dependency
    (package.json "dependencies", or a non-dev requirements.txt entry) is
    never imported anywhere in the real scanned source tree. Wasted install
    footprint and unnecessary attack surface — medium severity."""
    findings = []
    imported = {normalize(n) for n in ctx.get("imported_names", set())}
    for dep in sorted(ctx.get("declared_runtime", set())):
        if normalize(dep) not in imported:
            findings.append({
                "rule_id": "UDD-001",
                "rule_name": "Unused Runtime Dependency",
                "severity": SEVERITY_MEDIUM,
                "package_name": dep,
                "description": (
                    f"'{dep}' is declared as a runtime dependency but no "
                    f"import/require of it was found anywhere in the scanned "
                    f"source files. It may be an unused dependency, increasing "
                    f"install size and attack surface for no benefit."
                ),
            })
    return findings


def rule_unused_dev_dependency(ctx):
    """UDD-002: A declared devDependency is never imported/required in
    source AND is never textually referenced in package.json "scripts"
    entries (e.g. a linter/build tool invoked by name from an npm script).
    Low severity — dev dependencies are lower-risk than runtime ones."""
    findings = []
    imported = {normalize(n) for n in ctx.get("imported_names", set())}
    scripts_text = (ctx.get("scripts_text") or "").lower()
    for dep in sorted(ctx.get("declared_dev", set())):
        if normalize(dep) in imported:
            continue
        if dep.lower() in scripts_text:
            continue
        findings.append({
            "rule_id": "UDD-002",
            "rule_name": "Unused Dev Dependency",
            "severity": SEVERITY_LOW,
            "package_name": dep,
            "description": (
                f"'{dep}' is declared as a devDependency but was neither "
                f"imported anywhere in source nor referenced by name in any "
                f"package.json script. Likely an unused dev dependency."
            ),
        })
    return findings


def rule_dependency_in_both_categories(ctx):
    """UDD-003: The same package name is declared in BOTH "dependencies"
    and "devDependencies" simultaneously — a real duplicate-classification
    issue that usually means one of the two entries is stale. Medium
    severity, JavaScript/package.json only (Python has no equivalent
    duplicate-category concept in requirements.txt)."""
    findings = []
    runtime = {normalize(n): n for n in ctx.get("declared_runtime", set())}
    dev = {normalize(n): n for n in ctx.get("declared_dev", set())}
    for norm_name in sorted(set(runtime) & set(dev)):
        findings.append({
            "rule_id": "UDD-003",
            "rule_name": "Dependency Declared In Both Categories",
            "severity": SEVERITY_MEDIUM,
            "package_name": runtime[norm_name],
            "description": (
                f"'{runtime[norm_name]}' is declared in BOTH \"dependencies\" "
                f"and \"devDependencies\" in package.json. This is a real "
                f"duplicate-classification issue — decide whether it is a "
                f"runtime or a dev-only dependency."
            ),
        })
    return findings


# Node.js / Python standard-library module names that should never be
# reported as "undeclared" phantom dependencies even though they are
# imported without appearing in a manifest.
_NODE_BUILTINS = {
    "assert", "buffer", "child_process", "cluster", "crypto", "dgram", "dns",
    "events", "fs", "http", "https", "net", "os", "path", "querystring",
    "readline", "stream", "string_decoder", "timers", "tls", "tty", "url",
    "util", "v8", "vm", "zlib", "process", "console",
}
_PY_BUILTINS = {
    "os", "sys", "re", "json", "math", "time", "datetime", "collections",
    "itertools", "functools", "typing", "pathlib", "subprocess", "logging",
    "unittest", "io", "abc", "copy", "random", "string", "shutil", "csv",
    "argparse", "tempfile", "threading", "socket", "sqlite3", "enum",
    "dataclasses", "contextlib", "traceback", "hashlib", "base64", "uuid",
    "__future__",
}


def rule_undeclared_import_used(ctx):
    """UDD-004: A real source file imports a package that is NOT declared
    anywhere in the manifest (not in "dependencies", not in
    "devDependencies", not in requirements.txt). This is a real, honest
    "phantom dependency" risk: the import currently works only because the
    package happens to be present transitively (or globally), and could
    break with no warning on a clean install. Informational/low severity."""
    findings = []
    declared = {normalize(n) for n in ctx.get("declared_runtime", set())} | \
               {normalize(n) for n in ctx.get("declared_dev", set())}
    ecosystem = ctx.get("ecosystem", "none")
    builtins = set()
    if ecosystem in ("javascript", "both"):
        builtins |= _NODE_BUILTINS
    if ecosystem in ("python", "both"):
        builtins |= _PY_BUILTINS

    for name in sorted(ctx.get("imported_names", set())):
        norm = normalize(name)
        if norm in declared or norm in builtins:
            continue
        findings.append({
            "rule_id": "UDD-004",
            "rule_name": "Undeclared Import (Phantom Dependency)",
            "severity": SEVERITY_LOW,
            "package_name": name,
            "description": (
                f"Source imports '{name}' but it is not declared in any "
                f"manifest found in this project. It may be a relative/local "
                f"module that was mis-detected, or a real undeclared "
                f"(transitive-only) dependency that could break installs."
            ),
        })
    return findings


def rule_dependency_bloat_ratio(ctx):
    """UDD-005: General "dependency bloat" ratio check. If the total number
    of declared dependencies (runtime + dev) is more than 2x the number of
    distinct packages actually imported anywhere in the scanned source, that
    is a real signal of a bloated manifest carrying dead weight. Medium
    severity; the 2x threshold and both counts are computed for real from
    the scan, never hard-coded results."""
    declared_total = len(ctx.get("declared_runtime", set())) + len(ctx.get("declared_dev", set()))
    imported_total = len({normalize(n) for n in ctx.get("imported_names", set())})
    if declared_total >= 4 and imported_total >= 0 and declared_total > 2 * imported_total:
        ratio = round(declared_total / imported_total, 2) if imported_total else float("inf")
        return [{
            "rule_id": "UDD-005",
            "rule_name": "Dependency Bloat Ratio",
            "severity": SEVERITY_MEDIUM,
            "package_name": f"{declared_total} declared / {imported_total} imported",
            "description": (
                f"{declared_total} dependencies are declared in the manifest "
                f"but only {imported_total} distinct packages are actually "
                f"imported anywhere in the scanned source (ratio "
                f"{ratio if imported_total else '∞'}, threshold 2.0x). This "
                f"suggests the manifest carries significant unused weight."
            ),
        }]
    return []


def rule_no_manifest_found(ctx):
    """UDD-006: No recognizable dependency manifest (package.json or
    requirements.txt) was found anywhere at the top level of the scanned
    directory, so no dependency-usage comparison could be performed at all.
    Informational/low severity — purely a "nothing to compare" signal."""
    if ctx.get("ecosystem", "none") == "none":
        return [{
            "rule_id": "UDD-006",
            "rule_name": "No Manifest Found",
            "severity": SEVERITY_INFO,
            "package_name": None,
            "description": (
                "No package.json or requirements.txt manifest was found in "
                "the scanned directory, so declared-vs-imported dependency "
                "usage could not be evaluated."
            ),
        }]
    return []


ALL_RULES = [
    rule_unused_runtime_dependency,
    rule_unused_dev_dependency,
    rule_dependency_in_both_categories,
    rule_undeclared_import_used,
    rule_dependency_bloat_ratio,
    rule_no_manifest_found,
]
