"""
Security Engine — Unused Dependency Detector
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Real-parses a real dependency manifest (npm/yarn ``package.json`` and/or
Python ``requirements.txt``) found on the host filesystem, real-walks the
real source tree next to it, and compares the REAL declared-dependency set
against the REAL set of package names actually imported in source. No
sample/mock/simulated data is ever generated — every Finding reflects an
actual manifest entry and actual regex matches against actual file contents
read from disk at scan time.

STATIC, TEXT-BASED DETECTION — HONEST LIMITATIONS
---------------------------------------------------
This engine performs static, regex-based text analysis. It does **not**
execute or type-check any code, so it will legitimately miss:

- Dynamic / computed imports, e.g. ``require(someVariable)`` or
  ``importlib.import_module(f"{prefix}_plugin")``.
- String-built import paths assembled at runtime.
- Re-exports through barrel files that themselves are the only textual
  "user" of a package (the barrel file counts as usage, but if nothing else
  in the tree imports the barrel, the chain can be missed).
- Conditional imports guarded behind code paths that never execute.
- Package name vs. import name mismatches beyond the simple
  ``-``/``.`` → ``_`` normalization documented in
  ``app.detection_rules.normalize`` (e.g. ``beautifulsoup4`` installs as
  ``bs4`` — this engine will NOT know that without a lookup table it does
  not maintain).

Treat findings as a strong, honest heuristic starting point for a human
review — not as ground truth. Always verify with the actual package manager
before deleting a dependency.
"""
import json
import os
import re
import time

from app.detection_rules import ALL_RULES, normalize

# Directories that are never real project source and would otherwise pollute
# both the file count and the (already-installed) dependency detection.
EXCLUDED_DIR_NAMES = {
    "node_modules", ".git", "venv", ".venv", "env", "__pycache__",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "egg-info",
    ".eggs", "site-packages", ".idea", ".vscode",
}

JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
PY_EXTENSIONS = {".py"}

# --- Regexes for real static import detection --------------------------------
_RE_JS_REQUIRE = re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)""")
_RE_JS_FROM = re.compile(r"""from\s+['"]([^'"]+)['"]""")
_RE_JS_IMPORT_SIDE_EFFECT = re.compile(r"""import\s+['"]([^'"]+)['"]""")

_RE_PY_IMPORT = re.compile(r"^\s*import\s+(\w+)", re.MULTILINE)
_RE_PY_FROM = re.compile(r"^\s*from\s+(\w+)", re.MULTILINE)


def _js_package_name(spec):
    """Turn a raw JS import/require specifier into a real package name, or
    None if it is a relative/absolute local path (not a dependency)."""
    if not spec or spec.startswith(".") or spec.startswith("/"):
        return None
    parts = spec.split("/")
    if spec.startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 else spec
    return parts[0]


def _extract_js_imports(text):
    names = set()
    for regex in (_RE_JS_REQUIRE, _RE_JS_FROM, _RE_JS_IMPORT_SIDE_EFFECT):
        for match in regex.finditer(text):
            pkg = _js_package_name(match.group(1))
            if pkg:
                names.add(pkg)
    return names


def _extract_py_imports(text):
    names = set()
    for regex in (_RE_PY_IMPORT, _RE_PY_FROM):
        for match in regex.finditer(text):
            names.add(match.group(1))
    return names


def _parse_package_json(path):
    """Real-parse package.json. Returns (runtime_deps, dev_deps, scripts_text)."""
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        data = json.load(fh)
    runtime = set((data.get("dependencies") or {}).keys())
    dev = set((data.get("devDependencies") or {}).keys())
    scripts = data.get("scripts") or {}
    scripts_text = " ".join(str(v) for v in scripts.values()).lower()
    return runtime, dev, scripts_text


_REQ_NAME_SPLIT = re.compile(r"[<>=!~\[\s;#]")


def _parse_requirements_txt(path):
    """Real-parse requirements.txt. Returns a set of declared runtime dep names."""
    runtime = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            name = _REQ_NAME_SPLIT.split(line, 1)[0].strip()
            if name:
                runtime.add(name)
    return runtime


class ScanEngine:
    """Runs a real dependency-usage scan against a real project directory."""

    def __init__(self, target_path, max_depth=8, excludes=None, max_files=20000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set()
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def run(self):
        """Perform the real, synchronous manifest-parse + source-walk scan.
        Returns the standard summary dict used across this project's tools."""
        start = time.time()
        context = self._build_context()
        elapsed_partial = time.time() - start

        for rule in ALL_RULES:
            try:
                results = rule(context) or []
            except Exception:
                self.errors_count += 1
                continue
            for result in results:
                result["file_path"] = context["representative_file"]
                result["permissions_octal"] = str(result.get("package_name") or "")
                result["owner_uid"] = None
                result["owner_gid"] = None
                self.findings.append(result)

        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed if elapsed >= elapsed_partial else elapsed_partial, 3),
        }

    def _build_context(self):
        declared_runtime = set()
        declared_dev = set()
        scripts_text = ""
        manifest_paths = []
        representative_file = self.target_path

        pkg_json_path = os.path.join(self.target_path, "package.json")
        req_txt_path = os.path.join(self.target_path, "requirements.txt")

        has_js = os.path.isfile(pkg_json_path)
        has_py = os.path.isfile(req_txt_path)

        if has_js:
            try:
                rt, dev, scripts_text = _parse_package_json(pkg_json_path)
                declared_runtime |= rt
                declared_dev |= dev
                manifest_paths.append(pkg_json_path)
                representative_file = pkg_json_path
                self.files_scanned += 1
            except (OSError, ValueError, json.JSONDecodeError):
                self.errors_count += 1
                has_js = False

        if has_py:
            try:
                declared_runtime |= _parse_requirements_txt(req_txt_path)
                manifest_paths.append(req_txt_path)
                if representative_file == self.target_path:
                    representative_file = req_txt_path
                self.files_scanned += 1
            except OSError:
                self.errors_count += 1
                has_py = False

        if has_js and has_py:
            ecosystem = "both"
        elif has_js:
            ecosystem = "javascript"
        elif has_py:
            ecosystem = "python"
        else:
            ecosystem = "none"

        wanted_extensions = set()
        if ecosystem in ("javascript", "both"):
            wanted_extensions |= JS_EXTENSIONS
        if ecosystem in ("python", "both"):
            wanted_extensions |= PY_EXTENSIONS

        imported_names = set()
        import_counts = {}

        if wanted_extensions:
            for path in self._walk_source_files(wanted_extensions):
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                        text = fh.read()
                except OSError:
                    self.errors_count += 1
                    continue

                ext = os.path.splitext(path)[1]
                found = set()
                if ext in JS_EXTENSIONS:
                    found |= _extract_js_imports(text)
                if ext in PY_EXTENSIONS:
                    found |= _extract_py_imports(text)

                for name in found:
                    imported_names.add(name)
                    import_counts[name] = import_counts.get(name, 0) + 1

                self.files_scanned += 1

        return {
            "ecosystem": ecosystem,
            "manifest_paths": manifest_paths,
            "declared_runtime": declared_runtime,
            "declared_dev": declared_dev,
            "imported_names": imported_names,
            "import_counts": import_counts,
            "scripts_text": scripts_text,
            "representative_file": representative_file,
            "files_scanned": self.files_scanned,
        }

    def _walk_source_files(self, wanted_extensions):
        """Real os.walk of the target directory, yielding real source file
        paths whose extension is one this engine's ecosystem cares about."""
        for depth, (root, dirs, files) in enumerate(os.walk(self.target_path)):
            if self.files_scanned >= self.max_files:
                return
            if self._is_excluded(root):
                dirs[:] = []
                continue

            rel_depth = root[len(self.target_path):].count(os.sep)
            if rel_depth > self.max_depth:
                dirs[:] = []
                continue

            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIR_NAMES and not self._is_excluded(os.path.join(root, d))]
            self.dirs_scanned += 1

            for name in files:
                if self.files_scanned >= self.max_files:
                    return
                ext = os.path.splitext(name)[1]
                if ext in wanted_extensions:
                    yield os.path.join(root, name)
