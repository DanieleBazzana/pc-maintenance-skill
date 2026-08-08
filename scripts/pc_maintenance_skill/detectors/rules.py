from ..safety import BACKUP_WORDS, DATABASE_SUFFIXES, KEY_SUFFIXES, SENSITIVE_NAMES

_CODE_ARTIFACT_PARTS = {
    ".git", "node_modules", ".venv", "venv", "virtualenv", "site-packages",
    "dist-packages", "projects", "repos", "repositories", "development", "src", "tests",
}
_INSTALLER_SUFFIXES = {".dmg", ".pkg", ".msi", ".zip", ".iso", ".tgz"}
_INSTALLER_NAME_WORDS = ("install", "installer", "setup", "package", "download")


def entry_parts(entry):
    return set(getattr(entry, "parts_lower", tuple(part.lower() for part in entry.path.parts)))


def is_code_artifact(entry):
    parts = entry_parts(entry)
    return bool(parts & _CODE_ARTIFACT_PARTS) or "python" in parts and "lib" in parts


def is_downloads(entry):
    return "downloads" in entry_parts(entry)


def installer_candidate(entry):
    if not entry.is_file or is_code_artifact(entry):
        return False
    suffix = getattr(entry, "suffix_lower", entry.path.suffix.lower())
    if suffix not in _INSTALLER_SUFFIXES:
        return False
    name = getattr(entry, "name_lower", entry.path.name.lower())
    return is_downloads(entry) or any(word in name for word in _INSTALLER_NAME_WORDS)


def cache_context(entry):
    parts = entry_parts(entry)
    text = getattr(entry, "path_lower", str(entry.path).lower())
    if any(marker in text for marker in ("chrome", "brave", "safari", "firefox", "browser")):
        return "browser_cache"
    if parts & {".npm", ".yarn", ".pnpm", "pip", "uv", "cargo", "gomod", "pkg"}:
        return "package_manager_cache"
    if parts & {"__pycache__", "deriveddata", "build", "dist", ".cache"}:
        return "build_cache"
    return "application_cache"


def developer_context(entry):
    parts = entry_parts(entry)
    if "node_modules" in parts:
        return "node_modules"
    if parts & {".venv", "venv", "virtualenv", "site-packages", "dist-packages"}:
        return "python_venv"
    if parts & {".npm", ".yarn", ".pnpm", "pip", "uv", "cargo", "gomod"}:
        return "package_manager_cache"
    if parts & {"__pycache__", "deriveddata", "build", "dist", ".cache"}:
        return "build_cache"
    if parts & {"sdk", "sdks", "toolchain", "toolchains", "android", "xcode"}:
        return "sdk_toolchain"
    return "developer_artifact"


def temporary_candidate(entry):
    if not entry.is_file:
        return False
    name = getattr(entry, "name_lower", entry.path.name.lower())
    suffix = getattr(entry, "suffix_lower", entry.path.suffix.lower())
    if suffix in (".tmp", ".temp", ".part", ".crdownload"):
        return True
    return name.startswith("tmp") and bool(entry_parts(entry) & {"tmp", "temp", "temporary", "cache", "caches", "downloads"})


def large_evidence(entry):
    parts = entry_parts(entry)
    location = next((name for name in ("downloads", "documents", "desktop", "library", ".hermes", ".vscode") if name in parts), "other")
    suffix = getattr(entry, "suffix_lower", entry.path.suffix.lower()) or "<none>"
    directory = entry.path.parent.name or "/"
    return f"size={entry.size}; location={location.title()}; extension={suffix}; directory={directory}"


def detail_for_protected(entry):
    if entry.is_dir:
        return True
    name = getattr(entry, "name_lower", entry.path.name.lower())
    suffix = getattr(entry, "suffix_lower", entry.path.suffix.lower())
    return name in SENSITIVE_NAMES or name.endswith(".env") or name.startswith(".env.") or suffix in DATABASE_SUFFIXES or suffix in KEY_SUFFIXES or any(word in name for word in BACKUP_WORDS)
