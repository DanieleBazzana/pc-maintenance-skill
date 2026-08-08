import os
from pathlib import Path
from typing import Iterable

from ..domain.models import Classification, Disposition, PolicyDecision, ProtectionSource

SYSTEM_ROOTS = tuple(Path(p) for p in ("/System", "/usr", "/bin", "/sbin", "/private", "/var", "/Applications"))
SENSITIVE_NAMES = {".env", ".env.local", ".env.production", ".ssh", ".gnupg", ".aws", ".kube", ".git", "keychains", "credentials", "secrets"}
DATABASE_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".mdb", ".sqlitedb"}
KEY_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".crt", ".cer"}
BACKUP_WORDS = {"backup", "backups", "archive", "archives"}
PROJECT_MARKERS = {".git", "package.json", "pyproject.toml", "requirements.txt", "cargo.toml", "go.mod", "makefile", "src", "tests"}


def _resolve(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _under_any(path: Path, roots: Iterable[Path]) -> bool:
    return any(_inside(path, root) for root in roots)


def _is_external(path: Path) -> bool:
    return _under_any(path, (Path("/Volumes"), Path("/Network"), Path("/net"), Path("/mnt")))


def _marker_reason(path: Path):
    name = path.name.lower()
    parts = {p.lower() for p in path.parts}
    if name in SENSITIVE_NAMES or any(p in SENSITIVE_NAMES for p in parts):
        return "sensitive credential or secret path"
    if name.endswith(".env") or name.startswith(".env."):
        return "environment file may contain secrets"
    if name in {"keychain", "keychains"} or name.endswith(tuple(KEY_SUFFIXES)):
        return "credential or cryptographic key material"
    if name.endswith(tuple(DATABASE_SUFFIXES)) or name.endswith(("-wal", "-shm", ".journal")):
        return "database or database sidecar"
    if any(word in parts or word in name for word in BACKUP_WORDS):
        return "backup or archive path"
    return None


def _looks_like_project(path: Path) -> bool:
    lower = path.name.lower()
    return lower in PROJECT_MARKERS or any(part.lower() in {"projects", "repos", "repositories", "development", "dev", "src", "tests"} for part in path.parts)


def evaluate_path(path: Path, allowed_root: Path, known_is_symlink=None, known_stat=None):
    candidate = Path(path).expanduser()
    root = _resolve(Path(allowed_root)) if known_is_symlink is None else Path(os.path.abspath(os.path.normpath(str(Path(allowed_root).expanduser()))))
    if known_is_symlink is None:
        try:
            is_link = candidate.is_symlink()
        except OSError:
            is_link = True
        resolved = _resolve(candidate)
    else:
        is_link = bool(known_is_symlink)
        resolved = _resolve(candidate) if is_link else Path(os.path.abspath(os.path.normpath(str(candidate))))
    if is_link:
        return _decision(Classification.PROTECTED, "symlink requires explicit review", "symlink")
    if _is_external(resolved):
        return _decision(Classification.PROTECTED, "external, removable, or network volume", "mount path")
    if not _inside(resolved, root):
        return _decision(Classification.PROTECTED, "outside allowed root", str(root))
    if _under_any(resolved, SYSTEM_ROOTS) and resolved in SYSTEM_ROOTS:
        return _decision(Classification.PROTECTED, "system path", "system denylist")
    if _under_any(resolved, SYSTEM_ROOTS) and not _under_any(root, SYSTEM_ROOTS):
        return _decision(Classification.PROTECTED, "system path", "system denylist")
    home = Path.home().resolve(strict=False)
    protected_user = [home / name for name in ("Desktop", "Documents", "Pictures", "Movies", "Music", "Public")]
    if _under_any(resolved, protected_user):
        return _decision(Classification.PROTECTED, "personal data path", "user data denylist")
    reason = _marker_reason(resolved)
    if reason:
        return _decision(Classification.PROTECTED, reason, resolved.name)
    if _looks_like_project(resolved):
        return _decision(Classification.PROTECTED, "development project or repository path", resolved.name)
    if known_stat is None:
        try:
            candidate.stat()
        except PermissionError:
            return _decision(Classification.PROTECTED, "permission denied; fail closed", "PermissionError")
        except OSError as exc:
            return _decision(Classification.PROTECTED, "path metadata unavailable; fail closed", type(exc).__name__)
    return _decision(Classification.REVIEW, "no automatic SAFE evidence yet", "policy default")


def _decision(classification, reason, evidence):
    source = ProtectionSource.POLICY if classification == Classification.PROTECTED else ProtectionSource.NONE
    return PolicyDecision(source, Disposition(classification.value), reason, evidence)
