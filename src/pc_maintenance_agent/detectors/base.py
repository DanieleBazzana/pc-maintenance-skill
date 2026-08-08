from dataclasses import dataclass
from typing import Callable, Iterable, List

from ..domain.models import Finding


DetectorRunner = Callable[..., List[Finding]]


@dataclass(frozen=True)
class DetectorSpec:
    name: str
    runner: DetectorRunner

    def run(self, entries: Iterable, *, max_hash_files: int, large_threshold: int) -> List[Finding]:
        if self.name == "duplicates":
            return self.runner(entries, max_hash_files=max_hash_files)
        if self.name == "large":
            return self.runner(entries, threshold=large_threshold)
        return self.runner(entries)
