"""Abstract base for bounty platform clients."""

from abc import ABC, abstractmethod


class PlatformClient(ABC):
    @abstractmethod
    async def search_programs(self, **filters) -> list[dict]:
        ...

    @abstractmethod
    async def get_reports(self, target: str) -> list[dict]:
        ...

    @abstractmethod
    async def check_duplicate(self, target: str, vuln_type: str, desc: str) -> dict:
        ...
