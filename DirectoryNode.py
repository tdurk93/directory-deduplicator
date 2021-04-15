from __future__ import annotations
import hashlib
from collections import OrderedDict


class FileNode:
    def __init__(self, diskSpace: int, hash: str):
        self.diskSpace = diskSpace
        self.hash = hash


class DirectoryNode(FileNode):

    def __init__(self, parent: DirectoryNode, path: str):
        super().__init__(diskSpace=-1, hash="")
        self.parent = parent
        self.path = path
        self.subdirectoryNodes = OrderedDict()
        self.files = OrderedDict()

    def getHash(self) -> str:
        if not self.hash:
            self.hash, self.diskSpace = self.__calculateHashAndDiskSpace__()
        return self.hash

    def getDiskUsage(self) -> int:
        if self.diskSpace == -1:
            self.hash, self.diskSpace = self.__calculateHashAndDiskSpace__()
        return self.diskSpace

    def __calculateHashAndDiskSpace__(self) -> tuple[str, int]:
        """
        This has a side effect of saving to instance variables
        & does not return a value
        """
        subfolderHashTuple, subfolderDiskUsageTuple = \
            tuple(zip(*[child.__calculateHashAndDiskSpace__() for child in
                        self.subdirectoryNodes.values()] or [("", 0)]))
        subfolderHashes = "".join(subfolderHashTuple)
        fileHashes = "".join([file.hash for file in self.files.values()])
        fileDiskSpace = sum([file.diskSpace for file in self.files.values()])
        self.hash = hashlib.sha256((subfolderHashes +
                                    fileHashes).encode("utf-8")).hexdigest()
        self.diskSpace = sum(subfolderDiskUsageTuple, fileDiskSpace)
        return (self.hash, self.diskSpace)

    def __repr__(self) -> str:
        reprLines = [f"{self.path}:\n  fileHashes for files:",
                     "\n".join([f"\t{key}: {value}" for key, value in
                                self.fileHashes.items()]) or "none",
                     " subdirectories:"] + \
            ["\n".join(
                [f"\t{line}" for line in child.__repr__().split("\n")]
            ) for child in self.subdirectoryNodes.values()] or ["none"]
        return "\n".join(reprLines)
