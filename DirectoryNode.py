from __future__ import annotations
from typing import Any, cast, Dict, Optional, ValuesView
from collections import OrderedDict
import xxhash
import zlib


class FileNode:
    def __init__(self, diskSpace: int, hash: str):
        self.diskSpace = diskSpace
        self.hash = hash

    def __repr__(self) -> str:
        return f"[hash: {self.hash}, diskSpace: {self.diskSpace}]"


class DirectoryNode(FileNode):
    def __init__(self, parent: Optional[DirectoryNode], path: str):
        super().__init__(diskSpace=-1, hash="")
        self.parent = parent
        self.path = path
        self.subdirectoryNodes: Dict[str, DirectoryNode] = OrderedDict()
        self.files: Dict[str, FileNode] = OrderedDict()
        self.numFiles = -1  # includes files in subfolders
        self.numSubdirectories = -1  # includes folders of subfolders

    def getHash(self) -> str:
        if not self.hash:
            self.__calculateAggregateValues__()
        return self.hash

    def getDiskUsage(self) -> int:
        if self.diskSpace == -1:
            self.__calculateAggregateValues__()
        return self.diskSpace

    def getNumFiles(self) -> int:
        if self.numFiles == -1:
            self.__calculateAggregateValues__()
        return self.numFiles

    def getNumSubdirectories(self) -> int:
        if self.numSubdirectories == -1:
            self.__calculateAggregateValues__()
        return self.numSubdirectories

    def __calculateAggregateValues__(self) -> Dict[str, Any]:
        """
        This has a side effect of saving to instance variables,
        which is needed so that calculations for all child nodes are cached
        """
        subfolderHashTuple, subfolderDiskUsageTuple, \
            subfolderNumFileTuple, subfolderNumSubdirTuple = \
            tuple(zip(*[child.__calculateAggregateValues__().values() for child
                        in self.subdirectoryNodes.values()]
                      or cast(ValuesView[Any], [("", 0, 0, 0)])))
        # need stable order for hashes to maintain file-renaming invariance
        subfolderHashes = "".join(sorted(subfolderHashTuple))
        fileHashes = "".join(
            sorted([file.hash for file in self.files.values()]))
        fileAndFolderHashes = (subfolderHashes + fileHashes).encode("utf-8")
        self.hash = xxhash.xxh3_128_hexdigest(fileAndFolderHashes)
        # concatenate second hash/checksum for reduced chance of collisions
        self.hash += str(zlib.crc32(fileAndFolderHashes))
        fileDiskSpace = sum([file.diskSpace for file in self.files.values()])
        self.diskSpace = sum(subfolderDiskUsageTuple, fileDiskSpace)
        self.numFiles = sum(subfolderNumFileTuple, len(self.files))
        self.numSubdirectories = sum(subfolderNumSubdirTuple,
                                     len(self.subdirectoryNodes))
        return {
            "hash": self.hash,
            "diskSpace": self.diskSpace,
            "numFiles": self.numFiles,
            "numSubdirectories": self.numSubdirectories
        }

    def __repr__(self) -> str:
        reprLines = [f"{self.path}:\n  fileHashes for files:",
                     "\n".join([f"\t{key}: {value}" for key, value in
                                self.files.items()]) or "none",
                     " subdirectories:"] + \
            ["\n".join(
                [f"\t{line}" for line in child.__repr__().split("\n")]
            ) for child in self.subdirectoryNodes.values()] or ["none"]
        return "\n".join(reprLines)
