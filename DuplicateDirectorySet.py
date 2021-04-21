from typing import List
from DirectoryNode import DirectoryNode


class DuplicateDirectorySet:
    def __init__(self, diskSpace: int, numFiles: int, numSubdirectories: int,
                 directoryNodes: List[DirectoryNode]):
        self.diskSpace = diskSpace
        self.numFiles = numFiles
        self.numSubdirectories = numSubdirectories
        self.directoryNodes = directoryNodes

    def __repr__(self) -> str:
        return "\n".join([
            "[DuplicateDirectorySet:",
            f"diskSpace: {self.diskSpace}",
            f"numFiles: {self.numFiles}",
            f"numSubdirectories: {self.numSubdirectories}",
            f"directoryNodes: {self.directoryNodes}"
        ])
