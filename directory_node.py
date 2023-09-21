from __future__ import annotations
from typing import Any, cast, Dict, ValuesView
from collections import OrderedDict
from os.path import basename


class MiNode:  # represents a file or directory (play on "inode" and "MyNode")
    def __init__(self, path: str, disk_space: int):
        self.path = path
        self.name = basename(path)  # returns empty string for directories
        self.disk_space = disk_space
        self.hash = "" # TODO consider removing?


    def __repr__(self) -> str:
        return f"[hash: {self.hash}, disk_space: {self.disk_space}]"


class DirectoryNode(MiNode):
    def __init__(self, path: str, disk_space=0):
        super().__init__(path=path, disk_space=disk_space)
        self.subdir_nodes: Dict[str, DirectoryNode] = OrderedDict()
        self.files: Dict[str, MiNode] = OrderedDict()
        self.num_files = 0  # includes files in subfolders
        self.num_subdirectories = 0  # includes folders of subfolders

    def __repr__(self) -> str:
        repr_lines = [f"{self.path}:\n  fileHashes for files:",
                     "\n".join([f"\t{key}: {value}" for key, value in
                                self.files.items()]) or "none",
                     " subdirectories:"] + \
            ["\n".join(
                [f"\t{line}" for line in child.__repr__().split("\n")]
            ) for child in self.subdir_nodes.values()] or ["none"]
        return "\n".join(repr_lines)
