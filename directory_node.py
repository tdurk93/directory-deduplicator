from __future__ import annotations
from typing import Any, cast, Dict, ValuesView
from collections import OrderedDict
import xxhash
import zlib


class FileNode:
    def __init__(self, disk_space: int, hash: str):
        self.disk_space = disk_space
        self.hash = hash

    def __repr__(self) -> str:
        return f"[hash: {self.hash}, disk_space: {self.disk_space}]"


class DirectoryNode(FileNode):
    def __init__(self, path: str):
        super().__init__(disk_space=-1, hash="")
        self.path = path
        self.subdirectory_nodes: Dict[str, DirectoryNode] = OrderedDict()
        self.files: Dict[str, FileNode] = OrderedDict()
        self.num_files = -1  # includes files in subfolders
        self.num_subdirectories = -1  # includes folders of subfolders

    def get_hash(self) -> str:
        if not self.hash:
            self.__calculate_aggregate_values__()
        return self.hash

    def get_disk_usage(self) -> int:
        if self.disk_space == -1:
            self.__calculate_aggregate_values__()
        return self.disk_space

    def get_num_files(self) -> int:
        if self.num_files == -1:
            self.__calculate_aggregate_values__()
        return self.num_files

    def get_num_subdirectories(self) -> int:
        if self.num_subdirectories == -1:
            self.__calculate_aggregate_values__()
        return self.num_subdirectories

    def __calculate_aggregate_values__(self) -> Dict[str, Any]:
        """
        This has a side effect of saving to instance variables,
        which is needed so that calculations for all child nodes are cached
        """
        subfolder_hash_tuple, subfolder_disk_usage_tuple, \
            subfolder_num_file_tuple, subfolder_num_subdir_tuple = \
            tuple(zip(*[child.__calculate_aggregate_values__().values() for child
                        in self.subdirectory_nodes.values()]
                      or cast(ValuesView[Any], [("", 0, 0, 0)])))
        # need stable order for hashes to maintain file-renaming invariance
        subfolder_hashes = "".join(sorted(subfolder_hash_tuple))
        file_hashes = "".join(
            sorted([file.hash for file in self.files.values()]))
        file_and_folder_hashes = (subfolder_hashes + file_hashes).encode("utf-8")
        self.hash = xxhash.xxh3_128_hexdigest(file_and_folder_hashes)
        # concatenate second hash/checksum for reduced chance of collisions
        self.hash += str(zlib.crc32(file_and_folder_hashes))
        file_disk_space = sum([file.disk_space for file in self.files.values()])
        self.disk_space = sum(subfolder_disk_usage_tuple, file_disk_space)
        self.num_files = sum(subfolder_num_file_tuple, len(self.files))
        self.num_subdirectories = sum(subfolder_num_subdir_tuple,
                                     len(self.subdirectory_nodes))
        return {
            "hash": self.hash,
            "disk_space": self.disk_space,
            "num_files": self.num_files,
            "num_subdirectories": self.num_subdirectories
        }

    def __repr__(self) -> str:
        repr_lines = [f"{self.path}:\n  fileHashes for files:",
                     "\n".join([f"\t{key}: {value}" for key, value in
                                self.files.items()]) or "none",
                     " subdirectories:"] + \
            ["\n".join(
                [f"\t{line}" for line in child.__repr__().split("\n")]
            ) for child in self.subdirectory_nodes.values()] or ["none"]
        return "\n".join(repr_lines)
