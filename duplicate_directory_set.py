from typing import List
from directory_node import DirectoryNode


class DuplicateDirectorySet:
    def __init__(self, disk_space: int, num_files: int, num_subdirectories: int,
                 directory_nodes: List[DirectoryNode]):
        self.disk_space = disk_space
        self.num_files = num_files
        self.num_subdirectories = num_subdirectories
        self.directory_nodes = directory_nodes

    def __repr__(self) -> str:
        return "\n".join([
            "[DuplicateDirectorySet:",
            f"disk_space: {self.disk_space}",
            f"num_files: {self.num_files}",
            f"num_subdirectories: {self.num_subdirectories}",
            f"directory_nodes: {self.directory_nodes}"
        ])
