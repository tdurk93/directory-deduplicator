#!/usr/bin/env python3

from directory_node import DirectoryNode, FileNode
from duplicate_directory_set import DuplicateDirectorySet
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

import click
import os
import sys
import xxhash
import zlib


def build_tree(
        directory_path: str, parent: Optional[DirectoryNode],
        directory_hash_map: Dict[str, List[DirectoryNode]],
        safe_hash: bool = False,
        follow_symlinks: bool = False) -> Tuple[DirectoryNode, Dict[str, List[DirectoryNode]]]:
    node = DirectoryNode(path=directory_path, parent=parent)
    entries = os.scandir(directory_path)
    for entry in sorted(entries, key=lambda x: x.name):
        if entry.is_file() and (follow_symlinks or not entry.is_symlink()):
            # hash the contents of the file, insert into dict
            with open(entry.path, "rb") as current_file:
                file_contents = current_file.read()
                file_hash = xxhash.xxh3_128_hexdigest(file_contents)
                if safe_hash:
                    file_hash += str(zlib.crc32(file_contents))
                if (entry.stat().st_size == 0):
                    file_hash = "EMPTY" # override prev value, if applicable
                node.files[entry.path] = FileNode(entry.stat().st_size,
                                                  file_hash)
        elif entry.is_dir():
            node.subdirectory_nodes[
                entry.path], subdirectory_hash_map = build_tree(
                    entry.path, node, directory_hash_map, safe_hash)
    if directory_hash_map[node.get_hash()]:
        # This hash has already been seen. Therefore, subdirectories
        # are already duplicated in list. Remove immediate children nodes
        # from hash map, so we only track the roots of duplicate subtrees
        for child_dir_node in node.subdirectory_nodes.values():
            directory_hash_map[child_dir_node.get_hash()].remove(child_dir_node)
    directory_hash_map[node.get_hash()].append(node)
    return node, directory_hash_map


def find_duplicate_directory_sets(
    directory_hash_map: Dict[str, List[DirectoryNode]]
) -> List[DuplicateDirectorySet]:
    duplicate_directory_sets = []
    for directory_set in directory_hash_map.values():
        if len(directory_set) > 1:
            num_files = directory_set[0].get_num_files()
            num_subdirs = directory_set[0].get_num_subdirectories()
            disk_space = directory_set[0].get_disk_usage()
            duplicate_directory_sets.append(
                DuplicateDirectorySet(disk_space, num_files, num_subdirs,
                                      directory_set))
    return duplicate_directory_sets


# shamelessly copied from https://stackoverflow.com/questions/13343700/
def bytes2human(n: int, format: str = "%(value)i%(symbol)s") -> str:
    """
    >>> bytes2human(10000)
    "9K"
    >>> bytes2human(100001221)
    "95M"
    """
    symbols = ("B", "K", "M", "G", "T", "P", "E", "Z", "Y")
    prefix = {}
    for i, s in enumerate(symbols[1:]):
        prefix[s] = 1 << (i + 1) * 10
    for symbol in reversed(symbols[1:]):
        if n >= prefix[symbol]:
            value = float(n) / prefix[symbol]
            return format % locals()
    return format % dict(symbol=symbols[0], value=n)


@click.command()
@click.argument("directory-path",
                type=click.Path(exists=True, file_okay=False))
@click.option("--safe-hash",
              is_flag=True,
              default=False,
              help="Double-check results with an additional hashing algorithm")
@click.option("--follow-symlinks",
              is_flag=True,
              default=False,
              help="Follow symbolic links")
def run(safe_hash: bool, follow_symlinks: bool, directory_path: str) -> None:
    root_node, directory_hash_map = build_tree(directory_path,
                                           None,
                                           defaultdict(list),
                                           safe_hash=safe_hash,
                                           follow_symlinks=follow_symlinks)

    # add one to num_subdirectories for root node
    print(f"Scanned {root_node.get_num_subdirectories() + 1} directories " +
          f"({bytes2human(root_node.disk_space)})",
          file=sys.stderr)

    duplicate_directory_sets = find_duplicate_directory_sets(directory_hash_map)
    for directory_set in duplicate_directory_sets:
        summary = ", ".join([
            f"{directory_set.num_files} files",
            f"{directory_set.num_subdirectories} folders",
            f"{bytes2human(directory_set.disk_space)}"
        ])
        print(f"Duplicate directory set ({summary}):", file=sys.stderr)
        print("\t" +
              "\n\t".join([node.path for node in directory_set.directory_nodes]))