#!/usr/bin/env python3

from directory_node import DirectoryNode, MiNode
from duplicate_directory_set import DuplicateDirectorySet
from progress_tracker import track_progress
from util import bytes2human, print_message
from multiprocessing import Process, Queue
from collections import defaultdict
from typing import Dict, List
from io import BufferedReader

import click
import os
import sys
import xxhash

BUFFER_SIZE = 1024 * 1024 * 10  # 10MB
EMPTY_FILE_DIGEST = "EMPTY"
file_name_queue = Queue()
bytes_processed_queue = Queue()


def build_metadata_tree(directory_path: str, follow_symlinks: bool = False) -> DirectoryNode:
    node = DirectoryNode(directory_path)

    try:
      entries = os.scandir(directory_path)
    except PermissionError:
        print(f"Could not open directory {directory_path}: permission denied",
              file=sys.stderr)
        return node
    for entry in sorted(entries, key=lambda x: x.name):
        try:
            if entry.is_symlink() and not follow_symlinks:
                continue
            elif entry.is_file():
                file_size = entry.stat().st_size
                node.files[entry.path] = MiNode(entry.name, file_size)
                node.disk_space += file_size
                node.num_files += 1
            elif entry.is_dir():
                subdir_node = build_metadata_tree(entry.path, follow_symlinks)
                node.disk_space += subdir_node.disk_space
                node.num_files += subdir_node.num_files
                node.num_subdirectories += subdir_node.num_subdirectories + 1
                node.subdir_nodes[entry.path] = subdir_node
        except:
            print(f"Could not read metadata for path {entry.path}", file=sys.stderr)
    return node


def build_hash_map(node: DirectoryNode, working_hash_map: Dict[str, List[DirectoryNode]]) -> str:
    file_hashes: List[str] = []
    subdir_hashes: List[str] = []
    for file_path, file_node in node.files.items():
        if node.disk_space == 0:
                file_hashes.append(EMPTY_FILE_DIGEST)
                # TODO improve handling of empty files (exclude from results by default?)
                continue
        hash_builder = xxhash.xxh3_128()
        try:
            # hash the contents of the file
            with open(file_path, "rb") as current_file:
                file_name_queue.put(file_node.name)
                reader = BufferedReader(current_file)
                while file_chunk := reader.read(BUFFER_SIZE):
                    hash_builder.update(file_chunk)
                    bytes_processed_queue.put(len(file_chunk))
            file_hashes.append(hash_builder.hexdigest())
        except (PermissionError, OSError):
            print(f"Could not open file {file_path}",
                  file=sys.stderr)
            # use file name & size as stand-in for file contents
            summary = f"Couldn't Read: {file_path}".encode()
            file_hashes.append(xxhash.xxh3_128_hexdigest(summary))
    for child_node in node.subdir_nodes.values():
        subdir_hash = build_hash_map(child_node, working_hash_map)
        subdir_hashes.append(subdir_hash)
    node_summary: str = ",".join(sorted(file_hashes) + sorted(subdir_hashes))
    node.hash = xxhash.xxh3_128_hexdigest(node_summary.encode())
    working_hash_map[node.hash].append(node)
    return node.hash


def find_duplicate_directory_sets(
    directory_hash_map: Dict[str, List[DirectoryNode]]
) -> List[DuplicateDirectorySet]:
    duplicate_directory_sets = []
    for directory_set in directory_hash_map.values():
        if len(directory_set) > 1:
            num_files = directory_set[0].num_files
            num_subdirs = directory_set[0].num_subdirectories
            disk_space = directory_set[0].disk_space
            duplicate_directory_sets.append(
                DuplicateDirectorySet(disk_space, num_files, num_subdirs,
                                      directory_set))
    return duplicate_directory_sets

@click.command()
@click.argument("directory-path",
                type=click.Path(exists=True, file_okay=False))
@click.option("--follow-symlinks",
              is_flag=True,
              default=False,
              help="Follow symbolic links")
def run(follow_symlinks: bool, directory_path: str) -> None:
    print("Scanning file metadata...")
    root_node: DirectoryNode = build_metadata_tree(directory_path=directory_path, follow_symlinks=follow_symlinks)
    print(f"Found {root_node.num_files} files ({bytes2human(root_node.disk_space)}), {root_node.num_subdirectories} folders")
    p = Process(target=track_progress, args=(file_name_queue, bytes_processed_queue), daemon=True)
    p.start()
    directory_hash_map = defaultdict(list)
    build_hash_map(root_node, directory_hash_map)

    p.terminate()
    p.join()  # block/wait until the process is actually killed
    p.close()  # close any resources associated with the process

    # add one to num_subdirectories for root node
    print_message(f"Scanned {root_node.num_subdirectories + 1} directories, " +
          f"{len(directory_hash_map)} files ({bytes2human(root_node.disk_space)})",
          file=sys.stderr)
    print()

    duplicate_directory_sets = find_duplicate_directory_sets(
        directory_hash_map)
    potential_space_savings = 0
    for dir_set in sorted(duplicate_directory_sets,
                          key=lambda x: x.disk_space,
                          reverse=True):
        summary = ", ".join([
            f"{dir_set.num_files} files",
            f"{dir_set.num_subdirectories} folders",
            f"{bytes2human(dir_set.disk_space)}"
        ])
        print(f"Duplicate directory set ({summary}):")
        for node in dir_set.directory_nodes:
            print(f"\t{node.path}")
        potential_space_savings += dir_set.disk_space * (
            len(dir_set.directory_nodes) - 1)
    print(f"Potential space savings: {bytes2human(potential_space_savings)}")
