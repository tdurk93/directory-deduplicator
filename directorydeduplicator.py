#!/usr/bin/env python3

from directory_node import DirectoryNode, MiNode
from duplicate_directory_set import DuplicateDirectorySet
from execution_result import ExecutionResult
from progress_tracker import track_file_hash_progress, track_fs_scan_progress
from util import bytes2human, format_elapsed_time, print_message
from multiprocessing import Process, Queue
from collections import defaultdict
from termcolor import colored
from time import time
from typing import Dict, List
from io import BufferedReader

import click
import os
import pickle
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
                node.files[entry.path] = MiNode(entry.path, file_size)
                node.disk_space += file_size
                node.num_files += 1
                file_name_queue.put(entry.name)  # the queue is only used to track the number of files here
            elif entry.is_dir():
                subdir_node = build_metadata_tree(entry.path, follow_symlinks)
                node.disk_space += subdir_node.disk_space
                node.num_files += subdir_node.num_files
                node.num_subdirectories += subdir_node.num_subdirectories + 1
                node.subdir_nodes[entry.path] = subdir_node
        except Exception:
            print(f"Could not read metadata for path {entry.path}", file=sys.stderr)
    return node


def get_summary_str(file_or_folder_name: str, digest: str, match_names: bool) -> str:
    return f"{file_or_folder_name}_{digest}" if match_names else digest


def get_file_summary(file_node: MiNode) -> str:
    if file_node.disk_space == 0:
        # TODO improve handling of empty files (exclude from results by default?)
        return EMPTY_FILE_DIGEST
    hash_builder = xxhash.xxh3_128()
    digest: str = ""
    try:
        # hash the contents of the file
        with open(file_node.path, "rb") as current_file:
            file_name_queue.put(file_node.name)
            while file_chunk := current_file.read(BUFFER_SIZE):
                hash_builder.update(file_chunk)
                bytes_processed_queue.put(len(file_chunk))
        digest = hash_builder.hexdigest()
    except (PermissionError, OSError):
        print(f"Could not open file {file_node.path}",
            file=sys.stderr)
        # Hashing the full file path should ensure a unique hash,
        # preventing this directory (and its parents) from being considered.
        # Is this desirable behavior?
        content = f"Couldn't Read: {file_node.path}".encode()
        digest = xxhash.xxh3_128_hexdigest(content)
    return digest


def build_hash_map(node: DirectoryNode,
                   working_hash_map: Dict[str, List[DirectoryNode]],
                   match_names: bool) -> str:
    file_hashes: List[str] = []
    for file_node in node.files.values():
        file_summary: str = get_summary_str(file_node.name, get_file_summary(file_node), match_names)
        file_hashes.append(file_summary)
    subdir_hashes: List[str] = []
    for child_node in node.subdir_nodes.values():
        subdir_digest = build_hash_map(child_node, working_hash_map, match_names)
        subdir_summary = get_summary_str(child_node.name, subdir_digest, match_names)
        subdir_hashes.append(subdir_summary)
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
@click.option("--match-names",
              is_flag=True,
              default=False,
              help="Require file & subdirectory names to match")
@click.option("--import-file",
              # type=click.Path(allow_dash=False, dir_okay=False, exists=True, file_okay=True),
              multiple=True,
              default=[],
              help="import data from a previous scan and compare with current scan. Can be used mutliple times.")
@click.option("--export-file",
              # type=click.Path(writable=True, dir_okay=False, exists=True),
              help="export scan data for future import")
def run(directory_path: str, follow_symlinks: bool, match_names: bool, import_file: List[str], export_file: str) -> None:
    print("Scanning file metadata...")
    start_time: float = time()

    fs_scan_tracker = Process(target=track_fs_scan_progress, args=(file_name_queue,), daemon=True)
    fs_scan_tracker.start()

    root_node: DirectoryNode = build_metadata_tree(directory_path=directory_path, follow_symlinks=follow_symlinks)

    fs_scan_tracker.terminate()
    fs_scan_tracker.join()  # block/wait until the process is actually killed
    fs_scan_tracker.close()  # close any resources associated with the process

    fs_scan_elapsed_time: str = format_elapsed_time(time() - start_time)
    print_message(f"Found {root_node.num_files} files ({bytes2human(root_node.disk_space)}), {root_node.num_subdirectories} folders in {fs_scan_elapsed_time}",
        line_width=80, file=sys.stderr)
    print()

    directory_hash_map = defaultdict(list)
    for import_path in import_file:
        with open(import_path, 'rb') as f:
            print(f"Importing results from {import_path}...", end="")
            imported_results: ExecutionResult = pickle.load(f)
            for hash, nodes in imported_results.hashes.items():
                for n in nodes:
                    if not n.tag:  # keep original tags when nodes are imported, exported, then re-imported
                        n.tag = imported_results.tag
                directory_hash_map[hash].extend(nodes)
            print("done")

    file_hash_tracker = Process(target=track_file_hash_progress, args=(file_name_queue, bytes_processed_queue), daemon=True)
    file_hash_tracker.start()

    build_hash_map(root_node, directory_hash_map, match_names)

    file_hash_tracker.terminate()
    file_hash_tracker.join()  # block/wait until the process is actually killed
    file_hash_tracker.close()  # close any resources associated with the process

    # add one to num_subdirectories for root node
    print_message(f"Scanned {root_node.num_subdirectories + 1} directories, " +
        f"{len(directory_hash_map)} files ({bytes2human(root_node.disk_space)})",
        file=sys.stderr)
    print()

    if export_file:
        print(f"Exporting results to {export_file}...", end="")
        with open(export_file, 'wb') as f:
            run_result: ExecutionResult = ExecutionResult(root_node, directory_hash_map, "TODO")
            pickle.dump(run_result, f)  # TODO consider using JSON instead of pickle format (& change 'wb' to 'w')
        print(" done")

    duplicate_directory_sets = find_duplicate_directory_sets(
        directory_hash_map)
    potential_space_savings = 0

    filtered_results = filter(lambda directory_set: any(map(lambda n : not n.tag, directory_set.directory_nodes)), duplicate_directory_sets)
    for dir_set in sorted(filtered_results,
                          key=lambda x: x.disk_space,
                          reverse=True):
        summary = ", ".join([
            f"{dir_set.num_files} files",
            f"{dir_set.num_subdirectories} folders",
            f"{bytes2human(dir_set.disk_space)}"
        ])
        print(f"Duplicate directory set ({summary}):")
        for node in dir_set.directory_nodes:
            node_tag_str = f"({colored(node.tag, 'green')})" if node.tag else ""
            print(f"\t{node_tag_str} {node.path}")
        potential_space_savings += dir_set.disk_space * (
            len(dir_set.directory_nodes) - 1)
    print(f"Potential space savings: {bytes2human(potential_space_savings)}")
