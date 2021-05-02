#!/usr/bin/env python3

from DirectoryNode import DirectoryNode, FileNode
from DuplicateDirectorySet import DuplicateDirectorySet
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

import click
import os
import sys
import xxhash
import zlib


def buildTree(
        directoryPath: str, parent: Optional[DirectoryNode],
        directoryHashMap: Dict[str, List[DirectoryNode]],
        safe_hash: bool = False,
        follow_symlinks: bool = False) -> Tuple[DirectoryNode, Dict[str, List[DirectoryNode]]]:
    node = DirectoryNode(path=directoryPath, parent=parent)
    entries = os.scandir(directoryPath)
    for entry in sorted(entries, key=lambda x: x.name):
        if entry.is_file() and (follow_symlinks or not entry.is_symlink()):
            # hash the contents of the file, insert into dict
            with open(entry.path, "rb") as currentFile:
                fileContents = currentFile.read()
                fileHash = xxhash.xxh3_128_hexdigest(fileContents)
                if safe_hash:
                    fileHash += str(zlib.crc32(fileContents))
                if (entry.stat().st_size == 0):
                    fileHash = "EMPTY" # override prev value, if applicable
                node.files[entry.path] = FileNode(entry.stat().st_size,
                                                  fileHash)
        elif entry.is_dir():
            node.subdirectoryNodes[
                entry.path], subdirectoryHashMap = buildTree(
                    entry.path, node, directoryHashMap, safe_hash)
    if directoryHashMap[node.getHash()]:
        # This hash has already been seen. Therefore, subdirectories
        # are already duplicated in list. Remove immediate children nodes
        # from hash map, so we only track the roots of duplicate subtrees
        for childDirNode in node.subdirectoryNodes.values():
            directoryHashMap[childDirNode.getHash()].remove(childDirNode)
    directoryHashMap[node.getHash()].append(node)
    return node, directoryHashMap


def findDuplicateDirectorySets(
    directoryHashMap: Dict[str, List[DirectoryNode]]
) -> List[DuplicateDirectorySet]:
    duplicateDirectorySets = []
    for directorySet in directoryHashMap.values():
        if len(directorySet) > 1:
            numFiles = directorySet[0].getNumFiles()
            numSubdirs = directorySet[0].getNumSubdirectories()
            diskSpace = directorySet[0].getDiskUsage()
            duplicateDirectorySets.append(
                DuplicateDirectorySet(diskSpace, numFiles, numSubdirs,
                                      directorySet))
    return duplicateDirectorySets


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
    rootNode, directoryHashMap = buildTree(directory_path,
                                           None,
                                           defaultdict(list),
                                           safe_hash=safe_hash,
                                           follow_symlinks=follow_symlinks)

    # add one to numSubdirectories for root node
    print(f"Scanned {rootNode.getNumSubdirectories() + 1} directories " +
          f"({bytes2human(rootNode.diskSpace)})",
          file=sys.stderr)

    duplicateDirectorySets = findDuplicateDirectorySets(directoryHashMap)
    for directorySet in duplicateDirectorySets:
        summary = ", ".join([
            f"{directorySet.numFiles} files",
            f"{directorySet.numSubdirectories} folders",
            f"{bytes2human(directorySet.diskSpace)}"
        ])
        print(f"Duplicate directory set ({summary}):", file=sys.stderr)
        print("\t" +
              "\n\t".join([node.path for node in directorySet.directoryNodes]))