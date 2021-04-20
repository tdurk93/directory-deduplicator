#!/usr/bin/env python3

from DirectoryNode import DirectoryNode, FileNode
from collections import defaultdict

import click
import os
import sys
import xxhash
import zlib

hashes = defaultdict(list)


def buildTree(directoryPath: str, parent: DirectoryNode,
              safe: bool) -> DirectoryNode:
    node = DirectoryNode(path=directoryPath, parent=parent)
    entries = os.scandir(directoryPath)
    for entry in sorted(entries, key=lambda x: x.name):
        if entry.is_file() and not entry.is_symlink():
            # TODO handle empty file case (const hash or ignore?)
            # hash the contents of the file, insert into dict
            with open(entry.path, "rb") as currentFile:
                fileContents = currentFile.read()
                fileHash = xxhash.xxh3_128_hexdigest(fileContents)
                if safe:
                    fileHash += str(zlib.crc32(fileContents))
                node.files[entry.path] = FileNode(entry.stat().st_size,
                                                  fileHash)
        elif entry.is_dir():
            node.subdirectoryNodes[entry.path] = buildTree(
                entry.path, node, safe)
    if hashes[node.getHash()]:
        # This hash has already been seen. Therefore, subdirectories
        # are already duplicated in list. Remove immediate children nodes
        # from hash map, so we only track the roots of duplicate subtrees
        for childDirNode in node.subdirectoryNodes.values():
            hashes[childDirNode.getHash()].remove(childDirNode)
    hashes[node.getHash()].append(node)
    return node


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
@click.option("--safe",
              is_flag=True,
              default=False,
              help="Double-check results with an additional hashing algorithm")
def run(safe: bool, directory_path: click.Path) -> None:
    rootNode = buildTree(directory_path, None, safe=safe)

    # add one to numSubdirectories for root node
    print(f"Scanned {rootNode.getNumSubdirectories() + 1} directories " +
          f"({bytes2human(rootNode.diskSpace)})",
          file=sys.stderr)
    # print(rootNode.__repr__()) # uncomment for debugging

    # print out duplicate directories
    for nodeList in hashes.values():
        if len(nodeList) > 1:
            numFiles = nodeList[0].getNumFiles()
            numSubdirs = nodeList[0].getNumSubdirectories()
            diskSpace = bytes2human(nodeList[0].getDiskUsage())
            summary = f"{numFiles} files, {numSubdirs} folders, {diskSpace}"
            print(f"Duplicate directory set ({summary}):", file=sys.stderr)
            print("\t" + "\n\t".join([node.path for node in nodeList]))


if __name__ == '__main__':
    run()
