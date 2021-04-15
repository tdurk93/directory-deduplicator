#!/usr/bin/env python3

from DirectoryNode import DirectoryNode, FileNode

import hashlib
import os
import sys
from collections import defaultdict

testDir = "."
hashes = defaultdict(list)
numDirectories = 0

def buildTree(directoryPath: str, parent: DirectoryNode) -> DirectoryNode:
    global numDirectories
    node = DirectoryNode(path=directoryPath, parent=parent)
    entries = os.scandir(directoryPath)
    # consider sorting entries or inserting into heap
    for entry in sorted(entries, key=lambda x: x.name):
        if entry.is_file() and not entry.is_symlink():
            # TODO handle empty file case (const hash or ignore?)
            # hash the contents of the file, insert into dict
            with open(entry.path, "rb") as currentFile:
                m = hashlib.sha256(currentFile.read())
                node.files[entry.path] = FileNode(entry.stat().st_size, m.hexdigest())
        elif entry.is_dir():
            node.subdirectoryNodes[entry.path] = buildTree(entry.path, node)
    # print(f"Adding node to hash: {node.path}")
    if hashes[node.getHash()]:
        # This hash has already been seen. Therefore, subdirectories
        # are already duplicated in list. Remove immediate children nodes
        # from hash map, so we only track the roots of duplicate subtrees
        for childDirNode in node.subdirectoryNodes.values():
            hashes[childDirNode.getHash()].remove(childDirNode)
    hashes[node.getHash()].append(node)
    numDirectories += 1
    return node

# shamelessly copied from https://stackoverflow.com/questions/13343700/
def bytes2human(n: int, format: str ="%(value)i%(symbol)s") -> str:
    """
    >>> bytes2human(10000)
    "9K"
    >>> bytes2human(100001221)
    "95M"
    """
    symbols = ("B", "K", "M", "G", "T", "P", "E", "Z", "Y")
    prefix = {}
    for i, s in enumerate(symbols[1:]):
        prefix[s] = 1 << (i+1)*10
    for symbol in reversed(symbols[1:]):
        if n >= prefix[symbol]:
            value = float(n) / prefix[symbol]
            return format % locals()
    return format % dict(symbol=symbols[0], value=n)

def run(directoryPath: str) -> None:
    global numDirectories
    if not os.path.isdir(directoryPath):
        raise Exception("Please supply a valid directory path")

    fileHashes = {}
    rootNode = buildTree(directoryPath, None)
    print(f"Scanned {numDirectories} directories ({bytes2human(rootNode.diskSpace)})", file=sys.stderr)
    # print(rootNode.__repr__()) # uncomment for debugging

    # Step 3: print out duplicate directories
    for nodeList in hashes.values():
        if len(nodeList) > 1:
            print(f"Duplicate directories:", file=sys.stderr)
            print("\t" + "\n\t".join([node.path for node in nodeList]))


if __name__ == "__main__":
    run(testDir)
