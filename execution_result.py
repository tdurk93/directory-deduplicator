from datetime import datetime
from directory_node import DirectoryNode
from typing import Dict, List

# class storing results of an execution. Used for (de-)serialization
class ExecutionResult:
    def __init__(self, root_node: DirectoryNode, hashes: Dict[str, List[DirectoryNode]]):
        self.timestamp = datetime.now().isoformat()
        self.root: DirectoryNode = root_node
        self.hashes = hashes