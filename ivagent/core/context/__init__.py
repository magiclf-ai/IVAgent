#!/usr/bin/env python3
"""
上下文管理核心组件。

提供 ArtifactStore、MessageManager、ContextAssembler 等通用组件。
"""

from .artifact_store import ArtifactStore, ArtifactReference
from .message_manager import MessageManager, AgentMessage
from .context_assembler import ContextAssembler
from .context_compressor import ContextCompressor, ContextCompressionResult
from .read_artifact_pruner import ReadArtifactPruner, ReadArtifactPruneResult

__all__ = [
    "ArtifactStore",
    "ArtifactReference",
    "MessageManager",
    "AgentMessage",
    "ContextAssembler",
    "ContextCompressor",
    "ContextCompressionResult",
    "ReadArtifactPruner",
    "ReadArtifactPruneResult",
]
