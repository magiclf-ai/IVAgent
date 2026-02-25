#!/usr/bin/env python3
"""
FileManager - Session 目录和数据文件管理器

管理 session 目录结构和数据文件的读写，支持路径安全检查和文件大小限制。
"""

import os
from typing import List
from pathlib import Path


class FileManager:
    """
    文件管理器
    
    职责：
    - 管理 session 目录结构
    - 提供数据文件的读写接口
    - 实现路径安全检查（防止路径遍历）
    - 实现文件大小限制检查
    
    目录结构：
    .ivagent/sessions/{session_id}/
    ├── tasks.md                          # 任务列表
    ├── workflow.md                       # Workflow 文档副本
    └── artifacts/                        # 数据文件目录
        ├── task_1_attack_surface.md      # 任务 1 输出
        ├── task_2_vuln_results.md        # 任务 2 输出
        └── ...
    """
    
    # 文件大小限制（默认 10MB）
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB in bytes
    
    def __init__(self, session_dir: Path):
        """
        初始化文件管理器
        
        Args:
            session_dir: Session 目录路径 (如 .ivagent/sessions/{session_id})
        """
        self.session_dir = Path(session_dir).resolve()
        self.artifacts_dir = self.session_dir / "artifacts"
        
        # 初始化目录结构
        self._init_directories()
    
    def _init_directories(self) -> None:
        """初始化 session 目录结构"""
        # 创建 session 目录
        self.session_dir.mkdir(parents=True, exist_ok=True)
        
        # 创建 artifacts 目录
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
    
    def get_artifact_path(self, task_id: str, artifact_name: str) -> Path:
        """
        生成数据文件路径
        
        Args:
            task_id: 任务 ID (如 task_1)
            artifact_name: 数据文件名称 (如 attack_surface)
        
        Returns:
            Path: 数据文件的完整路径
        
        Example:
            >>> fm = FileManager(Path(".ivagent/sessions/session_123"))
            >>> path = fm.get_artifact_path("task_1", "attack_surface")
            >>> print(path)
            .ivagent/sessions/session_123/artifacts/task_1_attack_surface.md
        """
        # 生成文件名: {task_id}_{artifact_name}.md
        filename = f"{task_id}_{artifact_name}.md"
        
        # 返回完整路径
        return self.artifacts_dir / filename

    def read_artifact(self, file_path: Path) -> str:
        """
        读取数据文件
        
        Args:
            file_path: 文件路径
        
        Returns:
            str: 文件内容
        
        Raises:
            ValueError: 路径不安全（路径遍历攻击）
            FileNotFoundError: 文件不存在
            ValueError: 文件大小超过限制
        """
        # 路径安全检查
        self._validate_path(file_path)
        
        # 检查文件是否存在
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # 检查文件大小
        file_size = file_path.stat().st_size
        if file_size > self.MAX_FILE_SIZE:
            raise ValueError(
                f"File size ({file_size} bytes) exceeds limit ({self.MAX_FILE_SIZE} bytes)"
            )
        
        # 读取文件内容
        return file_path.read_text(encoding="utf-8")
    
    def write_artifact(self, file_path: Path, content: str) -> None:
        """
        写入数据文件
        
        Args:
            file_path: 文件路径
            content: 文件内容
        
        Raises:
            ValueError: 路径不安全（路径遍历攻击）
            ValueError: 内容大小超过限制
        """
        # 路径安全检查
        self._validate_path(file_path)
        
        # 检查内容大小
        content_size = len(content.encode("utf-8"))
        if content_size > self.MAX_FILE_SIZE:
            raise ValueError(
                f"Content size ({content_size} bytes) exceeds limit ({self.MAX_FILE_SIZE} bytes)"
            )
        
        # 确保父目录存在
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 写入文件
        file_path.write_text(content, encoding="utf-8")
    
    def list_artifacts(self) -> List[Path]:
        """
        列出所有数据文件
        
        Returns:
            List[Path]: 数据文件路径列表（按文件名排序）
        """
        if not self.artifacts_dir.exists():
            return []
        
        # 获取所有 .md 文件
        artifacts = list(self.artifacts_dir.glob("*.md"))
        
        # 按文件名排序
        return sorted(artifacts)
    
    def _validate_path(self, file_path: Path) -> None:
        """
        验证路径安全性（防止路径遍历攻击）
        
        Args:
            file_path: 要验证的文件路径
        
        Raises:
            ValueError: 路径不安全
        """
        # 解析为绝对路径
        resolved_path = Path(file_path).resolve()
        
        # 检查路径是否在 session 目录内
        try:
            resolved_path.relative_to(self.session_dir)
        except ValueError:
            raise ValueError(
                f"Path traversal detected: {file_path} is outside session directory"
            )


__all__ = [
    "FileManager",
]
