#!/usr/bin/env python3
"""
任务管理数据模型

定义任务状态和任务数据结构，用于 Orchestrator 任务管理。
"""

from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
import uuid


class TaskStatus(str, Enum):
    """
    任务状态枚举

    定义了任务的生命周期状态：
    - PENDING: 待执行
    - IN_PROGRESS: 执行中
    - COMPLETED: 已完成
    - FAILED: 执行失败
    """
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskStatusTransitionError(Exception):
    """非法状态转换异常"""
    pass


@dataclass
class Task:
    """
    任务数据模型

    表示 Orchestrator 中的一个任务单元，支持任务树结构（通过 parent_id）。
    """

    id: str  # 唯一标识符 (UUID)
    description: str  # 任务描述
    status: TaskStatus  # 任务状态
    parent_id: Optional[str] = None  # 父任务 ID (支持任务树)
    created_at: datetime = field(default_factory=datetime.now)  # 创建时间
    completed_at: Optional[datetime] = None  # 完成时间
    result: Optional[str] = None  # 任务执行结果
    error_message: Optional[str] = None  # 错误信息

    def __post_init__(self):
        """初始化后验证，确保 id 不为空"""
        if not self.id:
            self.id = str(uuid.uuid4())

    def can_transition_to(self, new_status: TaskStatus) -> bool:
        """
        检查是否可以转换到新状态

        Args:
            new_status: 目标状态

        Returns:
            bool: 是否可以转换
        """
        # 允许任何状态转换为 pending (重新开始)
        if new_status == TaskStatus.PENDING:
            return True

        # PENDING 可以转换为任何状态
        if self.status == TaskStatus.PENDING:
            return True

        # IN_PROGRESS 只能转换为 COMPLETED 或 FAILED
        if self.status == TaskStatus.IN_PROGRESS:
            return new_status in [TaskStatus.COMPLETED, TaskStatus.FAILED]

        # COMPLETED 和 FAILED 不能再转换（除非转为 PENDING）
        if self.status in [TaskStatus.COMPLETED, TaskStatus.FAILED]:
            return new_status == TaskStatus.PENDING

        return False

    def transition_to(self, new_status: TaskStatus) -> "Task":
        """
        转换到新状态

        Args:
            new_status: 目标状态

        Returns:
            Task: 转换后的新 Task 对象

        Raises:
            TaskStatusTransitionError: 非法状态转换
        """
        if not self.can_transition_to(new_status):
            raise TaskStatusTransitionError(
                f"Cannot transition from {self.status} to {new_status}"
            )

        # 更新状态和相关时间戳
        task = Task(
            id=self.id,
            description=self.description,
            status=new_status,
            parent_id=self.parent_id,
            created_at=self.created_at,
            completed_at=self.completed_at,
            result=self.result,
            error_message=self.error_message,
        )

        # 更新时间戳
        if new_status in [TaskStatus.COMPLETED, TaskStatus.FAILED]:
            task.completed_at = datetime.now()
        else:
            task.completed_at = None

        return task

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "id": self.id,
            "description": self.description,
            "status": self.status.value,
            "parent_id": self.parent_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": self.result,
            "error_message": self.error_message,
        }

    def to_summary_dict(self) -> Dict[str, Any]:
        """
        转换为精简摘要字典（用于 LLM 返回）

        只包含关键信息，避免返回过多细节。
        """
        return {
            "id": self.id,
            "description": self.description,
            "status": self.status.value,
            "parent_id": self.parent_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Task":
        """从字典创建 Task"""
        # 解析 datetime 字符串
        created_at = None
        if data.get("created_at"):
            try:
                created_at = datetime.fromisoformat(data["created_at"])
            except (ValueError, TypeError):
                created_at = None

        completed_at = None
        if data.get("completed_at"):
            try:
                completed_at = datetime.fromisoformat(data["completed_at"])
            except (ValueError, TypeError):
                completed_at = None

        return cls(
            id=data.get("id", str(uuid.uuid4())),
            description=data.get("description", ""),
            status=TaskStatus(data.get("status", TaskStatus.PENDING)),
            parent_id=data.get("parent_id"),
            created_at=created_at or datetime.now(),
            completed_at=completed_at,
            result=data.get("result"),
            error_message=data.get("error_message"),
        )


__all__ = [
    "TaskStatus",
    "TaskStatusTransitionError",
    "Task",
]
