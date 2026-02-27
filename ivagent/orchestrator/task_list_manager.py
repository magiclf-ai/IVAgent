#!/usr/bin/env python3
"""
TaskListManager - Markdown Checkbox 格式的任务列表管理器

管理基于 Markdown Checkbox 格式的任务列表，支持任务状态跟踪和持久化。
"""

import re
from typing import List, Optional, Dict, Any
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum


class TaskStatus(str, Enum):
    """
    任务状态枚举
    
    映射到 Markdown Checkbox 格式：
    - PENDING: - [ ] 待执行
    - IN_PROGRESS: - [-] 执行中
    - COMPLETED: - [x] 已完成
    - FAILED: - [!] 失败
    """
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Task:
    """
    任务数据模型
    
    表示一个任务单元，包含 ID、描述、状态和元数据。
    """
    id: str  # 任务 ID (如 task_1, task_2)
    description: str  # 任务描述
    status: TaskStatus  # 任务状态
    created_at: datetime = field(default_factory=datetime.now)  # 创建时间
    completed_at: Optional[datetime] = None  # 完成时间
    depends_on: Optional[str] = None  # 依赖的任务 ID（未来扩展）
    agent_type: Optional[str] = None  # 建议的 Agent 类型（code_explorer / vuln_analysis）
    function_identifier: Optional[str] = None  # 目标函数标识符（vuln_analysis 必需）
    task_group: Optional[str] = None  # 任务分组标识（由 workflow 生成）
    workflow_name: Optional[str] = None  # 所属 workflow 名称
    workflow_execution_mode: Optional[str] = None  # workflow 执行模式
    analysis_context: Optional[str] = None  # 漏洞挖掘前置信息（文件引用或短文本）
    
    def to_markdown_line(self) -> str:
        """
        转换为 Markdown Checkbox 格式
        
        Returns:
            str: Markdown 格式的任务行
        """
        # 状态映射
        checkbox_map = {
            TaskStatus.PENDING: "[ ]",
            TaskStatus.IN_PROGRESS: "[-]",
            TaskStatus.COMPLETED: "[x]",
            TaskStatus.FAILED: "[!]",
        }
        
        checkbox = checkbox_map[self.status]
        return f"- {checkbox} {self.id}: {self.description}"
    
    def to_metadata_comment(self) -> str:
        """
        生成元数据注释
        
        Returns:
            str: HTML 注释格式的元数据
        """
        metadata = {
            "task_id": self.id,
            "created_at": self.created_at.isoformat(),
        }
        
        if self.completed_at:
            metadata["completed_at"] = self.completed_at.isoformat()
        
        if self.depends_on:
            metadata["depends_on"] = self.depends_on
        if self.agent_type:
            metadata["agent_type"] = self.agent_type
        if self.function_identifier:
            metadata["function_identifier"] = self.function_identifier
        if self.task_group:
            metadata["task_group"] = self.task_group
        if self.workflow_name:
            metadata["workflow_name"] = self.workflow_name
        if self.workflow_execution_mode:
            metadata["workflow_execution_mode"] = self.workflow_execution_mode
        if self.analysis_context:
            metadata["analysis_context"] = self.analysis_context
        
        # 生成注释字符串
        metadata_str = ", ".join(f"{k}: {v}" for k, v in metadata.items())
        return f"<!-- {metadata_str} -->"


class TaskListManager:
    """
    任务列表管理器
    
    职责：
    - 管理任务列表的读写
    - 支持 Markdown Checkbox 格式
    - 维护任务状态
    - 持久化到文件系统
    """
    
    def __init__(self, tasks_file: Path):
        """
        初始化任务列表管理器
        
        Args:
            tasks_file: 任务列表文件路径 (如 .ivagent/sessions/{session_id}/tasks.md)
        """
        self.tasks_file = Path(tasks_file)
        self._tasks: Dict[str, Task] = {}
        
        # 如果文件存在，加载任务
        if self.tasks_file.exists():
            self._load_tasks()
    
    def create_tasks(self, task_descriptions: List[Any]) -> None:
        """
        创建任务列表并写入文件
        
        Args:
            task_descriptions: 任务描述列表（字符串或包含 description 的字典）
        """
        # 清空现有任务
        self._tasks.clear()
        
        # 创建新任务
        for idx, description in enumerate(task_descriptions, start=1):
            task_id = f"task_{idx}"
            if isinstance(description, dict):
                task = Task(
                    id=task_id,
                    description=str(description["description"]).strip(),
                    status=TaskStatus.PENDING,
                    agent_type=description.get("agent_type"),
                    function_identifier=description.get("function_identifier"),
                    task_group=description.get("task_group"),
                    workflow_name=description.get("workflow_name"),
                    workflow_execution_mode=description.get("workflow_execution_mode"),
                    analysis_context=description.get("analysis_context"),
                )
            else:
                task = Task(
                    id=task_id,
                    description=str(description).strip(),
                    status=TaskStatus.PENDING,
                )
            self._tasks[task_id] = task
        
        # 写入文件
        self._save_tasks()

    def append_tasks(self, task_descriptions: List[Any]) -> None:
        """
        追加任务到现有列表并写入文件

        Args:
            task_descriptions: 任务描述列表（字符串或包含 description 的字典）
        """
        # 计算当前最大任务编号
        max_num = 0
        for task_id in self._tasks.keys():
            num = self._extract_task_number(task_id)
            if num > max_num:
                max_num = num

        for idx, description in enumerate(task_descriptions, start=1):
            task_id = f"task_{max_num + idx}"
            if isinstance(description, dict):
                task = Task(
                    id=task_id,
                    description=str(description["description"]).strip(),
                    status=TaskStatus.PENDING,
                    agent_type=description.get("agent_type"),
                    function_identifier=description.get("function_identifier"),
                    task_group=description.get("task_group"),
                    workflow_name=description.get("workflow_name"),
                    workflow_execution_mode=description.get("workflow_execution_mode"),
                    analysis_context=description.get("analysis_context"),
                )
            else:
                task = Task(
                    id=task_id,
                    description=str(description).strip(),
                    status=TaskStatus.PENDING,
                )
            self._tasks[task_id] = task

        self._save_tasks()
    
    def get_current_task(self, task_group: Optional[str] = None) -> Optional[Task]:
        """
        获取当前待执行任务（第一个 PENDING 状态的任务）

        Args:
            task_group: 任务分组标识（可选）

        Returns:
            Optional[Task]: 待执行任务，无则返回 None
        """
        tasks = self.get_all_tasks(task_group=task_group)
        for task in tasks:
            if task.status == TaskStatus.PENDING:
                return task
        return None
    
    def update_task_status(
        self,
        task_id: str,
        status: TaskStatus,
        error_message: Optional[str] = None
    ) -> None:
        """
        更新任务状态并写入文件
        
        Args:
            task_id: 任务 ID
            status: 新状态
            error_message: 错误信息（可选，用于 FAILED 状态）
        
        Raises:
            ValueError: 任务不存在
        """
        if task_id not in self._tasks:
            raise ValueError(f"Task not found: {task_id}")
        
        task = self._tasks[task_id]
        task.status = status
        
        # 更新完成时间
        if status in [TaskStatus.COMPLETED, TaskStatus.FAILED]:
            task.completed_at = datetime.now()
        
        # 如果有错误信息，添加到描述中（可选）
        if error_message and status == TaskStatus.FAILED:
            # 可以选择将错误信息添加到任务描述或单独存储
            pass
        
        # 写入文件
        self._save_tasks()
    
    def set_task_function_identifier(self, task_id: str, function_identifier: str) -> None:
        """Update task function_identifier and persist to tasks.md."""
        if task_id not in self._tasks:
            raise ValueError(f"Task not found: {task_id}")

        normalized = (function_identifier or "").strip()
        if not normalized:
            raise ValueError("function_identifier cannot be empty")

        self._tasks[task_id].function_identifier = normalized
        self._save_tasks()

    def get_all_tasks(self, task_group: Optional[str] = None) -> List[Task]:
        """
        获取所有任务

        Args:
            task_group: 任务分组标识（可选）

        Returns:
            List[Task]: 任务列表（按 ID 排序）
        """
        tasks = sorted(self._tasks.values(), key=lambda t: self._extract_task_number(t.id))
        if not task_group:
            return tasks
        return [task for task in tasks if task.task_group == task_group]
    
    def is_all_completed(self, task_group: Optional[str] = None) -> bool:
        """
        检查是否所有任务已完成

        Args:
            task_group: 任务分组标识（可选）

        Returns:
            bool: 是否所有任务已完成
        """
        tasks = self.get_all_tasks(task_group=task_group)
        if not tasks:
            return False
        return all(task.status == TaskStatus.COMPLETED for task in tasks)
    
    def get_task(self, task_id: str) -> Optional[Task]:
        """
        根据 ID 获取任务
        
        Args:
            task_id: 任务 ID
        
        Returns:
            Optional[Task]: 任务对象，不存在返回 None
        """
        return self._tasks.get(task_id)
    
    def get_statistics(self, task_group: Optional[str] = None) -> Dict[str, Any]:
        """
        获取任务统计信息

        Args:
            task_group: 任务分组标识（可选）

        Returns:
            Dict[str, Any]: 统计信息
        """
        tasks = self.get_all_tasks(task_group=task_group)
        total = len(tasks)
        pending = sum(1 for t in tasks if t.status == TaskStatus.PENDING)
        in_progress = sum(1 for t in tasks if t.status == TaskStatus.IN_PROGRESS)
        completed = sum(1 for t in tasks if t.status == TaskStatus.COMPLETED)
        failed = sum(1 for t in tasks if t.status == TaskStatus.FAILED)

        completion_rate = (completed / total * 100) if total > 0 else 0

        return {
            "total": total,
            "pending": pending,
            "in_progress": in_progress,
            "completed": completed,
            "failed": failed,
            "completion_rate": round(completion_rate, 2),
        }
    
    def _load_tasks(self) -> None:
        """从文件加载任务列表"""
        if not self.tasks_file.exists():
            return
        
        content = self.tasks_file.read_text(encoding="utf-8")
        self._tasks = self._parse_markdown(content)
    
    def _save_tasks(self) -> None:
        """保存任务列表到文件"""
        # 确保目录存在
        self.tasks_file.parent.mkdir(parents=True, exist_ok=True)
        
        # 生成 Markdown 内容
        content = self._generate_markdown()
        
        # 写入文件
        self.tasks_file.write_text(content, encoding="utf-8")
    
    def _parse_markdown(self, content: str) -> Dict[str, Task]:
        """
        解析 Markdown 格式的任务列表
        
        Args:
            content: Markdown 内容
        
        Returns:
            Dict[str, Task]: 任务字典 (task_id -> Task)
        """
        tasks = {}
        lines = content.split("\n")
        
        # 状态映射（反向）
        status_map = {
            "[ ]": TaskStatus.PENDING,
            "[-]": TaskStatus.IN_PROGRESS,
            "[x]": TaskStatus.COMPLETED,
            "[!]": TaskStatus.FAILED,
        }
        
        # 正则表达式匹配任务行
        # 格式: - [x] task_1: 任务描述
        task_pattern = re.compile(r"^-\s+\[(.)\]\s+(task_\d+):\s+(.+)$")
        
        # 正则表达式匹配元数据注释
        # 格式: <!-- task_id: task_1, created_at: 2024-01-01T10:00:00 -->
        metadata_pattern = re.compile(r"<!--\s+(.+?)\s+-->")
        
        current_metadata = {}
        
        for line in lines:
            line = line.strip()
            
            # 解析元数据注释
            metadata_match = metadata_pattern.match(line)
            if metadata_match:
                metadata_str = metadata_match.group(1)
                # 解析键值对
                for pair in metadata_str.split(","):
                    if ":" in pair:
                        key, value = pair.split(":", 1)
                        current_metadata[key.strip()] = value.strip()
                continue
            
            # 解析任务行
            task_match = task_pattern.match(line)
            if task_match:
                checkbox_char = task_match.group(1)
                task_id = task_match.group(2)
                description = task_match.group(3)
                
                # 确定状态
                checkbox = f"[{checkbox_char}]"
                status = status_map.get(checkbox, TaskStatus.PENDING)
                
                # 创建任务对象
                task = Task(
                    id=task_id,
                    description=description,
                    status=status,
                )
                
                # 应用元数据（如果有）
                if "created_at" in current_metadata:
                    try:
                        task.created_at = datetime.fromisoformat(current_metadata["created_at"])
                    except (ValueError, TypeError):
                        pass
                
                if "completed_at" in current_metadata:
                    try:
                        task.completed_at = datetime.fromisoformat(current_metadata["completed_at"])
                    except (ValueError, TypeError):
                        pass
                
                if "depends_on" in current_metadata:
                    task.depends_on = current_metadata["depends_on"]
                if "agent_type" in current_metadata:
                    task.agent_type = current_metadata["agent_type"]
                if "function_identifier" in current_metadata:
                    task.function_identifier = current_metadata["function_identifier"]
                if "task_group" in current_metadata:
                    task.task_group = current_metadata["task_group"]
                if "workflow_name" in current_metadata:
                    task.workflow_name = current_metadata["workflow_name"]
                if "workflow_execution_mode" in current_metadata:
                    task.workflow_execution_mode = current_metadata["workflow_execution_mode"]
                if "analysis_context" in current_metadata:
                    task.analysis_context = current_metadata["analysis_context"]
                
                tasks[task_id] = task
                
                # 清空元数据
                current_metadata = {}
        
        return tasks
    
    def _generate_markdown(self) -> str:
        """
        生成 Markdown 格式的任务列表
        
        Returns:
            str: Markdown 内容
        """
        lines = ["# 任务列表", ""]
        
        # 按任务 ID 排序
        sorted_tasks = sorted(self._tasks.values(), key=lambda t: self._extract_task_number(t.id))
        
        for task in sorted_tasks:
            # 添加元数据注释
            lines.append(task.to_metadata_comment())
            # 添加任务行
            lines.append(task.to_markdown_line())
            lines.append("")  # 空行
        
        # 添加统计信息
        stats = self.get_statistics()
        lines.append("---")
        lines.append("")
        lines.append(f"**总计**: {stats['total']} 个任务")
        lines.append(f"**待执行**: {stats['pending']} 个")
        lines.append(f"**执行中**: {stats['in_progress']} 个")
        lines.append(f"**已完成**: {stats['completed']} 个")
        lines.append(f"**失败**: {stats['failed']} 个")
        lines.append(f"**完成率**: {stats['completion_rate']}%")
        
        return "\n".join(lines)
    
    @staticmethod
    def _extract_task_number(task_id: str) -> int:
        """
        从任务 ID 中提取数字
        
        Args:
            task_id: 任务 ID (如 task_1, task_2)
        
        Returns:
            int: 任务编号
        """
        match = re.match(r"task_(\d+)", task_id)
        if match:
            return int(match.group(1))
        return 0


__all__ = [
    "TaskStatus",
    "Task",
    "TaskListManager",
]
