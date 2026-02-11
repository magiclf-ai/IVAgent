#!/usr/bin/env python3
"""
TaskManager - 任务管理核心逻辑

管理任务生命周期，维护状态转换约束，提供任务查询和统计接口。
"""

from typing import List, Optional, Dict, Any
from ..models.task import Task, TaskStatus, TaskStatusTransitionError


class TaskManager:
    """
    任务管理器

    核心职责:
    - 管理任务的生命周期
    - 维护任务状态转换约束（确保同一时间只有一个 in_progress 任务）
    - 提供任务查询和统计接口
    - 支持任务树结构（通过 parent_id）

    使用方式:
    >>> tm = TaskManager()
    >>> task = tm.create_task("分析入口函数")
    >>> tm.update_task_status(task.id, TaskStatus.IN_PROGRESS)
    >>> current = tm.get_current_task()
    """

    def __init__(self):
        """初始化任务管理器"""
        self._tasks: Dict[str, Task] = {}  # id -> Task
        self._next_id = 1  # 用于生成简单任务ID的计数器

    def create_task(
        self,
        description: str,
        parent_id: Optional[str] = None,
    ) -> Task:
        """
        创建新任务

        Args:
            description: 任务描述
            parent_id: 父任务 ID（可选，用于任务树）

        Returns:
            Task: 创建的任务对象
        """
        # 生成简单的任务ID：task_1, task_2, ...
        task_id = f"task_{self._next_id}"
        self._next_id += 1

        task = Task(
            id=task_id,
            description=description,
            status=TaskStatus.PENDING,
            parent_id=parent_id,
        )

        self._tasks[task.id] = task
        return task

    def update_task_status(
        self,
        task_id: str,
        status: TaskStatus,
        result: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> Task:
        """
        更新任务状态

        自动维护 in_progress 约束：当将一个任务设为 in_progress 时，
        自动将其他 in_progress 任务退回 pending。

        Args:
            task_id: 任务 ID
            status: 新状态
            result: 任务结果（可选）
            error_message: 错误信息（可选）

        Returns:
            Task: 更新后的任务对象

        Raises:
            ValueError: 任务不存在
            TaskStatusTransitionError: 非法状态转换
        """
        if task_id not in self._tasks:
            raise ValueError(f"Task not found: {task_id}")

        task = self._tasks[task_id]

        # 尝试状态转换
        try:
            updated_task = task.transition_to(status)
        except TaskStatusTransitionError as e:
            raise TaskStatusTransitionError(f"Task {task_id}: {e}")

        # 更新可选字段
        if result is not None:
            updated_task.result = result
        if error_message is not None:
            updated_task.error_message = error_message

        # 维护 in_progress 约束
        if status == TaskStatus.IN_PROGRESS:
            # 将其他 in_progress 任务退回 pending
            for tid, t in self._tasks.items():
                if tid != task_id and t.status == TaskStatus.IN_PROGRESS:
                    self._tasks[tid] = t.transition_to(TaskStatus.PENDING)

        # 更新任务
        self._tasks[task_id] = updated_task
        return updated_task

    def get_task(self, task_id: str) -> Optional[Task]:
        """
        根据 ID 获取任务

        Args:
            task_id: 任务 ID

        Returns:
            Optional[Task]: 任务对象，不存在返回 None
        """
        return self._tasks.get(task_id)

    def get_current_task(self) -> Optional[Task]:
        """
        获取当前正在执行的任务

        Returns:
            Optional[Task]: 当前 in_progress 的任务，无则返回 None
        """
        for task in self._tasks.values():
            if task.status == TaskStatus.IN_PROGRESS:
                return task
        return None

    def list_tasks(
        self,
        status: Optional[TaskStatus] = None,
        parent_id: Optional[str] = None,
    ) -> List[Task]:
        """
        获取任务列表

        Args:
            status: 按状态过滤（可选）
            parent_id: 按父任务 ID 过滤（可选）

        Returns:
            List[Task]: 任务列表
        """
        tasks = list(self._tasks.values())

        # 状态过滤
        if status is not None:
            tasks = [t for t in tasks if t.status == status]

        # 父任务过滤
        if parent_id is not None:
            tasks = [t for t in tasks if t.parent_id == parent_id]

        # 按创建时间排序
        tasks.sort(key=lambda t: t.created_at)
        return tasks

    def get_progress_summary(self) -> Dict[str, Any]:
        """
        获取进度统计信息

        Returns:
            Dict[str, Any]: 包含任务统计信息的字典
        """
        total = len(self._tasks)
        pending = len([t for t in self._tasks.values() if t.status == TaskStatus.PENDING])
        in_progress = len([t for t in self._tasks.values() if t.status == TaskStatus.IN_PROGRESS])
        completed = len([t for t in self._tasks.values() if t.status == TaskStatus.COMPLETED])
        failed = len([t for t in self._tasks.values() if t.status == TaskStatus.FAILED])

        # 计算完成百分比
        completion_rate = (completed / total * 100) if total > 0 else 0

        # 获取当前任务
        current_task = self.get_current_task()
        current_task_info = None
        if current_task:
            current_task_info = {
                "id": current_task.id,
                "description": current_task.description,
                "status": current_task.status.value,
            }

        return {
            "total": total,
            "pending": pending,
            "in_progress": in_progress,
            "completed": completed,
            "failed": failed,
            "completion_rate": round(completion_rate, 2),
            "current_task": current_task_info,
        }

    def delete_task(self, task_id: str) -> bool:
        """
        删除任务

        Args:
            task_id: 任务 ID

        Returns:
            bool: 是否删除成功
        """
        if task_id not in self._tasks:
            return False

        # 删除子任务（递归）
        child_tasks = self.list_tasks(parent_id=task_id)
        for child in child_tasks:
            self.delete_task(child.id)

        # 删除任务
        del self._tasks[task_id]
        return True

    def clear_all(self) -> None:
        """清空所有任务"""
        self._tasks.clear()

    def get_task_tree(self) -> List[Dict[str, Any]]:
        """
        获取任务树结构（仅顶层任务）

        Returns:
            List[Dict]: 任务树列表，包含子任务
        """
        # 获取顶层任务（没有 parent_id）
        top_level_tasks = [t for t in self._tasks.values() if t.parent_id is None]

        # 按创建时间排序
        top_level_tasks.sort(key=lambda t: t.created_at)

        # 构建树结构
        def build_tree(task: Task) -> Dict[str, Any]:
            children = self.list_tasks(parent_id=task.id)
            children.sort(key=lambda t: t.created_at)

            node = task.to_summary_dict()
            if children:
                node["children"] = [build_tree(child) for child in children]

            return node

        return [build_tree(task) for task in top_level_tasks]

    def __len__(self) -> int:
        """获取任务总数"""
        return len(self._tasks)

    def __contains__(self, task_id: str) -> bool:
        """检查任务是否存在"""
        return task_id in self._tasks
