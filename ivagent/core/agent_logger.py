#!/usr/bin/env python3
"""
Agent 执行日志系统

扩展 LLM 日志系统，记录 Agent 层级关系和执行流程。
支持可视化展示 Agent 调用树和执行状态。
"""

import json
import sqlite3
import threading
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, asdict


class AgentStatus(str, Enum):
    """Agent 执行状态"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskType(str, Enum):
    """任务类型"""
    LLM_CALL = "llm_call"
    GET_SUMMARY = "get_summary"
    CREATE_SUBAGENT = "create_subagent"
    ANALYZE_CODE = "analyze_code"


@dataclass
class AgentTaskLog:
    """Agent 任务日志"""
    task_id: str
    agent_id: str
    task_type: str
    target: str  # 目标函数或操作对象
    status: str
    start_time: str
    end_time: Optional[str] = None
    result_summary: str = ""
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class AgentExecutionLog:
    """Agent 执行日志"""
    agent_id: str
    parent_id: Optional[str]
    agent_type: str  # DeepVulnAgent, FunctionSummaryAgent, etc.
    target_function: str
    call_stack: List[str]
    depth: int
    status: str
    start_time: str
    end_time: Optional[str] = None
    vulnerabilities_found: int = 0
    sub_agents_created: int = 0
    llm_calls: int = 0
    summary: str = ""
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class AgentLogStorage:
    """Agent 日志存储（SQLite）"""
    
    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_db()
    
    def _get_conn(self) -> sqlite3.Connection:
        """获取线程本地连接"""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn
    
    def _init_db(self):
        """初始化数据库表"""
        conn = self._get_conn()
        
        # Agent 执行日志表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_executions (
                id TEXT PRIMARY KEY,
                parent_id TEXT,
                agent_type TEXT NOT NULL,
                target_function TEXT NOT NULL,
                call_stack TEXT NOT NULL,
                depth INTEGER NOT NULL,
                status TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                vulnerabilities_found INTEGER DEFAULT 0,
                sub_agents_created INTEGER DEFAULT 0,
                llm_calls INTEGER DEFAULT 0,
                summary TEXT,
                error_message TEXT,
                metadata TEXT NOT NULL
            )
        """)
        
        # Agent 任务日志表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_tasks (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                task_type TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                result_summary TEXT,
                error_message TEXT,
                metadata TEXT NOT NULL
            )
        """)
        
        # 创建索引
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_parent ON agent_executions(parent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_status ON agent_executions(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_agent_start_time ON agent_executions(start_time)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_task_agent ON agent_tasks(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_task_type ON agent_tasks(task_type)")
        
        conn.commit()
    
    def save_execution(self, log: AgentExecutionLog) -> str:
        """保存 Agent 执行日志"""
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO agent_executions 
            (id, parent_id, agent_type, target_function, call_stack, depth, status,
             start_time, end_time, vulnerabilities_found, sub_agents_created, llm_calls,
             summary, error_message, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log.agent_id,
            log.parent_id,
            log.agent_type,
            log.target_function,
            json.dumps(log.call_stack, ensure_ascii=False),
            log.depth,
            log.status,
            log.start_time,
            log.end_time,
            log.vulnerabilities_found,
            log.sub_agents_created,
            log.llm_calls,
            log.summary,
            log.error_message,
            json.dumps(log.metadata, ensure_ascii=False),
        ))
        conn.commit()
        return log.agent_id
    
    def update_execution(self, agent_id: str, **kwargs) -> bool:
        """更新 Agent 执行日志"""
        conn = self._get_conn()
        allowed_fields = [
            'status', 'end_time', 'vulnerabilities_found', 'sub_agents_created',
            'llm_calls', 'summary', 'error_message'
        ]
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not updates:
            return False
        
        set_clause = ', '.join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values())
        values.append(agent_id)
        
        conn.execute(f"UPDATE agent_executions SET {set_clause} WHERE id = ?", values)
        conn.commit()
        return True
    
    def save_task(self, log: AgentTaskLog) -> str:
        """保存任务日志"""
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO agent_tasks 
            (id, agent_id, task_type, target, status, start_time, end_time,
             result_summary, error_message, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log.task_id,
            log.agent_id,
            log.task_type,
            log.target,
            log.status,
            log.start_time,
            log.end_time,
            log.result_summary,
            log.error_message,
            json.dumps(log.metadata, ensure_ascii=False),
        ))
        conn.commit()
        return log.task_id
    
    def get_execution(self, agent_id: str) -> Optional[AgentExecutionLog]:
        """获取单个 Agent 执行日志"""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM agent_executions WHERE id = ?", (agent_id,)
        ).fetchone()
        
        if not row:
            return None
        
        return self._row_to_execution(row)
    
    def get_executions_by_parent(self, parent_id: Optional[str]) -> List[AgentExecutionLog]:
        """获取子 Agent 列表"""
        conn = self._get_conn()
        if parent_id is None:
            rows = conn.execute(
                "SELECT * FROM agent_executions WHERE parent_id IS NULL ORDER BY start_time"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM agent_executions WHERE parent_id = ? ORDER BY start_time",
                (parent_id,)
            ).fetchall()
        
        return [self._row_to_execution(row) for row in rows]
    
    def get_execution_tree(self, root_id: str) -> Dict[str, Any]:
        """获取 Agent 执行树"""
        root = self.get_execution(root_id)
        if not root:
            return {}
        
        def build_tree(agent_id: str) -> Dict[str, Any]:
            agent = self.get_execution(agent_id)
            if not agent:
                return {}
            
            children = self.get_executions_by_parent(agent_id)
            return {
                **agent.__dict__,
                "children": [build_tree(child.agent_id) for child in children]
            }
        
        return build_tree(root_id)
    
    def get_tasks_by_agent(self, agent_id: str) -> List[AgentTaskLog]:
        """获取 Agent 的任务列表"""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM agent_tasks WHERE agent_id = ? ORDER BY start_time",
            (agent_id,)
        ).fetchall()
        
        return [self._row_to_task(row) for row in rows]
    
    def query_executions(
        self,
        agent_type: Optional[str] = None,
        status: Optional[str] = None,
        target_function: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AgentExecutionLog]:
        """查询 Agent 执行日志"""
        conn = self._get_conn()
        
        conditions = []
        params = []
        
        if agent_type:
            conditions.append("agent_type = ?")
            params.append(agent_type)
        if status:
            conditions.append("status = ?")
            params.append(status)
        if target_function:
            conditions.append("target_function LIKE ?")
            params.append(f"%{target_function}%")
        if start_time:
            conditions.append("start_time >= ?")
            params.append(start_time)
        if end_time:
            conditions.append("start_time <= ?")
            params.append(end_time)
        
        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        
        rows = conn.execute(
            f"SELECT * FROM agent_executions {where_clause} ORDER BY start_time DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()
        
        return [self._row_to_execution(row) for row in rows]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        conn = self._get_conn()
        
        total = conn.execute("SELECT COUNT(*) FROM agent_executions").fetchone()[0]
        completed = conn.execute(
            "SELECT COUNT(*) FROM agent_executions WHERE status = 'completed'"
        ).fetchone()[0]
        failed = conn.execute(
            "SELECT COUNT(*) FROM agent_executions WHERE status = 'failed'"
        ).fetchone()[0]
        
        total_vulns = conn.execute(
            "SELECT SUM(vulnerabilities_found) FROM agent_executions"
        ).fetchone()[0] or 0
        
        agent_type_dist = conn.execute("""
            SELECT agent_type, COUNT(*) as count 
            FROM agent_executions 
            GROUP BY agent_type
        """).fetchall()
        
        return {
            "total_agents": total,
            "completed": completed,
            "failed": failed,
            "total_vulnerabilities": total_vulns,
            "agent_type_distribution": {row[0]: row[1] for row in agent_type_dist},
        }
    
    def _row_to_execution(self, row: sqlite3.Row) -> AgentExecutionLog:
        """将数据库行转换为 AgentExecutionLog"""
        return AgentExecutionLog(
            agent_id=row['id'],
            parent_id=row['parent_id'],
            agent_type=row['agent_type'],
            target_function=row['target_function'],
            call_stack=json.loads(row['call_stack']),
            depth=row['depth'],
            status=row['status'],
            start_time=row['start_time'],
            end_time=row['end_time'],
            vulnerabilities_found=row['vulnerabilities_found'],
            sub_agents_created=row['sub_agents_created'],
            llm_calls=row['llm_calls'],
            summary=row['summary'] or "",
            error_message=row['error_message'],
            metadata=json.loads(row['metadata']),
        )
    
    def _row_to_task(self, row: sqlite3.Row) -> AgentTaskLog:
        """将数据库行转换为 AgentTaskLog"""
        return AgentTaskLog(
            task_id=row['id'],
            agent_id=row['agent_id'],
            task_type=row['task_type'],
            target=row['target'],
            status=row['status'],
            start_time=row['start_time'],
            end_time=row['end_time'],
            result_summary=row['result_summary'] or "",
            error_message=row['error_message'],
            metadata=json.loads(row['metadata']),
        )


class AgentLogManager:
    """Agent 日志管理器（单例）"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        if self._initialized:
            return
        
        self._initialized = True
        
        if db_path is None:
            base_dir = Path.home() / ".ivagent" / "logs"
            db_path = base_dir / "agent_logs.db"
        
        self.storage = AgentLogStorage(db_path)
    
    def log_execution_start(
        self,
        agent_id: str,
        agent_type: str,
        target_function: str,
        parent_id: Optional[str] = None,
        call_stack: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentExecutionLog:
        """记录 Agent 执行开始"""
        log = AgentExecutionLog(
            agent_id=agent_id,
            parent_id=parent_id,
            agent_type=agent_type,
            target_function=target_function,
            call_stack=call_stack or [],
            depth=len(call_stack) if call_stack else 0,
            status=AgentStatus.RUNNING,
            start_time=datetime.now().isoformat(),
            metadata=metadata or {},
        )
        self.storage.save_execution(log)
        return log
    
    def log_execution_end(
        self,
        agent_id: str,
        status: AgentStatus,
        vulnerabilities_found: int = 0,
        sub_agents_created: int = 0,
        llm_calls: int = 0,
        summary: str = "",
        error_message: Optional[str] = None,
    ):
        """记录 Agent 执行结束"""
        self.storage.update_execution(
            agent_id=agent_id,
            status=status.value,
            end_time=datetime.now().isoformat(),
            vulnerabilities_found=vulnerabilities_found,
            sub_agents_created=sub_agents_created,
            llm_calls=llm_calls,
            summary=summary,
            error_message=error_message,
        )
    
    def log_task_start(
        self,
        agent_id: str,
        task_type: str,
        target: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentTaskLog:
        """记录任务开始"""
        log = AgentTaskLog(
            task_id=str(uuid.uuid4()),
            agent_id=agent_id,
            task_type=task_type,
            target=target,
            status=AgentStatus.RUNNING,
            start_time=datetime.now().isoformat(),
            metadata=metadata or {},
        )
        self.storage.save_task(log)
        return log
    
    def log_task_end(
        self,
        task_id: str,
        status: AgentStatus,
        result_summary: str = "",
        error_message: Optional[str] = None,
    ):
        """记录任务结束"""
        conn = self.storage._get_conn()
        conn.execute("""
            UPDATE agent_tasks 
            SET status = ?, end_time = ?, result_summary = ?, error_message = ?
            WHERE id = ?
        """, (
            status.value,
            datetime.now().isoformat(),
            result_summary,
            error_message,
            task_id,
        ))
        conn.commit()
    
    def get_execution(self, agent_id: str) -> Optional[AgentExecutionLog]:
        """获取 Agent 执行日志"""
        return self.storage.get_execution(agent_id)
    
    def get_execution_tree(self, root_id: str) -> Dict[str, Any]:
        """获取执行树"""
        return self.storage.get_execution_tree(root_id)
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return self.storage.get_stats()


# 全局实例
def get_agent_log_manager(db_path: Optional[Union[str, Path]] = None) -> AgentLogManager:
    """获取 Agent 日志管理器实例"""
    return AgentLogManager(db_path)
