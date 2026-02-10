#!/usr/bin/env python3
"""
LLM 交互日志管理系统

提供完整的 LLM 调用日志记录、存储、查询和可视化功能
支持 SQLite 数据库存储和 JSON 文件存储两种模式
"""

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, asdict
from contextlib import contextmanager
import asyncio
from concurrent.futures import ThreadPoolExecutor


class LogStorageType(Enum):
    """日志存储类型"""
    SQLITE = "sqlite"
    JSON = "json"
    MEMORY = "memory"


class LogStatus(str, Enum):
    """日志交互状态"""
    PENDING = "pending"      # 等待中
    RUNNING = "running"      # 进行中
    COMPLETED = "completed"  # 成功完成
    FAILED = "failed"        # 失败


@dataclass
class LLMLogEntry:
    """LLM 交互日志条目"""
    id: str
    timestamp: str
    session_id: str
    agent_id: Optional[str]  # 发起日志的 Agent ID
    call_type: str  # structured_call, chat, etc.
    model: str
    messages: List[Dict[str, Any]]
    system_prompt: Optional[str]
    output_schema: Optional[str]
    response: Optional[Dict[str, Any]]
    error: Optional[str]
    latency_ms: float
    retry_count: int
    status: str  # pending, running, completed, failed
    success: bool  # 保留兼容
    metadata: Dict[str, Any]
    
    @classmethod
    def create(
        cls,
        call_type: str,
        model: str,
        messages: List[Dict[str, Any]],
        system_prompt: Optional[str] = None,
        output_schema: Optional[str] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "LLMLogEntry":
        """创建新的日志条目"""
        return cls(
            id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            session_id=session_id or str(uuid.uuid4()),
            agent_id=agent_id,
            call_type=call_type,
            model=model,
            messages=messages,
            system_prompt=system_prompt,
            output_schema=output_schema,
            response=None,
            error=None,
            latency_ms=0.0,
            retry_count=0,
            status=LogStatus.PENDING.value,
            success=False,
            metadata=metadata or {}
        )


class BaseLogStorage:
    """日志存储基类"""
    
    def save_entry(self, entry: LLMLogEntry) -> str:
        """保存日志条目，返回条目 ID"""
        raise NotImplementedError
    
    def get_entry(self, entry_id: str) -> Optional[LLMLogEntry]:
        """获取单个日志条目"""
        raise NotImplementedError
    
    def query_entries(
        self,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        call_type: Optional[str] = None,
        model: Optional[str] = None,
        status: Optional[str] = None,
        success: Optional[bool] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        search_keyword: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[LLMLogEntry]:
        """查询日志条目"""
        raise NotImplementedError
    
    def get_sessions(self) -> List[Dict[str, Any]]:
        """获取所有会话列表"""
        raise NotImplementedError
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        raise NotImplementedError
    
    def delete_old_entries(self, days: int) -> int:
        """删除指定天数前的日志，返回删除数量"""
        raise NotImplementedError


class SQLiteLogStorage(BaseLogStorage):
    """SQLite 日志存储"""
    
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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS llm_logs (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                session_id TEXT NOT NULL,
                agent_id TEXT,
                call_type TEXT NOT NULL,
                model TEXT NOT NULL,
                messages TEXT NOT NULL,
                system_prompt TEXT,
                output_schema TEXT,
                response TEXT,
                error TEXT,
                latency_ms REAL NOT NULL,
                retry_count INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                success INTEGER NOT NULL,
                metadata TEXT NOT NULL
            )
        """)
        
        # 检查并添加缺失的列（向后兼容）
        self._migrate_db(conn)
        
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON llm_logs(timestamp)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_session ON llm_logs(session_id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_agent ON llm_logs(agent_id)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_call_type ON llm_logs(call_type)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_status ON llm_logs(status)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_success ON llm_logs(success)
        """)
        conn.commit()
    
    def _migrate_db(self, conn: sqlite3.Connection):
        """数据库迁移：添加缺失的列"""
        # 获取当前表的列信息
        cursor = conn.execute("PRAGMA table_info(llm_logs)")
        existing_columns = {row[1] for row in cursor.fetchall()}
        
        # 定义所有需要的列
        required_columns = {
            'id': 'TEXT PRIMARY KEY',
            'timestamp': 'TEXT NOT NULL',
            'session_id': 'TEXT NOT NULL',
            'agent_id': 'TEXT',
            'call_type': 'TEXT NOT NULL',
            'model': 'TEXT NOT NULL',
            'messages': 'TEXT NOT NULL',
            'system_prompt': 'TEXT',
            'output_schema': 'TEXT',
            'response': 'TEXT',
            'error': 'TEXT',
            'latency_ms': 'REAL NOT NULL',
            'retry_count': 'INTEGER NOT NULL',
            'status': "TEXT NOT NULL DEFAULT 'pending'",
            'success': 'INTEGER NOT NULL',
            'metadata': 'TEXT NOT NULL'
        }
        
        # 添加缺失的列
        for col_name, col_type in required_columns.items():
            if col_name not in existing_columns:
                try:
                    conn.execute(f"ALTER TABLE llm_logs ADD COLUMN {col_name} {col_type}")
                except sqlite3.OperationalError as e:
                    # 列可能已存在或表结构问题，忽略错误
                    pass
    
    def save_entry(self, entry: LLMLogEntry) -> str:
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO llm_logs 
            (id, timestamp, session_id, agent_id, call_type, model, messages, system_prompt,
             output_schema, response, error, latency_ms, retry_count, status, success, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            entry.id,
            entry.timestamp,
            entry.session_id,
            entry.agent_id,
            entry.call_type,
            entry.model,
            json.dumps(entry.messages, ensure_ascii=False),
            entry.system_prompt,
            entry.output_schema,
            json.dumps(entry.response, ensure_ascii=False) if entry.response else None,
            entry.error,
            entry.latency_ms,
            entry.retry_count,
            entry.status,
            1 if entry.success else 0,
            json.dumps(entry.metadata, ensure_ascii=False)
        ))
        conn.commit()
        return entry.id
    
    def update_entry(self, entry_id: str, **kwargs) -> bool:
        """更新日志条目"""
        conn = self._get_conn()
        allowed_fields = ['response', 'error', 'latency_ms', 'retry_count', 'status', 'success']
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not updates:
            return False
        
        set_clause = ', '.join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values())
        
        # JSON 序列化字典字段
        if 'response' in updates and updates['response'] is not None:
            values[list(updates.keys()).index('response')] = json.dumps(updates['response'], ensure_ascii=False)
        
        values.append(entry_id)
        
        conn.execute(f"UPDATE llm_logs SET {set_clause} WHERE id = ?", values)
        conn.commit()
        return True
    
    def get_entry(self, entry_id: str) -> Optional[LLMLogEntry]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM llm_logs WHERE id = ?", (entry_id,)
        ).fetchone()
        
        if not row:
            return None
        
        return self._row_to_entry(row)
    
    def query_entries(
        self,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        call_type: Optional[str] = None,
        model: Optional[str] = None,
        status: Optional[str] = None,
        success: Optional[bool] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        search_keyword: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[LLMLogEntry]:
        conn = self._get_conn()
        
        conditions = []
        params = []
        
        if session_id:
            conditions.append("session_id = ?")
            params.append(session_id)
        if agent_id:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        if call_type:
            conditions.append("call_type = ?")
            params.append(call_type)
        if model:
            conditions.append("model = ?")
            params.append(model)
        if status:
            conditions.append("status = ?")
            params.append(status)
        if success is not None:
            conditions.append("success = ?")
            params.append(1 if success else 0)
        if start_time:
            conditions.append("timestamp >= ?")
            params.append(start_time)
        if end_time:
            conditions.append("timestamp <= ?")
            params.append(end_time)
        
        # 搜索关键词：匹配 messages、response、error、system_prompt 等字段
        if search_keyword:
            keyword_lower = search_keyword.lower()
            conditions.append("""
                (
                    LOWER(messages) LIKE ? OR 
                    LOWER(response) LIKE ? OR 
                    LOWER(COALESCE(error, '')) LIKE ? OR 
                    LOWER(COALESCE(system_prompt, '')) LIKE ?
                )
            """)
            like_pattern = f"%{keyword_lower}%"
            params.extend([like_pattern, like_pattern, like_pattern, like_pattern])
        
        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        
        rows = conn.execute(
            f"SELECT * FROM llm_logs {where_clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()
        
        return [self._row_to_entry(row) for row in rows]
    
    def get_sessions(self) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT 
                session_id,
                MIN(timestamp) as start_time,
                MAX(timestamp) as end_time,
                COUNT(*) as total_calls,
                SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as success_calls,
                SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as failed_calls
            FROM llm_logs
            GROUP BY session_id
            ORDER BY start_time DESC
        """).fetchall()
        
        return [dict(row) for row in rows]
    
    def get_stats(self) -> Dict[str, Any]:
        conn = self._get_conn()
        
        total = conn.execute("SELECT COUNT(*) FROM llm_logs").fetchone()[0]
        success = conn.execute("SELECT COUNT(*) FROM llm_logs WHERE success = 1").fetchone()[0]
        failed = total - success
        
        avg_latency = conn.execute("SELECT AVG(latency_ms) FROM llm_logs").fetchone()[0] or 0
        
        model_dist = conn.execute("""
            SELECT model, COUNT(*) as count 
            FROM llm_logs 
            GROUP BY model
        """).fetchall()
        
        call_type_dist = conn.execute("""
            SELECT call_type, COUNT(*) as count 
            FROM llm_logs 
            GROUP BY call_type
        """).fetchall()
        
        return {
            "total_calls": total,
            "success_calls": success,
            "failed_calls": failed,
            "success_rate": success / total if total > 0 else 0,
            "avg_latency_ms": avg_latency,
            "model_distribution": {row[0]: row[1] for row in model_dist},
            "call_type_distribution": {row[0]: row[1] for row in call_type_dist}
        }
    
    def delete_old_entries(self, days: int) -> int:
        conn = self._get_conn()
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        cursor = conn.execute("DELETE FROM llm_logs WHERE timestamp < ?", (cutoff,))
        conn.commit()
        return cursor.rowcount
    
    def _row_to_entry(self, row: sqlite3.Row) -> LLMLogEntry:
        """将数据库行转换为日志条目"""
        return LLMLogEntry(
            id=row['id'],
            timestamp=row['timestamp'],
            session_id=row['session_id'],
            agent_id=row['agent_id'],
            call_type=row['call_type'],
            model=row['model'],
            messages=json.loads(row['messages']),
            system_prompt=row['system_prompt'],
            output_schema=row['output_schema'],
            response=json.loads(row['response']) if row['response'] else None,
            error=row['error'],
            latency_ms=row['latency_ms'],
            retry_count=row['retry_count'],
            status=row['status'] or LogStatus.PENDING.value,
            success=bool(row['success']),
            metadata=json.loads(row['metadata'])
        )


class JSONLogStorage(BaseLogStorage):
    """JSON 文件日志存储"""
    
    def __init__(self, log_dir: Union[str, Path]):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.log_dir / "index.json"
        self._lock = threading.Lock()
        self._ensure_index()
    
    def _ensure_index(self):
        """确保索引文件存在"""
        if not self.index_file.exists():
            self._save_index({"entries": [], "sessions": {}})
    
    def _load_index(self) -> Dict:
        """加载索引"""
        with open(self.index_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _save_index(self, index: Dict):
        """保存索引"""
        with self._lock:
            with open(self.index_file, 'w', encoding='utf-8') as f:
                json.dump(index, f, ensure_ascii=False, indent=2)
    
    def _entry_file_path(self, entry_id: str) -> Path:
        """获取条目文件路径"""
        # 按日期分目录
        date_prefix = datetime.now().strftime("%Y%m")
        subdir = self.log_dir / date_prefix
        subdir.mkdir(exist_ok=True)
        return subdir / f"{entry_id}.json"

    def save_entry(self, entry: LLMLogEntry) -> str:
        entry_dict = asdict(entry)
        entry_dict['success'] = entry.success
        entry_dict['status'] = entry.status
        entry_dict['agent_id'] = entry.agent_id
        
        # 保存条目文件
        entry_file = self._entry_file_path(entry.id)
        with self._lock:
            with open(entry_file, 'w', encoding='utf-8') as f:
                json.dump(entry_dict, f, ensure_ascii=False, indent=2)
        
        # 更新索引
        index = self._load_index()
        index["entries"].append({
            "id": entry.id,
            "timestamp": entry.timestamp,
            "session_id": entry.session_id,
            "agent_id": entry.agent_id,
            "call_type": entry.call_type,
            "model": entry.model,
            "status": entry.status,
            "success": entry.success,
            "file": str(entry_file.relative_to(self.log_dir))
        })
        
        # 更新会话信息
        if entry.session_id not in index["sessions"]:
            index["sessions"][entry.session_id] = {
                "start_time": entry.timestamp,
                "call_count": 0,
                "success_count": 0
            }
        index["sessions"][entry.session_id]["call_count"] += 1
        if entry.success:
            index["sessions"][entry.session_id]["success_count"] += 1
        
        self._save_index(index)
        return entry.id
    
    def update_entry(self, entry_id: str, **kwargs) -> bool:
        """更新日志条目"""
        index = self._load_index()
        entry_info = next((e for e in index["entries"] if e["id"] == entry_id), None)
        if not entry_info:
            return False
        
        entry_file = self.log_dir / entry_info["file"]
        if not entry_file.exists():
            return False
        
        with open(entry_file, 'r', encoding='utf-8') as f:
            entry_dict = json.load(f)
        
        allowed_fields = ['response', 'error', 'latency_ms', 'retry_count', 'status', 'success']
        for key, value in kwargs.items():
            if key in allowed_fields:
                entry_dict[key] = value
        
        with self._lock:
            with open(entry_file, 'w', encoding='utf-8') as f:
                json.dump(entry_dict, f, ensure_ascii=False, indent=2)
        
        # 更新索引中的状态
        entry_info["success"] = entry_dict.get("success", False)
        entry_info["status"] = entry_dict.get("status", LogStatus.PENDING.value)
        self._save_index(index)
        
        return True
    
    def get_entry(self, entry_id: str) -> Optional[LLMLogEntry]:
        index = self._load_index()
        entry_info = next((e for e in index["entries"] if e["id"] == entry_id), None)
        if not entry_info:
            return None
        
        entry_file = self.log_dir / entry_info["file"]
        if not entry_file.exists():
            return None
        
        with open(entry_file, 'r', encoding='utf-8') as f:
            entry_dict = json.load(f)
        
        return LLMLogEntry(**entry_dict)
    
    def query_entries(
        self,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        call_type: Optional[str] = None,
        model: Optional[str] = None,
        status: Optional[str] = None,
        success: Optional[bool] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        search_keyword: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[LLMLogEntry]:
        index = self._load_index()
        entries = index["entries"]
        
        # 过滤
        if session_id:
            entries = [e for e in entries if e["session_id"] == session_id]
        if agent_id:
            entries = [e for e in entries if e.get("agent_id") == agent_id]
        if call_type:
            entries = [e for e in entries if e["call_type"] == call_type]
        if model:
            entries = [e for e in entries if e["model"] == model]
        if status:
            entries = [e for e in entries if e.get("status") == status]
        if success is not None:
            entries = [e for e in entries if e["success"] == success]
        if start_time:
            entries = [e for e in entries if e["timestamp"] >= start_time]
        if end_time:
            entries = [e for e in entries if e["timestamp"] <= end_time]
        
        # 搜索关键词：在加载完整条目后匹配内容
        if search_keyword:
            keyword_lower = search_keyword.lower()
            filtered_entries = []
            for entry_info in entries:
                entry = self.get_entry(entry_info["id"])
                if entry and self._entry_matches_keyword(entry, keyword_lower):
                    filtered_entries.append(entry_info)
            entries = filtered_entries
        
        # 排序和分页
        entries.sort(key=lambda x: x["timestamp"], reverse=True)
        entries = entries[offset:offset + limit]
        
        result = []
        for entry_info in entries:
            entry = self.get_entry(entry_info["id"])
            if entry:
                result.append(entry)
        
        return result
    
    def _entry_matches_keyword(self, entry: LLMLogEntry, keyword: str) -> bool:
        """检查日志条目是否匹配搜索关键词"""
        import json
        
        # 搜索各个字段
        fields_to_search = [
            json.dumps(entry.messages) if entry.messages else "",
            json.dumps(entry.response) if entry.response else "",
            entry.error or "",
            entry.system_prompt or "",
            entry.call_type or "",
            entry.model or "",
        ]
        
        return any(keyword in field.lower() for field in fields_to_search)
    
    def get_sessions(self) -> List[Dict[str, Any]]:
        index = self._load_index()
        sessions = []
        for session_id, info in index["sessions"].items():
            sessions.append({
                "session_id": session_id,
                "start_time": info["start_time"],
                "total_calls": info["call_count"],
                "success_calls": info["success_count"],
                "failed_calls": info["call_count"] - info["success_count"]
            })
        sessions.sort(key=lambda x: x["start_time"], reverse=True)
        return sessions
    
    def get_stats(self) -> Dict[str, Any]:
        index = self._load_index()
        entries = index["entries"]
        
        total = len(entries)
        success = sum(1 for e in entries if e["success"])
        
        model_dist = {}
        call_type_dist = {}
        for e in entries:
            model_dist[e["model"]] = model_dist.get(e["model"], 0) + 1
            call_type_dist[e["call_type"]] = call_type_dist.get(e["call_type"], 0) + 1
        
        return {
            "total_calls": total,
            "success_calls": success,
            "failed_calls": total - success,
            "success_rate": success / total if total > 0 else 0,
            "avg_latency_ms": 0,  # JSON 模式需要额外计算
            "model_distribution": model_dist,
            "call_type_distribution": call_type_dist
        }
    
    def delete_old_entries(self, days: int) -> int:
        # JSON 模式下实现较复杂，暂不实现
        return 0


class MemoryLogStorage(BaseLogStorage):
    """内存日志存储（用于测试）"""
    
    def __init__(self):
        self._entries: Dict[str, LLMLogEntry] = {}
        self._lock = threading.Lock()
    
    def save_entry(self, entry: LLMLogEntry) -> str:
        with self._lock:
            self._entries[entry.id] = entry
        return entry.id
    
    def update_entry(self, entry_id: str, **kwargs) -> bool:
        with self._lock:
            if entry_id not in self._entries:
                return False
            entry = self._entries[entry_id]
            for key, value in kwargs.items():
                if hasattr(entry, key):
                    setattr(entry, key, value)
        return True
    
    def get_entry(self, entry_id: str) -> Optional[LLMLogEntry]:
        return self._entries.get(entry_id)
    
    def query_entries(
        self,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        call_type: Optional[str] = None,
        model: Optional[str] = None,
        status: Optional[str] = None,
        success: Optional[bool] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        search_keyword: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[LLMLogEntry]:
        import json
        
        entries = list(self._entries.values())
        
        if session_id:
            entries = [e for e in entries if e.session_id == session_id]
        if agent_id:
            entries = [e for e in entries if e.agent_id == agent_id]
        if call_type:
            entries = [e for e in entries if e.call_type == call_type]
        if model:
            entries = [e for e in entries if e.model == model]
        if status:
            entries = [e for e in entries if e.status == status]
        if success is not None:
            entries = [e for e in entries if e.success == success]
        if start_time:
            entries = [e for e in entries if e.timestamp >= start_time]
        if end_time:
            entries = [e for e in entries if e.timestamp <= end_time]
        
        # 搜索关键词
        if search_keyword:
            keyword_lower = search_keyword.lower()
            entries = [e for e in entries if self._entry_matches_keyword(e, keyword_lower)]
        
        entries.sort(key=lambda x: x.timestamp, reverse=True)
        return entries[offset:offset + limit]
    
    def _entry_matches_keyword(self, entry: LLMLogEntry, keyword: str) -> bool:
        """检查日志条目是否匹配搜索关键词"""
        import json
        
        fields_to_search = [
            json.dumps(entry.messages) if entry.messages else "",
            json.dumps(entry.response) if entry.response else "",
            entry.error or "",
            entry.system_prompt or "",
            entry.call_type or "",
            entry.model or "",
        ]
        
        return any(keyword in field.lower() for field in fields_to_search)
    
    def get_sessions(self) -> List[Dict[str, Any]]:
        sessions = {}
        for entry in self._entries.values():
            if entry.session_id not in sessions:
                sessions[entry.session_id] = {
                    "session_id": entry.session_id,
                    "start_time": entry.timestamp,
                    "total_calls": 0,
                    "success_calls": 0,
                    "failed_calls": 0
                }
            sessions[entry.session_id]["total_calls"] += 1
            if entry.success:
                sessions[entry.session_id]["success_calls"] += 1
            else:
                sessions[entry.session_id]["failed_calls"] += 1
        
        return list(sessions.values())
    
    def get_stats(self) -> Dict[str, Any]:
        total = len(self._entries)
        success = sum(1 for e in self._entries.values() if e.success)
        
        model_dist = {}
        call_type_dist = {}
        for e in self._entries.values():
            model_dist[e.model] = model_dist.get(e.model, 0) + 1
            call_type_dist[e.call_type] = call_type_dist.get(e.call_type, 0) + 1
        
        return {
            "total_calls": total,
            "success_calls": success,
            "failed_calls": total - success,
            "success_rate": success / total if total > 0 else 0,
            "avg_latency_ms": 0,
            "model_distribution": model_dist,
            "call_type_distribution": call_type_dist
        }
    
    def delete_old_entries(self, days: int) -> int:
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        to_delete = [k for k, v in self._entries.items() if v.timestamp < cutoff]
        for k in to_delete:
            del self._entries[k]
        return len(to_delete)


class LLMLogManager:
    """LLM 日志管理器"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(
        self,
        storage_type: LogStorageType = LogStorageType.SQLITE,
        storage_path: Optional[Union[str, Path]] = None,
        enable_logging: bool = True
    ):
        # 确保 storage 属性始终存在
        if not hasattr(self, 'storage'):
            self.storage: BaseLogStorage = MemoryLogStorage()
        
        if self._initialized:
            return
        
        self._initialized = True
        self.enable_logging = enable_logging
        
        if not enable_logging:
            self.storage = MemoryLogStorage()
            return
        
        try:
            # 默认路径
            if storage_path is None:
                base_dir = Path.home() / ".ivagent" / "llm_logs"
                base_dir.mkdir(parents=True, exist_ok=True)
                if storage_type == LogStorageType.SQLITE:
                    storage_path = base_dir / "logs.db"
                elif storage_type == LogStorageType.JSON:
                    storage_path = base_dir / "json_logs"
            
            if storage_type == LogStorageType.SQLITE:
                self.storage = SQLiteLogStorage(storage_path)
            elif storage_type == LogStorageType.JSON:
                self.storage = JSONLogStorage(storage_path)
            else:
                self.storage = MemoryLogStorage()
        except Exception as e:
            # 如果初始化失败，使用内存存储作为回退
            print(f"Warning: Failed to initialize log storage: {e}, using memory storage")
            self.storage = MemoryLogStorage()
        
        self._executor = ThreadPoolExecutor(max_workers=2)
    
    def log_start(
        self,
        call_type: str,
        model: str,
        messages: List[Dict[str, Any]],
        system_prompt: Optional[str] = None,
        output_schema: Optional[str] = None,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[LLMLogEntry]:
        """记录调用开始"""
        if not self.enable_logging:
            return None
        
        # 合并 metadata，自动添加 Agent 信息
        merged_metadata = dict(metadata) if metadata else {}
        
        # 如果提供了 agent_id 且 metadata 中没有 agent 信息，尝试从 agent_logger 获取
        if agent_id and ('agent_type' not in merged_metadata or 'target_function' not in merged_metadata):
            try:
                # 延迟导入避免循环依赖
                from .agent_logger import get_agent_log_manager
                agent_logger = get_agent_log_manager()
                agent_exec = agent_logger.get_execution(agent_id)
                if agent_exec:
                    if 'agent_type' not in merged_metadata:
                        merged_metadata['agent_type'] = agent_exec.agent_type
                    if 'target_function' not in merged_metadata:
                        merged_metadata['target_function'] = agent_exec.target_function
            except Exception:
                pass  # 如果获取失败，忽略错误
        
        entry = LLMLogEntry.create(
            call_type=call_type,
            model=model,
            messages=messages,
            system_prompt=system_prompt,
            output_schema=output_schema,
            session_id=session_id,
            agent_id=agent_id,
            metadata=merged_metadata
        )
        # 更新状态为运行中
        entry.status = LogStatus.RUNNING.value
        
        self.storage.save_entry(entry)
        return entry
    
    def log_end(
        self,
        entry: Optional[LLMLogEntry],
        response: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        latency_ms: float = 0,
        retry_count: int = 0,
        success: bool = False
    ):
        """记录调用结束"""
        if not self.enable_logging or entry is None:
            return
        
        # 根据 success 设置 status
        status = LogStatus.COMPLETED.value if success else LogStatus.FAILED.value
        
        if hasattr(self.storage, 'update_entry'):
            self.storage.update_entry(
                entry.id,
                response=response,
                error=error,
                latency_ms=latency_ms,
                retry_count=retry_count,
                status=status,
                success=success
            )
    
    async def alog_end(self, **kwargs):
        """异步记录调用结束"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self._executor, self.log_end, **kwargs)
    
    def get_entry(self, entry_id: str) -> Optional[LLMLogEntry]:
        """获取日志条目"""
        return self.storage.get_entry(entry_id)
    
    def query(
        self,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        call_type: Optional[str] = None,
        model: Optional[str] = None,
        status: Optional[str] = None,
        success: Optional[bool] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        search_keyword: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[LLMLogEntry]:
        """查询日志"""
        return self.storage.query_entries(
            session_id=session_id,
            agent_id=agent_id,
            call_type=call_type,
            model=model,
            status=status,
            success=success,
            start_time=start_time,
            end_time=end_time,
            search_keyword=search_keyword,
            limit=limit,
            offset=offset
        )
    
    def get_sessions(self) -> List[Dict[str, Any]]:
        """获取会话列表"""
        return self.storage.get_sessions()
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        if not hasattr(self, 'storage') or self.storage is None:
            return {
                "total_calls": 0,
                "success_calls": 0,
                "failed_calls": 0,
                "success_rate": 0.0,
                "avg_latency_ms": 0.0,
                "model_distribution": {},
                "call_type_distribution": {}
            }
        return self.storage.get_stats()
    
    def get_tool_call_stats(self) -> Dict[str, Any]:
        """获取 Tool Call 相关的统计信息"""
        # 查询所有 tool_call 类型的日志
        tool_call_entries = self.query(call_type="tool_call", limit=10000)
        
        total = len(tool_call_entries)
        if total == 0:
            return {
                "total_tool_calls": 0,
                "success_count": 0,
                "failed_count": 0,
                "avg_tools_per_call": 0,
                "tool_usage_distribution": {},
            }
        
        success_count = sum(1 for e in tool_call_entries if e.success)
        failed_count = total - success_count
        
        # 统计工具使用分布
        tool_usage = {}
        for entry in tool_call_entries:
            metadata = entry.metadata or {}
            tool_names = metadata.get("tool_names", [])
            for name in tool_names:
                tool_usage[name] = tool_usage.get(name, 0) + 1
        
        # 计算平均每次调用使用的工具数
        avg_tools = sum(len(e.metadata.get("tool_names", [])) for e in tool_call_entries) / total if total > 0 else 0
        
        return {
            "total_tool_calls": total,
            "success_count": success_count,
            "failed_count": failed_count,
            "success_rate": success_count / total if total > 0 else 0,
            "avg_tools_per_call": round(avg_tools, 2),
            "tool_usage_distribution": tool_usage,
        }
    
    def export_to_json(self, filepath: Union[str, Path], 
                       session_id: Optional[str] = None) -> int:
        """导出日志到 JSON 文件"""
        entries = self.query(session_id=session_id, limit=10000)
        
        data = {
            "export_time": datetime.now().isoformat(),
            "total_entries": len(entries),
            "entries": [asdict(e) for e in entries]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        
        return len(entries)


# 全局日志管理器实例
def get_log_manager(
    storage_type: LogStorageType = LogStorageType.SQLITE,
    storage_path: Optional[Union[str, Path]] = None,
    enable_logging: bool = True
) -> LLMLogManager:
    """获取日志管理器实例（单例）"""
    return LLMLogManager(storage_type, storage_path, enable_logging)


# 便捷装饰器
def log_llm_call(call_type: str = "unknown"):
    """装饰器：自动记录 LLM 调用"""
    def decorator(func):
        async def async_wrapper(*args, **kwargs):
            manager = get_log_manager()
            entry = None
            start_time = datetime.now()
            
            try:
                # 提取参数信息
                messages = kwargs.get('messages', [])
                system_prompt = kwargs.get('system_prompt')
                output_schema = str(kwargs.get('output_schema', ''))
                
                # 获取模型名称（从第一个参数或 kwargs）
                model = "unknown"
                if args and hasattr(args[0], 'llm'):
                    model = getattr(args[0].llm, 'model_name', 'unknown')
                
                entry = manager.log_start(
                    call_type=call_type,
                    model=model,
                    messages=messages,
                    system_prompt=system_prompt,
                    output_schema=output_schema
                )
                
                result = await func(*args, **kwargs)
                
                # 计算延迟
                latency = (datetime.now() - start_time).total_seconds() * 1000
                
                # 记录成功
                response_data = None
                if hasattr(result, 'model_dump'):
                    response_data = result.model_dump()
                elif isinstance(result, dict):
                    response_data = result
                else:
                    response_data = {"content": str(result)}
                
                manager.log_end(
                    entry=entry,
                    response=response_data,
                    latency_ms=latency,
                    success=True
                )
                
                return result
                
            except Exception as e:
                latency = (datetime.now() - start_time).total_seconds() * 1000
                manager.log_end(
                    entry=entry,
                    error=str(e),
                    latency_ms=latency,
                    success=False
                )
                raise
        
        return async_wrapper
    return decorator
