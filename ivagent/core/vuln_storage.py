#!/usr/bin/env python3
"""
漏洞数据库存储系统

用于存储、查询和管理 IVAgent 发现的漏洞
支持漏洞去重、筛选、统计等功能
"""

import json
import sqlite3
import threading
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, asdict, field


class VulnerabilitySeverity(str, Enum):
    """漏洞危害等级"""
    CRITICAL = "critical"    # 严重
    HIGH = "high"            # 高危
    MEDIUM = "medium"        # 中危
    LOW = "low"              # 低危
    INFO = "info"            # 信息


class VulnerabilityStatus(str, Enum):
    """漏洞状态"""
    NEW = "new"              # 新发现
    CONFIRMED = "confirmed"  # 已确认
    FALSE_POSITIVE = "false_positive"  # 误报
    FIXED = "fixed"          # 已修复
    IGNORED = "ignored"      # 已忽略


@dataclass
class VulnerabilityRecord:
    """
    漏洞记录
    
    完整的漏洞信息，用于数据库存储
    """
    vuln_id: str
    
    # 基本信息
    name: str                                   # 漏洞名称
    type: str                                   # 漏洞类型
    description: str                            # 漏洞描述
    severity: str                               # 危害等级
    confidence: float                           # 置信度 (0-1)
    
    # 位置信息
    function_identifier: str                     # 函数标识符
    location: str                               # 具体位置
    file_path: Optional[str] = None             # 文件路径
    line_number: Optional[int] = None           # 行号
    
    # 数据流
    data_flow_source: Optional[str] = None      # 污点源
    data_flow_intermediate: str = "[]"          # 中间节点 (JSON)
    data_flow_sink: Optional[str] = None        # 漏洞点
    data_flow_path: Optional[str] = None        # 完整路径描述
    
    # 证据和修复
    evidence: str = "[]"                        # 证据列表 (JSON)
    remediation: Optional[str] = None           # 修复建议
    code_snippet: Optional[str] = None          # 代码片段
    
    # 分析来源
    agent_id: Optional[str] = None              # 发现该漏洞的 Agent ID
    parent_agent_id: Optional[str] = None       # 父 Agent ID
    call_stack: str = "[]"                      # 调用栈 (JSON)
    
    # 元数据
    status: str = "new"                         # 漏洞状态
    created_at: str = ""                        # 创建时间
    updated_at: Optional[str] = None            # 更新时间
    verified_by: Optional[str] = None           # 验证人
    verification_note: Optional[str] = None     # 验证备注
    tags: str = "[]"                            # 标签 (JSON)
    metadata: str = "{}"                        # 额外元数据 (JSON)
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
    
    @property
    def severity_score(self) -> int:
        """获取危害等级数值用于排序"""
        scores = {
            VulnerabilitySeverity.CRITICAL: 4,
            VulnerabilitySeverity.HIGH: 3,
            VulnerabilitySeverity.MEDIUM: 2,
            VulnerabilitySeverity.LOW: 1,
            VulnerabilitySeverity.INFO: 0,
        }
        return scores.get(self.severity, 0)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "vuln_id": self.vuln_id,
            "name": self.name,
            "type": self.type,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "function_identifier": self.function_identifier,
            "location": self.location,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "data_flow": {
                "source": self.data_flow_source,
                "intermediate": json.loads(self.data_flow_intermediate),
                "sink": self.data_flow_sink,
                "path": self.data_flow_path,
            },
            "evidence": json.loads(self.evidence),
            "remediation": self.remediation,
            "code_snippet": self.code_snippet,
            "agent_id": self.agent_id,
            "parent_agent_id": self.parent_agent_id,
            "call_stack": json.loads(self.call_stack),
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "verified_by": self.verified_by,
            "verification_note": self.verification_note,
            "tags": json.loads(self.tags),
            "metadata": json.loads(self.metadata),
        }


@dataclass
class ScanSession:
    """扫描会话记录"""
    session_id: str
    target_binary: Optional[str] = None         # 目标二进制文件
    scan_start_time: str = ""                   # 扫描开始时间
    scan_end_time: Optional[str] = None         # 扫描结束时间
    total_functions: int = 0                    # 总函数数
    scanned_functions: int = 0                  # 已扫描函数数
    total_vulnerabilities: int = 0              # 发现的漏洞总数
    status: str = "running"                     # 扫描状态
    config: str = "{}"                          # 扫描配置 (JSON)
    
    def __post_init__(self):
        if not self.scan_start_time:
            self.scan_start_time = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target_binary": self.target_binary,
            "scan_start_time": self.scan_start_time,
            "scan_end_time": self.scan_end_time,
            "total_functions": self.total_functions,
            "scanned_functions": self.scanned_functions,
            "total_vulnerabilities": self.total_vulnerabilities,
            "status": self.status,
            "config": json.loads(self.config),
        }


class VulnerabilityStorage:
    """漏洞数据库存储（SQLite）"""
    
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
        
        # 漏洞表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL,
                function_identifier TEXT NOT NULL,
                location TEXT NOT NULL,
                file_path TEXT,
                line_number INTEGER,
                data_flow_source TEXT,
                data_flow_intermediate TEXT,
                data_flow_sink TEXT,
                data_flow_path TEXT,
                evidence TEXT,
                remediation TEXT,
                code_snippet TEXT,
                agent_id TEXT,
                parent_agent_id TEXT,
                call_stack TEXT,
                status TEXT NOT NULL DEFAULT 'new',
                created_at TEXT NOT NULL,
                updated_at TEXT,
                verified_by TEXT,
                verification_note TEXT,
                tags TEXT,
                metadata TEXT
            )
        """)
        
        # 扫描会话表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id TEXT PRIMARY KEY,
                target_binary TEXT,
                scan_start_time TEXT NOT NULL,
                scan_end_time TEXT,
                total_functions INTEGER DEFAULT 0,
                scanned_functions INTEGER DEFAULT 0,
                total_vulnerabilities INTEGER DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'running',
                config TEXT
            )
        """)
        
        # 创建索引
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vuln_status ON vulnerabilities(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vuln_type ON vulnerabilities(type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vuln_function ON vulnerabilities(function_identifier)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vuln_agent ON vulnerabilities(agent_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_vuln_created ON vulnerabilities(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_session_status ON scan_sessions(status)")
        
        conn.commit()
    
    def save_vulnerability(self, vuln: VulnerabilityRecord) -> str:
        """保存漏洞记录"""
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO vulnerabilities 
            (id, name, type, description, severity, confidence, function_identifier, location,
             file_path, line_number, data_flow_source, data_flow_intermediate, data_flow_sink, data_flow_path,
             evidence, remediation, code_snippet, agent_id, parent_agent_id, call_stack,
             status, created_at, updated_at, verified_by, verification_note, tags, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            vuln.vuln_id, vuln.name, vuln.type, vuln.description, vuln.severity, vuln.confidence,
            vuln.function_identifier, vuln.location, vuln.file_path, vuln.line_number,
            vuln.data_flow_source, vuln.data_flow_intermediate, vuln.data_flow_sink, vuln.data_flow_path,
            vuln.evidence, vuln.remediation, vuln.code_snippet, vuln.agent_id, vuln.parent_agent_id, vuln.call_stack,
            vuln.status, vuln.created_at, vuln.updated_at, vuln.verified_by, vuln.verification_note, vuln.tags, vuln.metadata
        ))
        conn.commit()
        return vuln.vuln_id
    
    def update_vulnerability(self, vuln_id: str, **kwargs) -> bool:
        """更新漏洞记录"""
        conn = self._get_conn()
        allowed_fields = [
            'status', 'verified_by', 'verification_note', 'updated_at', 'tags', 'metadata'
        ]
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not updates:
            return False
        
        if 'updated_at' not in updates:
            updates['updated_at'] = datetime.now().isoformat()
        
        set_clause = ', '.join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values())
        values.append(vuln_id)
        
        conn.execute(f"UPDATE vulnerabilities SET {set_clause} WHERE id = ?", values)
        conn.commit()
        return True
    
    def get_vulnerability(self, vuln_id: str) -> Optional[VulnerabilityRecord]:
        """获取单个漏洞记录"""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM vulnerabilities WHERE id = ?", (vuln_id,)
        ).fetchone()
        
        if not row:
            return None
        
        return self._row_to_vulnerability(row)
    
    def query_vulnerabilities(
        self,
        severity: Optional[Union[str, List[str]]] = None,
        status: Optional[Union[str, List[str]]] = None,
        vuln_type: Optional[Union[str, List[str]]] = None,
        function_identifier: Optional[str] = None,
        agent_id: Optional[str] = None,
        search_keyword: Optional[str] = None,
        order_by: str = "created_at",
        order_desc: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> List[VulnerabilityRecord]:
        """查询漏洞记录"""
        conn = self._get_conn()
        
        conditions = []
        params = []
        
        if severity:
            if isinstance(severity, str):
                conditions.append("severity = ?")
                params.append(severity)
            else:
                conditions.append(f"severity IN ({','.join('?' * len(severity))})")
                params.extend(severity)
        
        if status:
            if isinstance(status, str):
                conditions.append("status = ?")
                params.append(status)
            else:
                conditions.append(f"status IN ({','.join('?' * len(status))})")
                params.extend(status)
        
        if vuln_type:
            if isinstance(vuln_type, str):
                conditions.append("type = ?")
                params.append(vuln_type)
            else:
                conditions.append(f"type IN ({','.join('?' * len(vuln_type))})")
                params.extend(vuln_type)
        
        if function_identifier:
            conditions.append("function_identifier LIKE ?")
            params.append(f"%{function_identifier}%")
        
        if agent_id:
            conditions.append("agent_id = ?")
            params.append(agent_id)
        
        if search_keyword:
            conditions.append("(name LIKE ? OR description LIKE ? OR location LIKE ?)")
            params.extend([f"%{search_keyword}%"] * 3)
        
        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        order_clause = f"ORDER BY {order_by} {'DESC' if order_desc else 'ASC'}"
        
        rows = conn.execute(
            f"SELECT * FROM vulnerabilities {where_clause} {order_clause} LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()
        
        return [self._row_to_vulnerability(row) for row in rows]
    
    def count_vulnerabilities(
        self,
        severity: Optional[Union[str, List[str]]] = None,
        status: Optional[Union[str, List[str]]] = None,
        vuln_type: Optional[Union[str, List[str]]] = None,
    ) -> int:
        """统计漏洞数量"""
        conn = self._get_conn()
        
        conditions = []
        params = []
        
        if severity:
            if isinstance(severity, str):
                conditions.append("severity = ?")
                params.append(severity)
            else:
                conditions.append(f"severity IN ({','.join('?' * len(severity))})")
                params.extend(severity)
        
        if status:
            if isinstance(status, str):
                conditions.append("status = ?")
                params.append(status)
            else:
                conditions.append(f"status IN ({','.join('?' * len(status))})")
                params.extend(status)
        
        if vuln_type:
            if isinstance(vuln_type, str):
                conditions.append("type = ?")
                params.append(vuln_type)
            else:
                conditions.append(f"type IN ({','.join('?' * len(vuln_type))})")
                params.extend(vuln_type)
        
        where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
        
        result = conn.execute(
            f"SELECT COUNT(*) FROM vulnerabilities {where_clause}", params
        ).fetchone()
        
        return result[0] if result else 0
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取漏洞统计信息"""
        conn = self._get_conn()
        
        # 按严重程度统计
        severity_stats = conn.execute("""
            SELECT severity, COUNT(*) as count FROM vulnerabilities GROUP BY severity
        """).fetchall()
        
        # 按状态统计
        status_stats = conn.execute("""
            SELECT status, COUNT(*) as count FROM vulnerabilities GROUP BY status
        """).fetchall()
        
        # 按类型统计
        type_stats = conn.execute("""
            SELECT type, COUNT(*) as count FROM vulnerabilities GROUP BY type
        """).fetchall()
        
        # 每日新增统计（最近30天）
        daily_stats = conn.execute("""
            SELECT DATE(created_at) as date, COUNT(*) as count 
            FROM vulnerabilities 
            WHERE created_at >= DATE('now', '-30 days')
            GROUP BY DATE(created_at)
            ORDER BY date
        """).fetchall()
        
        # 按函数统计
        function_stats = conn.execute("""
            SELECT function_identifier, COUNT(*) as count 
            FROM vulnerabilities 
            GROUP BY function_identifier
            ORDER BY count DESC
            LIMIT 10
        """).fetchall()
        
        total = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        
        return {
            "total": total,
            "by_severity": {row[0]: row[1] for row in severity_stats},
            "by_status": {row[0]: row[1] for row in status_stats},
            "by_type": {row[0]: row[1] for row in type_stats},
            "by_day": [{"date": row[0], "count": row[1]} for row in daily_stats],
            "by_function": [{"function": row[0], "count": row[1]} for row in function_stats],
        }
    
    def delete_vulnerability(self, vuln_id: str) -> bool:
        """删除漏洞记录"""
        conn = self._get_conn()
        cursor = conn.execute("DELETE FROM vulnerabilities WHERE id = ?", (vuln_id,))
        conn.commit()
        return cursor.rowcount > 0
    
    def delete_old_vulnerabilities(self, days: int) -> int:
        """删除指定天数前的漏洞记录"""
        conn = self._get_conn()
        cursor = conn.execute(
            "DELETE FROM vulnerabilities WHERE created_at < DATETIME('now', '-? days')",
            (days,)
        )
        conn.commit()
        return cursor.rowcount
    
    def clear_all_vulnerabilities(self) -> int:
        """清除所有漏洞记录"""
        conn = self._get_conn()
        cursor = conn.execute("DELETE FROM vulnerabilities")
        conn.commit()
        return cursor.rowcount
    
    # ========== 扫描会话相关 ==========
    
    def create_scan_session(self, session: ScanSession) -> str:
        """创建扫描会话"""
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO scan_sessions 
            (id, target_binary, scan_start_time, scan_end_time, total_functions, 
             scanned_functions, total_vulnerabilities, status, config)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session.session_id, session.target_binary, session.scan_start_time,
            session.scan_end_time, session.total_functions, session.scanned_functions,
            session.total_vulnerabilities, session.status, session.config
        ))
        conn.commit()
        return session.session_id
    
    def update_scan_session(self, session_id: str, **kwargs) -> bool:
        """更新扫描会话"""
        conn = self._get_conn()
        allowed_fields = [
            'scan_end_time', 'total_functions', 'scanned_functions',
            'total_vulnerabilities', 'status'
        ]
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not updates:
            return False
        
        set_clause = ', '.join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values())
        values.append(session_id)
        
        conn.execute(f"UPDATE scan_sessions SET {set_clause} WHERE id = ?", values)
        conn.commit()
        return True
    
    def get_scan_session(self, session_id: str) -> Optional[ScanSession]:
        """获取扫描会话"""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM scan_sessions WHERE id = ?", (session_id,)
        ).fetchone()
        
        if not row:
            return None
        
        return self._row_to_scan_session(row)
    
    def get_all_scan_sessions(self, limit: int = 100) -> List[ScanSession]:
        """获取所有扫描会话"""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM scan_sessions ORDER BY scan_start_time DESC LIMIT ?",
            (limit,)
        ).fetchall()
        
        return [self._row_to_scan_session(row) for row in rows]
    
    def _row_to_vulnerability(self, row: sqlite3.Row) -> VulnerabilityRecord:
        """将数据库行转换为 VulnerabilityRecord"""
        return VulnerabilityRecord(
            vuln_id=row['id'],
            name=row['name'],
            type=row['type'],
            description=row['description'],
            severity=row['severity'],
            confidence=row['confidence'],
            function_identifier=row['function_identifier'],
            location=row['location'],
            file_path=row['file_path'],
            line_number=row['line_number'],
            data_flow_source=row['data_flow_source'],
            data_flow_intermediate=row['data_flow_intermediate'] or "[]",
            data_flow_sink=row['data_flow_sink'],
            data_flow_path=row['data_flow_path'],
            evidence=row['evidence'] or "[]",
            remediation=row['remediation'],
            code_snippet=row['code_snippet'],
            agent_id=row['agent_id'],
            parent_agent_id=row['parent_agent_id'],
            call_stack=row['call_stack'] or "[]",
            status=row['status'],
            created_at=row['created_at'],
            updated_at=row['updated_at'],
            verified_by=row['verified_by'],
            verification_note=row['verification_note'],
            tags=row['tags'] or "[]",
            metadata=row['metadata'] or "{}",
        )
    
    def _row_to_scan_session(self, row: sqlite3.Row) -> ScanSession:
        """将数据库行转换为 ScanSession"""
        return ScanSession(
            session_id=row['id'],
            target_binary=row['target_binary'],
            scan_start_time=row['scan_start_time'],
            scan_end_time=row['scan_end_time'],
            total_functions=row['total_functions'],
            scanned_functions=row['scanned_functions'],
            total_vulnerabilities=row['total_vulnerabilities'],
            status=row['status'],
            config=row['config'] or "{}",
        )


class VulnerabilityManager:
    """漏洞管理器（单例）"""
    
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
            db_path = base_dir / "vulnerabilities.db"
        
        self.storage = VulnerabilityStorage(db_path)
    
    def add_vulnerability(
        self,
        name: str,
        vuln_type: str,
        description: str,
        severity: str,
        confidence: float,
        function_identifier: str,
        location: str,
        agent_id: Optional[str] = None,
        **kwargs
    ) -> VulnerabilityRecord:
        """
        添加新漏洞
        
        Args:
            name: 漏洞名称
            vuln_type: 漏洞类型
            description: 漏洞描述
            severity: 危害等级 (critical/high/medium/low/info)
            confidence: 置信度 (0-1)
            function_identifier: 函数唯一标识符（全局唯一）
            location: 具体位置
            agent_id: Agent ID
            **kwargs: 其他可选字段
        
        Returns:
            VulnerabilityRecord 对象
        """
        vuln = VulnerabilityRecord(
            vuln_id=str(uuid.uuid4()),
            name=name,
            type=vuln_type,
            description=description,
            severity=severity,
            confidence=confidence,
            function_identifier=function_identifier,
            location=location,
            agent_id=agent_id,
            **kwargs
        )
        self.storage.save_vulnerability(vuln)
        return vuln
    
    def import_from_agent_result(
        self,
        vulnerabilities: List[Any],
        function_identifier: str,
        agent_id: Optional[str] = None,
        parent_agent_id: Optional[str] = None,
    ) -> List[VulnerabilityRecord]:
        """
        从 Agent 分析结果导入漏洞
        
        Args:
            vulnerabilities: Agent 返回的漏洞列表
            function_identifier: 函数唯一标识符（全局唯一）
            agent_id: Agent ID
            parent_agent_id: 父 Agent ID
        
        Returns:
            导入的漏洞记录列表
        """
        records = []
        for vuln in vulnerabilities:
            if hasattr(vuln, 'to_dict'):
                vuln_dict = vuln.to_dict()
            elif isinstance(vuln, dict):
                vuln_dict = vuln
            else:
                continue
            
            # 映射严重程度
            severity_val = vuln_dict.get('severity', 0.5)
            if isinstance(severity_val, (int, float)):
                if severity_val >= 0.9:
                    severity = VulnerabilitySeverity.CRITICAL
                elif severity_val >= 0.7:
                    severity = VulnerabilitySeverity.HIGH
                elif severity_val >= 0.4:
                    severity = VulnerabilitySeverity.MEDIUM
                elif severity_val >= 0.2:
                    severity = VulnerabilitySeverity.LOW
                else:
                    severity = VulnerabilitySeverity.INFO
            else:
                severity = severity_val
            
            # 处理数据流
            data_flow = vuln_dict.get('data_flow', {})
            if data_flow:
                data_flow_intermediate = json.dumps(data_flow.get('intermediate_nodes', []))
                data_flow_path = data_flow.get('path_description')
            else:
                data_flow_intermediate = "[]"
                data_flow_path = None
            
            record = VulnerabilityRecord(
                vuln_id=str(uuid.uuid4()),
                name=vuln_dict.get('name', 'Unknown'),
                type=vuln_dict.get('type', 'UNKNOWN'),
                description=vuln_dict.get('description', ''),
                severity=severity,
                confidence=vuln_dict.get('confidence', 0.5),
                function_identifier=function_identifier,
                location=vuln_dict.get('location', ''),
                file_path=vuln_dict.get('file_path'),
                line_number=vuln_dict.get('line_number'),
                data_flow_source=data_flow.get('source') if data_flow else None,
                data_flow_intermediate=data_flow_intermediate,
                data_flow_sink=data_flow.get('sink') if data_flow else None,
                data_flow_path=data_flow_path,
                evidence=json.dumps(vuln_dict.get('metadata', {}).get('evidence', [])),
                remediation=vuln_dict.get('remediation'),
                code_snippet=vuln_dict.get('code_snippet'),
                agent_id=agent_id,
                parent_agent_id=parent_agent_id,
                call_stack=json.dumps(vuln_dict.get('metadata', {}).get('call_stack', [])),
                tags=json.dumps(vuln_dict.get('tags', [])),
                metadata=json.dumps(vuln_dict.get('metadata', {})),
            )
            
            self.storage.save_vulnerability(record)
            records.append(record)
        
        return records
    
    def get_vulnerability(self, vuln_id: str) -> Optional[VulnerabilityRecord]:
        """获取单个漏洞"""
        return self.storage.get_vulnerability(vuln_id)
    
    def list_vulnerabilities(self, **kwargs) -> List[VulnerabilityRecord]:
        """列出漏洞"""
        return self.storage.query_vulnerabilities(**kwargs)
    
    def update_status(
        self,
        vuln_id: str,
        status: str,
        verified_by: Optional[str] = None,
        note: Optional[str] = None,
    ) -> bool:
        """更新漏洞状态"""
        return self.storage.update_vulnerability(
            vuln_id=vuln_id,
            status=status,
            verified_by=verified_by,
            verification_note=note,
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return self.storage.get_statistics()
    
    def delete_vulnerability(self, vuln_id: str) -> bool:
        """删除单个漏洞"""
        return self.storage.delete_vulnerability(vuln_id)
    
    def clear_all_vulnerabilities(self) -> int:
        """清除所有漏洞记录"""
        return self.storage.clear_all_vulnerabilities()


# 全局实例
def get_vulnerability_manager(db_path: Optional[Union[str, Path]] = None) -> VulnerabilityManager:
    """获取漏洞管理器实例"""
    return VulnerabilityManager(db_path)
