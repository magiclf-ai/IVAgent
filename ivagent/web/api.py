#!/usr/bin/env python3
"""
LLM 日志 Web API

使用 FastAPI 提供 RESTful API 接口
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.llm_logger import get_log_manager, LLMLogEntry, LogStorageType
from core.agent_logger import get_agent_log_manager, AgentLogManager
from core.vuln_storage import get_vulnerability_manager, VulnerabilityManager, VulnerabilitySeverity, VulnerabilityStatus
from api_redis import redis_router


# API 模型
class LogEntryResponse(BaseModel):
    """日志条目响应"""
    id: str
    timestamp: str
    session_id: str
    agent_id: Optional[str]
    call_type: str
    model: str
    messages: List[Dict[str, Any]]
    system_prompt: Optional[str]
    output_schema: Optional[str]
    response: Optional[Dict[str, Any]]
    error: Optional[str]
    latency_ms: float
    retry_count: int
    status: str  # pending, running, completed, failed
    success: bool
    metadata: Dict[str, Any]
    # Agent 相关信息（用于展示）
    agent_type: Optional[str] = None
    target_function: Optional[str] = None


class SessionInfo(BaseModel):
    """会话信息"""
    session_id: str
    start_time: str
    end_time: Optional[str]
    total_calls: int
    success_calls: int
    failed_calls: int


class StatsResponse(BaseModel):
    """统计信息响应"""
    total_calls: int
    success_calls: int
    failed_calls: int
    success_rate: float
    avg_latency_ms: float
    model_distribution: Dict[str, int]
    call_type_distribution: Dict[str, int]


class QueryRequest(BaseModel):
    """查询请求"""
    session_id: Optional[str] = None
    agent_id: Optional[str] = None
    call_type: Optional[str] = None
    model: Optional[str] = None
    status: Optional[str] = None
    success: Optional[bool] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    search: Optional[str] = Field(None, description="搜索关键词（匹配日志内容）")
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


# 创建 FastAPI 应用
app = FastAPI(
    title="LLM 交互日志可视化系统",
    description="用于查看和分析 LLM 交互日志的 Web API",
    version="1.0.0"
)

# 注册 Redis 路由
app.include_router(redis_router)

# WebSocket 连接管理器
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
    
    async def broadcast(self, message: Dict[str, Any]):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                disconnected.append(connection)
        
        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()

# 获取日志管理器
def get_logger():
    return get_log_manager()

# 获取 Agent 日志管理器
def get_agent_logger():
    return get_agent_log_manager()


# 调试：打印数据库路径
@app.on_event("startup")
async def startup_event():
    """应用启动时打印数据库路径信息"""
    logger = get_logger()
    agent_logger = get_agent_logger()
    llm_db = getattr(logger.storage, 'db_path', 'N/A (Memory Storage)')
    agent_db = getattr(agent_logger.storage, 'db_path', 'N/A (Memory Storage)')
    print(f"[STARTUP] LLM Logs DB: {llm_db}")
    print(f"[STARTUP] Agent Logs DB: {agent_db}")

# 获取漏洞管理器
def get_vuln_manager():
    return get_vulnerability_manager()


# ==================== API 路由 ====================

@app.get("/api/health")
async def health_check():
    """健康检查"""
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


@app.get("/api/logs", response_model=List[LogEntryResponse])
async def get_logs(
    session_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    call_type: Optional[str] = None,
    model: Optional[str] = None,
    status: Optional[str] = None,
    success: Optional[bool] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    search: Optional[str] = Query(None, description="搜索关键词（匹配日志内容）"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0)
):
    """获取日志列表"""
    logger = get_logger()
    agent_logger = get_agent_logger()
    entries = logger.query(
        session_id=session_id,
        agent_id=agent_id,
        call_type=call_type,
        model=model,
        status=status,
        success=success,
        start_time=start_time,
        end_time=end_time,
        search_keyword=search,
        limit=limit,
        offset=offset
    )
    
    # 批量获取 Agent 信息（用于补充 metadata 中可能缺失的信息）
    agent_ids = [e.agent_id for e in entries if e.agent_id]
    agent_info_map = {}
    if agent_ids:
        for aid in set(agent_ids):
            agent_exec = agent_logger.get_execution(aid)
            if agent_exec:
                agent_info_map[aid] = {
                    "agent_type": agent_exec.agent_type,
                    "target_function": agent_exec.target_function
                }
    
    return [
        LogEntryResponse(
            id=e.id,
            timestamp=e.timestamp,
            session_id=e.session_id,
            agent_id=e.agent_id,
            call_type=e.call_type,
            model=e.model,
            messages=e.messages,
            system_prompt=e.system_prompt,
            output_schema=e.output_schema,
            response=e.response,
            error=e.error,
            latency_ms=e.latency_ms,
            retry_count=e.retry_count,
            status=e.status,
            success=e.success,
            metadata=e.metadata,
            # 优先从 metadata 获取，否则从 agent_info_map 获取
            agent_type=e.metadata.get('agent_type') or (agent_info_map.get(e.agent_id, {}).get("agent_type") if e.agent_id else None),
            target_function=e.metadata.get('target_function') or (agent_info_map.get(e.agent_id, {}).get("target_function") if e.agent_id else None)
        )
        for e in entries
    ]


@app.post("/api/logs/query", response_model=List[LogEntryResponse])
async def query_logs(request: QueryRequest):
    """高级查询日志"""
    return await get_logs(
        session_id=request.session_id,
        agent_id=request.agent_id,
        call_type=request.call_type,
        model=request.model,
        status=request.status,
        success=request.success,
        start_time=request.start_time,
        end_time=request.end_time,
        search=request.search,
        limit=request.limit,
        offset=request.offset
    )


@app.get("/api/logs/{entry_id}", response_model=LogEntryResponse)
async def get_log_entry(entry_id: str):
    """获取单个日志条目详情"""
    logger = get_logger()
    agent_logger = get_agent_logger()
    entry = logger.get_entry(entry_id)
    
    if not entry:
        raise HTTPException(status_code=404, detail="日志条目不存在")
    
    # 获取 Agent 信息（用于补充 metadata 中可能缺失的信息）
    agent_type = entry.metadata.get('agent_type')
    target_function = entry.metadata.get('target_function')
    
    # 如果 metadata 中没有，从 agent_logger 获取
    if entry.agent_id and (not agent_type or not target_function):
        agent_exec = agent_logger.get_execution(entry.agent_id)
        if agent_exec:
            if not agent_type:
                agent_type = agent_exec.agent_type
            if not target_function:
                target_function = agent_exec.target_function
    
    return LogEntryResponse(
        id=entry.id,
        timestamp=entry.timestamp,
        session_id=entry.session_id,
        agent_id=entry.agent_id,
        call_type=entry.call_type,
        model=entry.model,
        messages=entry.messages,
        system_prompt=entry.system_prompt,
        output_schema=entry.output_schema,
        response=entry.response,
        error=entry.error,
        latency_ms=entry.latency_ms,
        retry_count=entry.retry_count,
        status=entry.status,
        success=entry.success,
        metadata=entry.metadata,
        agent_type=agent_type,
        target_function=target_function
    )


@app.get("/api/sessions", response_model=List[SessionInfo])
async def get_sessions():
    """获取所有会话列表"""
    logger = get_logger()
    sessions = logger.get_sessions()
    
    return [
        SessionInfo(
            session_id=s["session_id"],
            start_time=s["start_time"],
            end_time=s.get("end_time"),
            total_calls=s["total_calls"],
            success_calls=s["success_calls"],
            failed_calls=s["failed_calls"]
        )
        for s in sessions
    ]


@app.get("/api/sessions/{session_id}/logs", response_model=List[LogEntryResponse])
async def get_session_logs(session_id: str, limit: int = Query(default=100, ge=1, le=1000)):
    """获取指定会话的所有日志"""
    return await get_logs(session_id=session_id, limit=limit)


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats():
    """获取统计信息"""
    logger = get_logger()
    stats = logger.get_stats()
    
    return StatsResponse(**stats)


@app.get("/api/stats/timeline")
async def get_timeline_stats(hours: int = Query(default=24, ge=1, le=168)):
    """获取时间线统计"""
    logger = get_logger()
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=hours)
    
    entries = logger.query(
        start_time=start_time.isoformat(),
        end_time=end_time.isoformat(),
        limit=10000
    )
    
    # 按小时分组统计
    hourly_stats = {}
    for entry in entries:
        hour = entry.timestamp[:13]  # YYYY-MM-DDTHH
        if hour not in hourly_stats:
            hourly_stats[hour] = {"total": 0, "success": 0, "failed": 0}
        hourly_stats[hour]["total"] += 1
        if entry.success:
            hourly_stats[hour]["success"] += 1
        else:
            hourly_stats[hour]["failed"] += 1
    
    return {
        "timeline": [
            {"hour": h, **stats}
            for h, stats in sorted(hourly_stats.items())
        ]
    }


@app.get("/api/models")
async def get_models():
    """获取所有使用过的模型列表"""
    logger = get_logger()
    stats = logger.get_stats()
    return {"models": list(stats.get("model_distribution", {}).keys())}


@app.get("/api/call-types")
async def get_call_types():
    """获取所有调用类型列表"""
    logger = get_logger()
    stats = logger.get_stats()
    return {"call_types": list(stats.get("call_type_distribution", {}).keys())}


# ==================== Tool Call 日志 API ====================

class ToolCallStatsResponse(BaseModel):
    """Tool Call 统计响应"""
    total_tool_calls: int
    success_count: int
    failed_count: int
    success_rate: float
    avg_tools_per_call: float
    tool_usage_distribution: Dict[str, int]


class ToolCallLogEntry(BaseModel):
    """Tool Call 日志条目"""
    id: str
    timestamp: str
    session_id: str
    agent_id: Optional[str]
    model: str
    status: str
    success: bool
    latency_ms: float
    retry_count: int
    tool_count: int
    tool_names: List[str]
    tool_calls: List[Dict[str, Any]]
    response_content: Optional[str]
    error: Optional[str]
    agent_type: Optional[str] = None
    target_function: Optional[str] = None


@app.get("/api/tool-calls", response_model=List[ToolCallLogEntry])
async def get_tool_calls(
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    success: Optional[bool] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0)
):
    """获取 Tool Call 日志列表"""
    logger = get_logger()
    agent_logger = get_agent_logger()
    
    # 查询 tool_call 类型的日志
    entries = logger.query(
        call_type="tool_call",
        agent_id=agent_id,
        status=status,
        success=success,
        limit=limit,
        offset=offset
    )
    
    # 批量获取 Agent 信息
    agent_ids = [e.agent_id for e in entries if e.agent_id]
    agent_info_map = {}
    if agent_ids:
        for aid in set(agent_ids):
            agent_exec = agent_logger.get_execution(aid)
            if agent_exec:
                agent_info_map[aid] = {
                    "agent_type": agent_exec.agent_type,
                    "target_function": agent_exec.target_function
                }
    
    result = []
    for e in entries:
        metadata = e.metadata or {}
        response = e.response or {}
        tool_call_details = response.get("tool_call_details", {})
        
        result.append(ToolCallLogEntry(
            id=e.id,
            timestamp=e.timestamp,
            session_id=e.session_id,
            agent_id=e.agent_id,
            model=e.model,
            status=e.status,
            success=e.success,
            latency_ms=e.latency_ms,
            retry_count=e.retry_count,
            tool_count=metadata.get("tool_count", 0),
            tool_names=metadata.get("tool_names", []),
            tool_calls=response.get("tool_calls", []),
            response_content=response.get("content", ""),
            error=e.error,
            agent_type=e.metadata.get('agent_type') or (agent_info_map.get(e.agent_id, {}).get("agent_type") if e.agent_id else None),
            target_function=e.metadata.get('target_function') or (agent_info_map.get(e.agent_id, {}).get("target_function") if e.agent_id else None)
        ))
    
    return result


@app.get("/api/tool-calls/stats", response_model=ToolCallStatsResponse)
async def get_tool_call_stats():
    """获取 Tool Call 统计信息"""
    logger = get_logger()
    stats = logger.get_tool_call_stats()
    return ToolCallStatsResponse(**stats)


@app.get("/api/tool-calls/{entry_id}")
async def get_tool_call_detail(entry_id: str):
    """获取 Tool Call 日志详情"""
    logger = get_logger()
    agent_logger = get_agent_logger()
    
    entry = logger.get_entry(entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="日志条目不存在")
    
    # 获取 Agent 信息
    agent_type = entry.metadata.get('agent_type')
    target_function = entry.metadata.get('target_function')
    
    if entry.agent_id and (not agent_type or not target_function):
        agent_exec = agent_logger.get_execution(entry.agent_id)
        if agent_exec:
            if not agent_type:
                agent_type = agent_exec.agent_type
            if not target_function:
                target_function = agent_exec.target_function
    
    metadata = entry.metadata or {}
    response = entry.response or {}
    
    return {
        "id": entry.id,
        "timestamp": entry.timestamp,
        "session_id": entry.session_id,
        "agent_id": entry.agent_id,
        "model": entry.model,
        "status": entry.status,
        "success": entry.success,
        "latency_ms": entry.latency_ms,
        "retry_count": entry.retry_count,
        "messages": entry.messages,
        "system_prompt": entry.system_prompt,
        "tools": metadata.get("tools", []),
        "tool_count": metadata.get("tool_count", 0),
        "tool_names": metadata.get("tool_names", []),
        "tool_calls": response.get("tool_calls", []),
        "response": response,
        "error": entry.error,
        "agent_type": agent_type,
        "target_function": target_function
    }


@app.get("/api/tool-calls/tools/list")
async def get_tool_list():
    """获取所有已使用的工具列表"""
    logger = get_logger()
    entries = logger.query(call_type="tool_call", limit=10000)
    
    # 统计工具使用
    tool_usage = {}
    for entry in entries:
        metadata = entry.metadata or {}
        tool_names = metadata.get("tool_names", [])
        for name in tool_names:
            if name not in tool_usage:
                tool_usage[name] = {"count": 0, "success": 0, "failed": 0}
            tool_usage[name]["count"] += 1
            if entry.success:
                tool_usage[name]["success"] += 1
            else:
                tool_usage[name]["failed"] += 1
    
    return {
        "tools": [
            {"name": name, **stats}
            for name, stats in sorted(tool_usage.items(), key=lambda x: -x[1]["count"])
        ]
    }


@app.delete("/api/logs/old")
async def delete_old_logs(days: int = Query(default=7, ge=1)):
    """删除指定天数前的日志"""
    logger = get_logger()
    deleted = logger.storage.delete_old_entries(days)
    return {"deleted": deleted}


@app.post("/api/export")
async def export_logs(
    filepath: str,
    session_id: Optional[str] = None
):
    """导出日志到 JSON 文件"""
    logger = get_logger()
    try:
        count = logger.export_to_json(filepath, session_id)
        return {"exported": count, "filepath": filepath}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"导出失败: {str(e)}")


# WebSocket 接口
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket 实时推送"""
    await manager.connect(websocket)
    try:
        while True:
            # 接收客户端消息
            data = await websocket.receive_json()
            
            # 处理订阅请求
            if data.get("action") == "subscribe":
                await websocket.send_json({
                    "type": "subscribed",
                    "message": "已连接到日志实时推送"
                })
            
            elif data.get("action") == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "timestamp": datetime.now().isoformat()
                })
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# 广播新日志（供外部调用）
async def broadcast_new_log(entry: LLMLogEntry):
    """广播新日志条目"""
    await manager.broadcast({
        "type": "new_log",
        "data": {
            "id": entry.id,
            "timestamp": entry.timestamp,
            "session_id": entry.session_id,
            "agent_id": entry.agent_id,
            "call_type": entry.call_type,
            "model": entry.model,
            "status": entry.status,
            "success": entry.success,
            "latency_ms": entry.latency_ms
        }
    })


# ==================== Agent 日志 API ====================

class AgentExecutionResponse(BaseModel):
    """Agent 执行日志响应"""
    agent_id: str
    parent_id: Optional[str]
    agent_type: str
    target_function: str
    call_stack: List[str]
    depth: int
    status: str
    start_time: str
    end_time: Optional[str]
    vulnerabilities_found: int
    sub_agents_created: int
    llm_calls: int
    summary: str
    error_message: Optional[str]


class AgentTreeNode(BaseModel):
    """Agent 树节点"""
    agent_id: str
    parent_id: Optional[str]
    agent_type: str
    target_function: str
    depth: int
    status: str
    vulnerabilities_found: int
    sub_agents_created: int
    children: List['AgentTreeNode'] = []


class AgentStatsResponse(BaseModel):
    """Agent 统计响应"""
    total_agents: int
    completed: int
    failed: int
    total_vulnerabilities: int
    agent_type_distribution: Dict[str, int]


@app.get("/api/agents", response_model=List[AgentExecutionResponse])
async def get_agents(
    agent_type: Optional[str] = None,
    status: Optional[str] = None,
    target_function: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0)
):
    """获取 Agent 执行列表"""
    logger = get_agent_logger()
    executions = logger.storage.query_executions(
        agent_type=agent_type,
        status=status,
        target_function=target_function,
        limit=limit,
        offset=offset
    )
    
    return [
        AgentExecutionResponse(
            agent_id=e.agent_id,
            parent_id=e.parent_id,
            agent_type=e.agent_type,
            target_function=e.target_function,
            call_stack=e.call_stack,
            depth=e.depth,
            status=e.status,
            start_time=e.start_time,
            end_time=e.end_time,
            vulnerabilities_found=e.vulnerabilities_found,
            sub_agents_created=e.sub_agents_created,
            llm_calls=e.llm_calls,
            summary=e.summary,
            error_message=e.error_message,
        )
        for e in executions
    ]


@app.get("/api/agents/{agent_id}", response_model=AgentExecutionResponse)
async def get_agent(agent_id: str):
    """获取单个 Agent 执行详情"""
    logger = get_agent_logger()
    execution = logger.get_execution(agent_id)
    
    if not execution:
        raise HTTPException(status_code=404, detail="Agent 执行记录不存在")
    
    return AgentExecutionResponse(
        agent_id=execution.agent_id,
        parent_id=execution.parent_id,
        agent_type=execution.agent_type,
        target_function=execution.target_function,
        call_stack=execution.call_stack,
        depth=execution.depth,
        status=execution.status,
        start_time=execution.start_time,
        end_time=execution.end_time,
        vulnerabilities_found=execution.vulnerabilities_found,
        sub_agents_created=execution.sub_agents_created,
        llm_calls=execution.llm_calls,
        summary=execution.summary,
        error_message=execution.error_message,
    )


@app.get("/api/agents/{agent_id}/tree")
async def get_agent_tree(agent_id: str):
    """获取 Agent 执行树"""
    logger = get_agent_logger()
    tree = logger.get_execution_tree(agent_id)
    
    if not tree:
        raise HTTPException(status_code=404, detail="Agent 执行记录不存在")
    
    return tree


@app.get("/api/agents/{agent_id}/tasks")
async def get_agent_tasks(agent_id: str):
    """获取 Agent 的任务列表"""
    logger = get_agent_logger()
    tasks = logger.storage.get_tasks_by_agent(agent_id)
    
    return [
        {
            "task_id": t.task_id,
            "task_type": t.task_type,
            "target": t.target,
            "status": t.status,
            "start_time": t.start_time,
            "end_time": t.end_time,
            "result_summary": t.result_summary,
            "error_message": t.error_message,
        }
        for t in tasks
    ]


@app.get("/api/agents/stats/summary", response_model=AgentStatsResponse)
async def get_agent_stats():
    """获取 Agent 统计信息"""
    logger = get_agent_logger()
    stats = logger.get_stats()
    
    return AgentStatsResponse(**stats)


@app.get("/api/agents/{agent_id}/timeline")
async def get_agent_timeline(agent_id: str, limit: int = Query(default=100, ge=1, le=1000)):
    """获取指定 Agent 的 LLM 调用时间轴"""
    logger = get_logger()
    # 查询该 Agent 的所有 LLM 调用日志
    entries = logger.query(agent_id=agent_id, limit=limit)
    
    return {
        "agent_id": agent_id,
        "total_calls": len(entries),
        "timeline": [
            {
                "id": e.id,
                "timestamp": e.timestamp,
                "call_type": e.call_type,
                "model": e.model,
                "status": e.status,
                "success": e.success,
                "latency_ms": e.latency_ms,
                "retry_count": e.retry_count,
            }
            for e in entries
        ]
    }


@app.get("/api/agents/timeline/all")
async def get_all_agents_timeline(limit: int = Query(default=50, ge=1, le=200)):
    """获取所有 Agent 的时间轴（用于 Agent 维度视图）"""
    import os
    logger = get_logger()
    agent_logger = get_agent_logger()
    
    # 调试信息
    db_path = agent_logger.storage.db_path
    print(f"[DEBUG] Agent DB path: {db_path}")
    print(f"[DEBUG] Agent DB exists: {os.path.exists(db_path)}")
    
    # 检查表是否存在和数据量
    try:
        conn = agent_logger.storage._get_conn()
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        print(f"[DEBUG] Tables in DB: {tables}")
        
        if 'agent_executions' in tables:
            count = conn.execute("SELECT COUNT(*) FROM agent_executions").fetchone()[0]
            print(f"[DEBUG] Total rows in agent_executions: {count}")
            
            # 查看前几条记录
            rows = conn.execute("SELECT id, agent_type, status, start_time FROM agent_executions LIMIT 5").fetchall()
            for row in rows:
                print(f"[DEBUG] Row: {row}")
    except Exception as e:
        print(f"[DEBUG] Error checking DB: {e}")
    
    # 首先从 Agent 执行日志中获取所有 Agent
    all_agent_executions = agent_logger.storage.query_executions(limit=1000)
    print(f"[DEBUG] Found {len(all_agent_executions)} agent executions")
    
    result = []
    for agent_exec in all_agent_executions:
        agent_id = agent_exec.agent_id
        # 获取该 Agent 的 LLM 调用
        entries = logger.query(agent_id=agent_id, limit=limit)
        
        result.append({
            "agent_id": agent_id,
            "agent_type": agent_exec.agent_type,
            "target_function": agent_exec.target_function,
            "status": agent_exec.status,
            "total_calls": len(entries),
            "calls": [
                {
                    "id": e.id,
                    "timestamp": e.timestamp,
                    "call_type": e.call_type,
                    "model": e.model,
                    "status": e.status,
                    "success": e.success,
                    "latency_ms": e.latency_ms,
                }
                for e in entries
            ]
        })
    
    # 按最近活动时间排序（有调用的按最后调用时间，没有的按 Agent 开始时间）
    def get_sort_key(x):
        if x["calls"]:
            return x["calls"][0]["timestamp"]
        # 从 Agent 执行记录中获取开始时间
        agent_info = agent_logger.get_execution(x["agent_id"])
        return agent_info.start_time if agent_info else ""
    
    result.sort(key=get_sort_key, reverse=True)
    print(f"[DEBUG] Returning {len(result)} agents for timeline")
    return result


@app.get("/api/agents/active")
async def get_active_agents():
    """获取正在运行的 Agent 列表"""
    logger = get_agent_logger()
    executions = logger.storage.query_executions(
        status="running",
        limit=100
    )
    
    return [
        {
            "agent_id": e.agent_id,
            "agent_type": e.agent_type,
            "target_function": e.target_function,
            "depth": e.depth,
            "start_time": e.start_time,
            "call_stack": e.call_stack,
        }
        for e in executions
    ]


# ============================================================================
# 漏洞管理 API
# ============================================================================

class VulnerabilityResponse(BaseModel):
    """漏洞响应模型"""
    vuln_id: str
    name: str
    type: str
    description: str
    severity: str
    confidence: float
    function_signature: str
    location: str
    file_path: Optional[str]
    line_number: Optional[int]
    data_flow: Dict[str, Any]
    evidence: List[str]
    remediation: Optional[str]
    code_snippet: Optional[str]
    agent_id: Optional[str]
    call_stack: List[str]
    status: str
    created_at: str
    tags: List[str]


class VulnerabilityListResponse(BaseModel):
    """漏洞列表响应"""
    total: int
    items: List[VulnerabilityResponse]
    offset: int
    limit: int


class VulnerabilityStatsResponse(BaseModel):
    """漏洞统计响应"""
    total: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]
    by_type: Dict[str, int]
    by_day: List[Dict[str, Any]]
    by_function: List[Dict[str, Any]]


class VulnerabilityUpdateRequest(BaseModel):
    """漏洞更新请求"""
    status: Optional[str] = None
    verified_by: Optional[str] = None
    verification_note: Optional[str] = None
    tags: Optional[List[str]] = None


@app.get("/api/vulnerabilities", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    severity: Optional[str] = Query(None, description="严重程度过滤 (critical/high/medium/low/info)"),
    status: Optional[str] = Query(None, description="状态过滤 (new/confirmed/false_positive/fixed/ignored)"),
    vuln_type: Optional[str] = Query(None, description="漏洞类型过滤"),
    function_signature: Optional[str] = Query(None, description="函数签名搜索"),
    search: Optional[str] = Query(None, description="关键词搜索"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """获取漏洞列表"""
    manager = get_vuln_manager()
    
    # 解析 severity 参数（支持多个值，用逗号分隔）
    severity_list = severity.split(",") if severity else None
    status_list = status.split(",") if status else None
    
    # 查询漏洞
    records = manager.list_vulnerabilities(
        severity=severity_list,
        status=status_list,
        vuln_type=vuln_type,
        function_signature=function_signature,
        search_keyword=search,
        limit=limit,
        offset=offset,
    )
    
    # 统计总数
    total = manager.storage.count_vulnerabilities(
        severity=severity_list,
        status=status_list,
        vuln_type=vuln_type,
    )
    
    return VulnerabilityListResponse(
        total=total,
        items=[VulnerabilityResponse(**r.to_dict()) for r in records],
        offset=offset,
        limit=limit,
    )


@app.get("/api/vulnerabilities/stats", response_model=VulnerabilityStatsResponse)
async def get_vulnerability_stats():
    """获取漏洞统计信息"""
    manager = get_vuln_manager()
    stats = manager.get_statistics()
    return VulnerabilityStatsResponse(**stats)


@app.get("/api/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability_detail(vuln_id: str):
    """获取单个漏洞详情"""
    manager = get_vuln_manager()
    vuln = manager.get_vulnerability(vuln_id)
    
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    
    return VulnerabilityResponse(**vuln.to_dict())


@app.patch("/api/vulnerabilities/{vuln_id}")
async def update_vulnerability(vuln_id: str, request: VulnerabilityUpdateRequest):
    """更新漏洞信息"""
    manager = get_vuln_manager()
    
    # 检查漏洞是否存在
    vuln = manager.get_vulnerability(vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    
    # 构建更新参数
    update_data = {}
    if request.status:
        update_data["status"] = request.status
    if request.verified_by:
        update_data["verified_by"] = request.verified_by
    if request.verification_note:
        update_data["verification_note"] = request.verification_note
    if request.tags:
        update_data["tags"] = json.dumps(request.tags)
    
    if update_data:
        success = manager.storage.update_vulnerability(vuln_id, **update_data)
        if not success:
            raise HTTPException(status_code=500, detail="更新失败")
    
    # 返回更新后的漏洞
    updated_vuln = manager.get_vulnerability(vuln_id)
    return VulnerabilityResponse(**updated_vuln.to_dict())


@app.delete("/api/vulnerabilities/{vuln_id}")
async def delete_vulnerability(vuln_id: str):
    """删除漏洞"""
    manager = get_vuln_manager()
    
    # 检查漏洞是否存在
    vuln = manager.get_vulnerability(vuln_id)
    if not vuln:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    
    success = manager.storage.delete_vulnerability(vuln_id)
    if not success:
        raise HTTPException(status_code=500, detail="删除失败")
    
    return {"message": "漏洞已删除", "vuln_id": vuln_id}


@app.get("/api/vulnerabilities/types/all")
async def get_vulnerability_types():
    """获取所有漏洞类型"""
    manager = get_vuln_manager()
    stats = manager.get_statistics()
    return {"types": list(stats.get("by_type", {}).keys())}


@app.delete("/api/vulnerabilities")
async def clear_all_vulnerabilities():
    """清除所有漏洞记录"""
    manager = get_vuln_manager()
    
    # 获取清除前的统计
    stats_before = manager.get_statistics()
    total_before = stats_before.get("total", 0)
    
    # 执行清除
    deleted_count = manager.clear_all_vulnerabilities()
    
    return {
        "message": f"已清除 {deleted_count} 个漏洞记录",
        "deleted_count": deleted_count,
        "previous_total": total_before
    }


@app.get("/vulnerabilities", response_class=HTMLResponse)
async def get_vulnerabilities_page():
    """漏洞管理页面"""
    vuln_file = static_dir / "vulnerabilities.html"
    if vuln_file.exists():
        with open(vuln_file, 'r', encoding='utf-8') as f:
            return f.read()
    raise HTTPException(status_code=404, detail="漏洞页面未找到")


# ==================== 静态文件服务 ====================

# 获取静态文件目录
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/", response_class=HTMLResponse)
async def get_index():
    """主页面"""
    index_file = static_dir / "index.html"
    if index_file.exists():
        with open(index_file, 'r', encoding='utf-8') as f:
            return f.read()


@app.get("/redis", response_class=HTMLResponse)
async def get_redis_page():
    """Redis 管理页面"""
    redis_file = static_dir / "redis.html"
    if redis_file.exists():
        with open(redis_file, 'r', encoding='utf-8') as f:
            return f.read()
    raise HTTPException(status_code=404, detail="Redis 页面未找到")
    
    # 默认页面
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>LLM 交互日志可视化系统</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
            h2 { color: #555; margin-top: 30px; }
            .endpoint { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 4px; border-left: 4px solid #007bff; }
            .method { color: #28a745; font-weight: bold; margin-right: 10px; }
            .path { color: #333; font-family: monospace; }
            .description { color: #666; margin-top: 5px; }
            code { background: #e9ecef; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>LLM 交互日志可视化系统</h1>
            <p>系统已启动，API 服务运行正常。</p>
            
            <h2>可用 API 接口</h2>
            
            <div class="endpoint">
                <span class="method">GET</span>
                <span class="path">/api/health</span>
                <div class="description">健康检查</div>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span>
                <span class="path">/api/logs</span>
                <div class="description">获取日志列表（支持分页、筛选）</div>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span>
                <span class="path">/api/logs/{entry_id}</span>
                <div class="description">获取单个日志详情</div>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span>
                <span class="path">/api/sessions</span>
                <div class="description">获取所有会话列表</div>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span>
                <span class="path">/api/stats</span>
                <div class="description">获取统计信息</div>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span>
                <span class="path">/api/stats/timeline</span>
                <div class="description">获取时间线统计</div>
            </div>
            
            <div class="endpoint">
                <span class="method">WS</span>
                <span class="path">/ws</span>
                <div class="description">WebSocket 实时推送</div>
            </div>
            
            <p style="margin-top: 30px; color: #666;">
                前端界面正在开发中，请使用 API 直接访问数据。
            </p>
        </div>
    </body>
    </html>
    """


# 启动函数
def start_server(host: str = "0.0.0.0", port: int = 8080, reload: bool = False):
    """启动 API 服务器"""
    import uvicorn
    uvicorn.run("api:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    start_server()
