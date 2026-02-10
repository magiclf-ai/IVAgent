#!/usr/bin/env python3
"""
Redis 缓存管理 API

提供 Redis 缓存的可视化管理接口，支持搜索、查看、删除等操作
"""

import json
import pickle
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

import sys
from pathlib import Path

# 添加项目根目录到路径以支持 ivagent 导入
script_dir = Path(__file__).parent.parent.parent  # hexray_scripts 目录
sys.path.insert(0, str(script_dir))

from ivagent.core.cache import RedisCache, get_cache

# 导入模型类以确保 pickle 能正确反序列化
try:
    from ivagent.models.function import SimpleFunctionSummary
except ImportError:
    SimpleFunctionSummary = None


# 创建路由器
redis_router = APIRouter(prefix="/api/redis", tags=["Redis缓存管理"])


# ============ 数据模型 ============

class RedisConnectionConfig(BaseModel):
    """Redis 连接配置"""
    host: str = Field(default="localhost", description="Redis服务器地址")
    port: int = Field(default=6379, description="Redis服务器端口")
    db: int = Field(default=0, description="数据库编号")
    password: Optional[str] = Field(default=None, description="密码")


class RedisKeyInfo(BaseModel):
    """Redis 键信息"""
    key: str
    type: str
    ttl: int = -1
    size: int = 0
    expires_at: Optional[str] = None


class RedisKeyValue(BaseModel):
    """Redis 键值详情"""
    key: str
    type: str
    ttl: int
    size: int
    value: Any
    expires_at: Optional[str] = None


class RedisStats(BaseModel):
    """Redis 统计信息"""
    connected: bool
    total_keys: int
    memory_used: str
    memory_used_bytes: int
    key_types: Dict[str, int]
    namespaces: Dict[str, int]


class KeySearchRequest(BaseModel):
    """键搜索请求"""
    pattern: str = Field(default="*")
    namespace: Optional[str] = None
    key_type: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class KeyDeleteRequest(BaseModel):
    """键删除请求"""
    keys: List[str]


class TTLUpdateRequest(BaseModel):
    """TTL 更新请求"""
    key: str
    ttl: int = Field(..., ge=-1)


# ============ 全局缓存实例 ============

_cache_instances: Dict[str, RedisCache] = {}
_current_config: Dict[str, Any] = {
    "host": "localhost",
    "port": 6379,
    "db": 0,
    "password": None
}


def get_redis_cache(config: Optional[Dict] = None) -> RedisCache:
    """获取 Redis 缓存实例"""
    global _cache_instances, _current_config
    
    if config:
        _current_config.update(config)
    
    config_key = f"{_current_config['host']}:{_current_config['port']}:{_current_config['db']}"
    
    if config_key not in _cache_instances:
        _cache_instances[config_key] = RedisCache(
            namespace="admin",
            host=_current_config['host'],
            port=_current_config['port'],
            db=_current_config['db'],
            password=_current_config['password']
        )
    
    return _cache_instances[config_key]


def _get_raw_redis(config: Optional[Dict] = None):
    """获取原始 Redis 连接"""
    cache = get_redis_cache(config)
    return cache._get_redis()


def _format_bytes(size: int) -> str:
    """格式化字节大小"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def _safe_decode(value: Any, key: Optional[str] = None) -> Dict[str, Any]:
    """安全解码 Redis 值，返回包含原始值和反序列化后值的对象"""
    result = {
        "raw_type": "bytes",
        "raw_value": None,
        "decoded_value": None,
        "decode_method": None,
        "is_binary": False,
        "decode_errors": []
    }
    
    if not isinstance(value, bytes):
        result["raw_type"] = type(value).__name__
        result["decoded_value"] = value
        result["decode_method"] = "native"
        return result
    
    # 保存原始值的 hex 表示（用于二进制数据）
    result["raw_value"] = value.hex()
    
    # 尝试 pickle 反序列化
    try:
        decoded = pickle.loads(value)
        result["decoded_value"] = decoded
        result["decode_method"] = "pickle"
        result["raw_type"] = type(decoded).__name__
        return result
    except Exception as e:
        result["decode_errors"].append(f"pickle: {str(e)}")
    
    # 尝试 JSON 解码
    try:
        decoded = json.loads(value.decode('utf-8'))
        result["decoded_value"] = decoded
        result["decode_method"] = "json"
        result["raw_type"] = type(decoded).__name__
        return result
    except Exception as e:
        result["decode_errors"].append(f"json: {str(e)}")
    
    # 尝试 UTF-8 解码
    try:
        decoded = value.decode('utf-8')
        result["decoded_value"] = decoded
        result["decode_method"] = "utf-8"
        result["raw_type"] = "str"
        return result
    except Exception as e:
        result["decode_errors"].append(f"utf-8: {str(e)}")
    
    # 无法解码，标记为二进制
    result["decoded_value"] = value.hex()
    result["decode_method"] = "hex"
    result["is_binary"] = True
    result["raw_type"] = "binary"
    return result


def _format_value_for_display(value_info: Dict[str, Any], key: Optional[str] = None) -> Dict[str, Any]:
    """格式化值用于前端展示"""
    decoded = value_info.get("decoded_value")
    method = value_info.get("decode_method")
    
    # 识别特定数据类型并添加类型标识
    data_type = _identify_data_type(decoded, key)
    
    # 处理 dataclass 对象（如 SimpleFunctionSummary）
    if hasattr(decoded, '__dataclass_fields__'):
        try:
            import dataclasses
            dict_value = dataclasses.asdict(decoded)
            
            return {
                "type": "structured",
                "format": "dataclass",
                "value": dict_value,
                "preview": _truncate_preview(dict_value),
                "size": len(str(dict_value)),
                "data_type": data_type or type(decoded).__name__,
                "is_dataclass": True
            }
        except Exception as e:
            # 转换失败时，返回原始值的字符串表示
            return {
                "type": "object",
                "format": method,
                "value": str(decoded),
                "preview": str(decoded)[:500],
                "truncated": len(str(decoded)) > 500,
                "class_name": type(decoded).__name__ if decoded else "unknown",
                "data_type": data_type,
                "conversion_error": str(e)
            }
    
    # 处理大型数据结构
    if isinstance(decoded, (dict, list, tuple, set)):
        return {
            "type": "structured",
            "format": method,
            "value": decoded,
            "preview": _truncate_preview(decoded),
            "size": len(str(decoded)),
            "data_type": data_type
        }
    
    # 处理字符串
    if isinstance(decoded, str):
        return {
            "type": "text",
            "format": method,
            "value": decoded,
            "preview": decoded[:500] if len(decoded) > 500 else decoded,
            "truncated": len(decoded) > 500,
            "size": len(decoded),
            "data_type": data_type
        }
    
    # 处理数字
    if isinstance(decoded, (int, float)):
        return {
            "type": "number",
            "format": method,
            "value": decoded,
            "preview": str(decoded),
            "data_type": data_type
        }
    
    # 处理布尔值
    if isinstance(decoded, bool):
        return {
            "type": "boolean",
            "format": method,
            "value": decoded,
            "preview": str(decoded),
            "data_type": data_type
        }
    
    # 处理 None
    if decoded is None:
        return {
            "type": "null",
            "format": method,
            "value": None,
            "preview": "null",
            "data_type": data_type
        }
    
    # 其他类型（如自定义对象）
    return {
        "type": "object",
        "format": method,
        "value": str(decoded),
        "preview": str(decoded)[:500],
        "truncated": len(str(decoded)) > 500,
        "class_name": type(decoded).__name__,
        "data_type": data_type
    }


def _identify_data_type(value: Any, key: Optional[str] = None) -> Optional[str]:
    """识别特定数据类型"""
    if value is None:
        return None
    
    # 根据 key 前缀识别类型
    if key and key.startswith('func_summary:'):
        # 区分状态 key 和函数摘要 key
        if ':status:' in key:
            return 'analysis_state'
        # 真正的函数摘要 key: func_summary:<function_name>
        # 不是 func_summary:status: 或 func_summary:lock:
        if not any(x in key for x in [':status:', ':lock:']):
            return 'function_summary'
    
    # 识别 SimpleFunctionSummary
    if hasattr(value, '__dataclass_fields__'):
        class_name = type(value).__name__
        if class_name == 'SimpleFunctionSummary':
            return 'function_summary'
        return f'dataclass:{class_name}'
    
    # 识别字典类型的 SimpleFunctionSummary
    if isinstance(value, dict):
        if 'function_signature' in value and 'behavior_summary' in value:
            return 'function_summary_dict'
        if 'vuln_type' in value and 'description' in value:
            return 'vulnerability_dict'
    
    # 识别分析状态
    if isinstance(value, str):
        if value in ['pending', 'analyzing', 'completed', 'failed']:
            return 'analysis_state'
    
    return None


def _truncate_preview(data: Any, max_length: int = 200) -> str:
    """截断预览文本"""
    text = str(data)
    if len(text) <= max_length:
        return text
    return text[:max_length] + "..."


def _decode_redis_value(raw_value: Any, key: Optional[str] = None) -> Any:
    """解码 Redis 值为可序列化的格式"""
    if isinstance(raw_value, dict):
        return {k.decode('utf-8') if isinstance(k, bytes) else k: _decode_redis_value(v, key) 
                for k, v in raw_value.items()}
    elif isinstance(raw_value, list):
        return [_decode_redis_value(v, key) for v in raw_value]
    elif isinstance(raw_value, set):
        return [_decode_redis_value(v, key) for v in raw_value]
    elif isinstance(raw_value, tuple):
        return tuple(_decode_redis_value(v, key) for v in raw_value)
    elif isinstance(raw_value, bytes):
        info = _safe_decode(raw_value, key)
        return _format_value_for_display(info, key)
    else:
        return raw_value


# ============ API 路由 ============

@redis_router.post("/connect")
async def connect_redis(config: RedisConnectionConfig):
    """连接/切换 Redis 服务器"""
    try:
        cache = get_redis_cache({
            "host": config.host,
            "port": config.port,
            "db": config.db,
            "password": config.password
        })
        
        # 测试连接
        redis_client = cache._get_redis()
        redis_client.ping()
        
        info = redis_client.info()
        
        return {
            "success": True,
            "message": f"成功连接到 {config.host}:{config.port}/{config.db}",
            "server_version": info.get("redis_version", "unknown"),
            "mode": info.get("redis_mode", "standalone")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"连接失败: {str(e)}")


@redis_router.get("/stats")
async def get_stats():
    """获取 Redis 统计信息"""
    try:
        redis_client = _get_raw_redis()
        
        # 基础信息
        info = redis_client.info()
        
        # 获取所有键
        all_keys = list(redis_client.scan_iter(count=10000))
        total_keys = len(all_keys)
        
        # 统计键类型
        key_types = {}
        namespaces = {}
        sample_keys = []
        
        for i, key in enumerate(all_keys):
            key_str = key.decode('utf-8') if isinstance(key, bytes) else key
            key_type = redis_client.type(key).decode('utf-8') if isinstance(redis_client.type(key), bytes) else redis_client.type(key)
            key_types[key_type] = key_types.get(key_type, 0) + 1
            
            # 统计命名空间
            if ':' in key_str:
                ns = key_str.split(':')[0]
                namespaces[ns] = namespaces.get(ns, 0) + 1
            
            # 收集样本键（用于调试）
            if len(sample_keys) < 20:
                sample_keys.append(key_str)
        
        memory_info = redis_client.info('memory')
        used_memory = memory_info.get('used_memory', 0)
        
        return RedisStats(
            connected=True,
            total_keys=total_keys,
            memory_used=_format_bytes(used_memory),
            memory_used_bytes=used_memory,
            key_types=key_types,
            namespaces=namespaces
        )
    except Exception as e:
        return RedisStats(
            connected=False,
            total_keys=0,
            memory_used="0 B",
            memory_used_bytes=0,
            key_types={},
            namespaces={}
        )


@redis_router.post("/keys/search")
async def search_keys(request: KeySearchRequest):
    """搜索 Redis 键"""
    try:
        redis_client = _get_raw_redis()
        
        # 构建搜索模式
        pattern = request.pattern
        if request.namespace:
            pattern = f"{request.namespace}:{pattern}"
        
        # 扫描键
        keys = []
        for key in redis_client.scan_iter(match=pattern, count=1000):
            key_str = key.decode('utf-8') if isinstance(key, bytes) else key
            
            # 获取键信息
            key_type = redis_client.type(key)
            key_type = key_type.decode('utf-8') if isinstance(key_type, bytes) else key_type
            
            # 过滤类型
            if request.key_type and key_type != request.key_type:
                continue
            
            ttl = redis_client.ttl(key)
            
            # 计算大小
            size = 0
            try:
                if key_type == 'string':
                    size = len(redis_client.get(key) or b'')
                elif key_type == 'hash':
                    size = redis_client.hlen(key)
                elif key_type == 'list':
                    size = redis_client.llen(key)
                elif key_type == 'set':
                    size = redis_client.scard(key)
                elif key_type == 'zset':
                    size = redis_client.zcard(key)
            except:
                pass
            
            expires_at = None
            if ttl > 0:
                expires_at = datetime.fromtimestamp(datetime.now().timestamp() + ttl).isoformat()
            
            keys.append(RedisKeyInfo(
                key=key_str,
                type=key_type,
                ttl=ttl,
                size=size,
                expires_at=expires_at
            ))
        
        # 分页
        total = len(keys)
        keys = keys[request.offset:request.offset + request.limit]
        
        return {
            "keys": keys,
            "total": total,
            "offset": request.offset,
            "limit": request.limit
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"搜索失败: {str(e)}")


@redis_router.get("/keys/{key:path}")
async def get_key_value(key: str):
    """获取键值详情"""
    try:
        redis_client = _get_raw_redis()
        
        # 获取键类型
        key_type = redis_client.type(key)
        key_type = key_type.decode('utf-8') if isinstance(key_type, bytes) else key_type
        
        if key_type == 'none':
            raise HTTPException(status_code=404, detail="键不存在")
        
        # 获取 TTL
        ttl = redis_client.ttl(key)
        
        # 获取值
        value = None
        size = 0
        raw_bytes = b''
        
        if key_type == 'string':
            raw_value = redis_client.get(key)
            if raw_value:
                raw_bytes = raw_value if isinstance(raw_value, bytes) else str(raw_value).encode()
                size = len(raw_bytes)
                value = _decode_redis_value(raw_value, key)
            
        elif key_type == 'hash':
            raw_value = redis_client.hgetall(key)
            size = len(raw_value)
            value = {}
            for k, v in raw_value.items():
                k_str = k.decode('utf-8') if isinstance(k, bytes) else k
                value[k_str] = _decode_redis_value(v, key)
            
        elif key_type == 'list':
            raw_value = redis_client.lrange(key, 0, -1)
            size = len(raw_value)
            value = [_decode_redis_value(v, key) for v in raw_value]
            
        elif key_type == 'set':
            raw_value = redis_client.smembers(key)
            size = len(raw_value)
            value = [_decode_redis_value(v, key) for v in raw_value]
            
        elif key_type == 'zset':
            raw_value = redis_client.zrange(key, 0, -1, withscores=True)
            size = len(raw_value)
            value = []
            for member, score in raw_value:
                member_decoded = _decode_redis_value(member, key)
                value.append({
                    "member": member_decoded,
                    "score": score
                })
        
        expires_at = None
        if ttl > 0:
            expires_at = datetime.fromtimestamp(datetime.now().timestamp() + ttl).isoformat()
        
        return {
            "key": key,
            "type": key_type,
            "ttl": ttl,
            "size": size,
            "value": value,
            "expires_at": expires_at,
            "raw_size": len(raw_bytes) if isinstance(raw_bytes, bytes) else size
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取键值失败: {str(e)}")


@redis_router.delete("/keys")
async def delete_keys(request: KeyDeleteRequest):
    """删除指定键"""
    try:
        redis_client = _get_raw_redis()
        deleted = 0
        
        for key in request.keys:
            result = redis_client.delete(key)
            deleted += result
        
        return {"deleted": deleted, "requested": len(request.keys)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"删除失败: {str(e)}")


@redis_router.delete("/flush")
async def flush_database(confirm: str = Query(default="DELETE ALL", description="确认码，必须为 'DELETE ALL'")):
    """清空当前数据库中的所有键（危险操作）"""
    if confirm != "DELETE ALL":
        raise HTTPException(status_code=400, detail="确认码错误")
    
    try:
        redis_client = _get_raw_redis()
        
        # 获取删除前的键数
        key_count = redis_client.dbsize()
        
        # 执行 FLUSHDB 清空当前数据库
        redis_client.flushdb()
        
        return {
            "success": True,
            "deleted": key_count,
            "message": f"已清空当前数据库，共删除 {key_count} 个键"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"清空数据库失败: {str(e)}")


@redis_router.delete("/namespace/{namespace}")
async def delete_namespace(namespace: str, confirm: bool = False):
    """删除整个命名空间的所有键"""
    if not confirm:
        raise HTTPException(status_code=400, detail="请设置 confirm=true 确认删除")
    
    try:
        redis_client = _get_raw_redis()
        pattern = f"{namespace}:*"
        
        deleted = 0
        for key in redis_client.scan_iter(match=pattern):
            redis_client.delete(key)
            deleted += 1
        
        return {"deleted": deleted, "namespace": namespace}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"删除命名空间失败: {str(e)}")


@redis_router.put("/keys/ttl")
async def update_ttl(request: TTLUpdateRequest):
    """更新键的 TTL"""
    try:
        redis_client = _get_raw_redis()
        
        if request.ttl < 0:
            # 移除过期时间
            redis_client.persist(request.key)
        else:
            redis_client.expire(request.key, request.ttl)
        
        new_ttl = redis_client.ttl(request.key)
        return {"key": request.key, "ttl": new_ttl}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"更新 TTL 失败: {str(e)}")


@redis_router.get("/namespaces")
async def get_namespaces():
    """获取所有命名空间"""
    try:
        redis_client = _get_raw_redis()
        namespaces = set()
        
        for key in redis_client.scan_iter(count=10000):
            key_str = key.decode('utf-8') if isinstance(key, bytes) else key
            if ':' in key_str:
                namespaces.add(key_str.split(':')[0])
        
        return {"namespaces": sorted(list(namespaces))}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"获取命名空间失败: {str(e)}")
