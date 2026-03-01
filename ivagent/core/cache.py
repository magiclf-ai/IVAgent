#!/usr/bin/env python3
"""
缓存模块

提供 Redis 缓存实现和分布式锁，支持函数摘要缓存避免冗余计算
"""

from typing import Any, Optional, Union
from enum import Enum
import asyncio
import pickle
import hashlib

from .cli_logger import CLILogger

class AnalysisState(str, Enum):
    """分析状态枚举"""
    PENDING = "pending"      # 等待分析
    ANALYZING = "analyzing"  # 正在分析中
    COMPLETED = "completed"  # 分析完成
    FAILED = "failed"        # 分析失败


class RedisCache:
    """
    Redis 缓存实现
    
    使用 Redis 作为后端存储，支持分布式缓存和并发访问。
    使用 pickle 序列化 Python 对象，支持复杂数据类型。
    """
    
    def __init__(
        self,
        namespace: str = "default",
        ttl: int = 86400,
        host: str = "localhost",
        port: int = 6379,
        db: int = 0,
        password: Optional[str] = None,
        socket_timeout: float = 5.0,
        max_connections: int = 50,
    ):
        super().__init__()
        self.namespace = namespace
        self.ttl = ttl
        self.host = host
        self.port = port
        self.db = db
        self.password = password
        self.socket_timeout = socket_timeout
        self.max_connections = max_connections
        self._redis = None
        self._available_checked = False
        self._available = False
        self._availability_error_logged = False
        self._last_unavailable_message = ""
        self._logger = CLILogger(component="RedisCache")

    def ensure_available(self) -> None:
        """确保 Redis 可用，不可用时给出一次性友好提示并抛错"""
        if self._available_checked and self._available:
            return
        if self._available_checked and not self._available:
            raise RuntimeError(self._last_unavailable_message)
        try:
            client = self._get_redis()
            client.ping()
            self._available_checked = True
            self._available = True
        except Exception as e:
            self._available_checked = True
            self._available = False
            message = (
                f"Redis 未就绪，无法连接 {self.host}:{self.port}。"
                "请先启动 Redis 服务后再运行。"
            )
            detailed = f"{message} 原因: {e}"
            self._last_unavailable_message = detailed
            if not self._availability_error_logged:
                self._logger.error("cache.redis.unavailable", detailed, host=self.host, port=self.port)
                self._availability_error_logged = True
            raise RuntimeError(detailed)
    
    def _make_key(self, key: str) -> str:
        """生成带命名空间的键"""
        return f"{self.namespace}:{key}"
    
    def _get_redis(self):
        """获取 Redis 连接（延迟初始化）"""
        if self._redis is None:
            import redis
            self._redis = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                socket_timeout=self.socket_timeout,
                max_connections=self.max_connections,
                decode_responses=False,
            )
        return self._redis
    
    def get(self, key: str) -> Optional[Any]:
        """获取缓存值"""
        self.ensure_available()
        try:
            full_key = self._make_key(key)
            data = self._get_redis().get(full_key)
            if data is None:
                return None
            return pickle.loads(data)
        except Exception as e:
            self._logger.warning("cache.redis.get_failed", str(e), key=key)
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """设置缓存值"""
        self.ensure_available()
        try:
            full_key = self._make_key(key)
            data = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
            expire = ttl if ttl is not None else self.ttl
            self._get_redis().setex(full_key, expire, data)
            return True
        except Exception as e:
            self._logger.warning("cache.redis.set_failed", str(e), key=key)
            return False
    
    def expire(self, key: str, ttl: Optional[int] = None) -> bool:
        """刷新缓存的 TTL"""
        self.ensure_available()
        try:
            full_key = self._make_key(key)
            expire = ttl if ttl is not None else self.ttl
            result = self._get_redis().expire(full_key, expire)
            return bool(result)
        except Exception as e:
            self._logger.warning("cache.redis.expire_failed", str(e), key=key)
            return False
    
    def delete(self, key: str) -> bool:
        """删除缓存值"""
        self.ensure_available()
        try:
            full_key = self._make_key(key)
            self._get_redis().delete(full_key)
            return True
        except Exception as e:
            self._logger.warning("cache.redis.delete_failed", str(e), key=key)
            return False
    
    def exists(self, key: str) -> bool:
        """检查键是否存在"""
        self.ensure_available()
        try:
            full_key = self._make_key(key)
            return self._get_redis().exists(full_key) > 0
        except Exception as e:
            self._logger.warning("cache.redis.exists_failed", str(e), key=key)
            return False
    
    def clear(self) -> bool:
        """清空命名空间下的所有缓存"""
        self.ensure_available()
        try:
            pattern = f"{self.namespace}:*"
            redis_client = self._get_redis()
            for key in redis_client.scan_iter(match=pattern):
                redis_client.delete(key)
            return True
        except Exception as e:
            self._logger.warning("cache.redis.clear_failed", str(e))
            return False


class FunctionSummaryCache:
    """
    函数摘要专用缓存管理器（基于 Redis 分布式锁）
    
    使用 Redis 分布式锁实现跨进程/跨客户端的并发控制。
    """
    
    def __init__(
        self,
        cache: RedisCache,
        namespace: str = "func_summary",
        default_ttl: int = 3600,
        lock_timeout: int = 600,
        wait_interval: float = 1.0,
        max_wait_time: float = 600.0,
        verbose: bool = False,
    ):
        if not isinstance(cache, RedisCache):
            raise ValueError("FunctionSummaryCache requires RedisCache")
        
        self.cache = cache
        self.namespace = namespace
        self.default_ttl = default_ttl
        # 锁超时时间应该足够长，避免分析过程中锁过期
        # 默认 10 分钟，应该覆盖大多数分析场景
        self.lock_timeout = lock_timeout
        self.wait_interval = wait_interval
        self.max_wait_time = max_wait_time
        self.verbose = verbose
        self._logger = CLILogger(component="SummaryCache", verbose=verbose)
    
    def log(self, message: str, level: str = "INFO"):
        """打印日志（统一日志格式）"""
        if not self.verbose:
            return
        self._logger.log(level=level, event="cache.summary.event", message=message)
    
    def _generate_cache_key(self, function_identifier: str, context_hash: Optional[str] = None) -> str:
        """
        生成缓存键
        
        使用可读的函数标识符作为键，便于调试和维护。
        对特殊字符进行清理，确保键的合法性。
        """
        # 清理函数标识符中的特殊字符，使其适合作为 Redis 键
        # 替换空格、换行、制表符等空白字符为下划线
        import re
        clean_sig = re.sub(r'\s+', '_', function_identifier.strip())
        
        # 如果签名太长，使用前缀+哈希的方式
        max_len = 200
        if len(clean_sig) > max_len:
            short_hash = hashlib.md5(clean_sig.encode()).hexdigest()[:16]
            clean_sig = clean_sig[:max_len] + f"_{short_hash}"
        
        if context_hash:
            return f"{clean_sig}:{context_hash}"
        return clean_sig
    
    def _make_status_key(self, cache_key: str) -> str:
        """生成状态键"""
        return f"{self.namespace}:status:{cache_key}"
    
    def _make_lock_key(self, cache_key: str) -> str:
        """生成锁键"""
        return f"{self.namespace}:lock:{cache_key}"
    
    def _get_status(self, status_key: str) -> Optional[AnalysisState]:
        """获取分析状态"""
        self.cache.ensure_available()
        status = self.cache._get_redis().get(status_key)
        if status:
            return AnalysisState(status.decode() if isinstance(status, bytes) else status)
        return None
    
    def _set_status(self, status_key: str, state: AnalysisState, ttl: Optional[int] = None, nx: bool = False) -> bool:
        """设置分析状态
        
        Args:
            nx: 只有当 key 不存在时才设置（用于避免覆盖其他进程的状态）
        """
        try:
            self.cache.ensure_available()
            expire = ttl if ttl is not None else self.lock_timeout + 60
            redis_client = self.cache._get_redis()
            if nx:
                # 只有 key 不存在时才设置
                result = redis_client.set(status_key, state.value, ex=expire, nx=True)
                return result is not None
            else:
                redis_client.setex(status_key, expire, state.value)
                return True
        except Exception as e:
            self._logger.warning("cache.summary.set_status_failed", str(e), status_key=status_key)
            return False
    
    def _delete_status(self, status_key: str) -> bool:
        """删除分析状态"""
        try:
            self.cache.ensure_available()
            self.cache._get_redis().delete(status_key)
            return True
        except Exception as e:
            self._logger.warning("cache.summary.delete_status_failed", str(e), status_key=status_key)
            return False
    
    def _acquire_lock(self, lock_key: str):
        """获取分布式锁，返回锁对象或 None"""
        try:
            self.cache.ensure_available()
            lock = self.cache._get_redis().lock(
                lock_key,
                timeout=self.lock_timeout,
                blocking_timeout=0,  # 非阻塞
            )
            if lock.acquire():
                return lock
            return None
        except Exception as e:
            self._logger.warning("cache.summary.acquire_lock_failed", str(e), lock_key=lock_key)
            return None
    
    def _release_lock(self, lock) -> bool:
        """释放分布式锁"""
        try:
            lock.release()
            return True
        except Exception as e:
            self._logger.warning("cache.summary.release_lock_failed", str(e))
            return False
    
    def get(self, function_identifier: str, context_hash: Optional[str] = None) -> Optional[Any]:
        """获取函数摘要缓存"""
        cache_key = self._generate_cache_key(function_identifier, context_hash)
        return self.cache.get(cache_key)
    
    def set(self, function_identifier: str, value: Any, context_hash: Optional[str] = None, ttl: Optional[int] = None) -> bool:
        """设置函数摘要缓存"""
        cache_key = self._generate_cache_key(function_identifier, context_hash)
        return self.cache.set(cache_key, value, ttl or self.default_ttl)
    
    def refresh_ttl(self, function_identifier: str, context_hash: Optional[str] = None, ttl: Optional[int] = None) -> bool:
        """
        刷新函数摘要缓存的 TTL
        
        在缓存命中时调用，延长缓存的存活时间。
        使用默认 TTL 或指定的 TTL。
        """
        cache_key = self._generate_cache_key(function_identifier, context_hash)
        return self.cache.expire(cache_key, ttl or self.default_ttl)
    
    async def get_or_compute(
        self,
        function_identifier: str,
        compute_func,
        context_hash: Optional[str] = None,
        ttl: Optional[int] = None,
        compute_timeout: float = 1200.0,  # 计算函数超时时间（秒）
    ) -> Any:
        """
        获取或计算函数摘要
        
        使用 Redis 分布式锁实现跨客户端的并发控制。
        添加 compute_func 超时控制，防止因 RPC 卡住导致锁长期持有。
        """
        cache_key = self._generate_cache_key(function_identifier, context_hash)
        status_key = self._make_status_key(cache_key)
        lock_key = self._make_lock_key(cache_key)
        
        # 步骤1: 检查缓存
        cached = self.get(function_identifier, context_hash)
        if cached is not None:
            self.log(f"Cache hit for {function_identifier}", "DEBUG")
            # 刷新缓存 TTL，延长存活时间
            self.refresh_ttl(function_identifier, context_hash, ttl)
            return cached
        
        # 步骤2: 检查状态并等待或执行
        wait_time = 0.0
        while wait_time < self.max_wait_time:
            status = self._get_status(status_key)
            
            if status == AnalysisState.ANALYZING:
                self.log(f"Waiting for ongoing analysis: {function_identifier}", "DEBUG")
                await asyncio.sleep(self.wait_interval)
                wait_time += self.wait_interval
                
                # 再次检查缓存
                cached = self.get(function_identifier, context_hash)
                if cached is not None:
                    self.log(f"Cache hit after waiting: {function_identifier}", "DEBUG")
                    # 刷新缓存 TTL
                    self.refresh_ttl(function_identifier, context_hash, ttl)
                    return cached
                continue
            
            elif status == AnalysisState.COMPLETED:
                cached = self.get(function_identifier, context_hash)
                if cached is not None:
                    self.log(f"Cache hit (status=completed): {function_identifier}", "DEBUG")
                    # 刷新缓存 TTL
                    self.refresh_ttl(function_identifier, context_hash, ttl)
                    return cached
                # 缓存丢失，重新分析
                self.log(f"Cache lost (status=completed but no data), retrying: {function_identifier}", "DEBUG")
                self._delete_status(status_key)
            
            elif status == AnalysisState.FAILED:
                self.log(f"Previous analysis failed, retrying: {function_identifier}", "WARNING")
                self._delete_status(status_key)
            
            # 尝试获取分布式锁执行分析
            lock = self._acquire_lock(lock_key)
            
            if lock is None:
                # 获取锁失败，等待后重试
                await asyncio.sleep(self.wait_interval)
                wait_time += self.wait_interval
                continue
            
            # 获取锁成功，执行分析
            try:
                # 双重检查缓存
                cached = self.get(function_identifier, context_hash)
                if cached is not None:
                    self.log(f"Cache hit (double-check): {function_identifier}", "DEBUG")
                    # 刷新缓存 TTL
                    self.refresh_ttl(function_identifier, context_hash, ttl)
                    return cached
                
                # 设置状态为分析中（只有不存在时才设置，避免覆盖其他进程）
                if not self._set_status(status_key, AnalysisState.ANALYZING, nx=True):
                    # 状态已存在，说明其他进程在分析，释放锁并等待
                    try:
                        self._release_lock(lock)
                    except Exception:
                        pass  # 锁可能已经过期，忽略错误
                    await asyncio.sleep(self.wait_interval)
                    wait_time += self.wait_interval
                    continue
                
                self.log(f"Starting analysis: {function_identifier}", "DEBUG")
                
                # 执行分析（compute_func 是异步函数），添加超时控制
                try:
                    result = await asyncio.wait_for(
                        compute_func(),
                        timeout=compute_timeout
                    )
                except asyncio.TimeoutError:
                    self._set_status(status_key, AnalysisState.FAILED, ttl=300)
                    self.log(f"Analysis timeout after {compute_timeout}s: {function_identifier}", "ERROR")
                    raise RuntimeError(f"Analysis timeout for {function_identifier} after {compute_timeout}s")
                
                # 缓存结果
                self.set(function_identifier, result, context_hash, ttl)
                
                # 更新状态为完成（延长 TTL，避免过早过期）
                self._set_status(status_key, AnalysisState.COMPLETED, ttl=3600)
                
                self.log(f"Analysis completed: {function_identifier}", "DEBUG")
                return result
                
            except Exception as e:
                # 只在不是超时错误时设置失败状态（超时错误已设置）
                if not isinstance(e, RuntimeError) or "timeout" not in str(e).lower():
                    self._set_status(status_key, AnalysisState.FAILED, ttl=300)
                self.log(f"Analysis failed: {function_identifier} - {e}", "ERROR")
                raise
                
            finally:
                # 安全释放锁（锁可能已经过期被 Redis 删除）
                try:
                    self._release_lock(lock)
                except Exception:
                    # 锁已经过期或不存在，忽略错误
                    pass
        
        # 超时，最后尝试直接计算
        self.log(f"Wait timeout, computing directly: {function_identifier}", "WARNING")
        return await asyncio.wait_for(compute_func(), timeout=compute_timeout)


def get_cache(
    cache_type: str = "redis",
    namespace: str = "default",
    ttl: int = 86400,
    **kwargs
) -> RedisCache:
    """
    获取缓存实例的工厂函数
    
    参数:
        cache_type: 缓存类型（仅支持 "redis"）
        namespace: 命名空间
        ttl: 默认过期时间（秒）
        **kwargs: Redis 连接参数
            - host: Redis 服务器地址 (默认: localhost)
            - port: Redis 服务器端口 (默认: 6379)
            - db: Redis 数据库编号 (默认: 0)
            - password: Redis 密码
            - max_connections: 最大连接数 (默认: 50)
    
    返回:
        RedisCache 实例
    
    示例:
        >>> cache = get_cache("redis", namespace="vuln_scan", host="localhost", port=6379)
    """
    if cache_type == "redis":
        return RedisCache(namespace=namespace, ttl=ttl, **kwargs)
    else:
        raise ValueError(f"Unknown cache type: {cache_type}. Use 'redis'.")
