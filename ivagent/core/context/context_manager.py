#!/usr/bin/env python3
"""
ContextManager - 上下文管理器

核心职责：
- 上下文生命周期管理
- 文件引用管理
- 压缩策略调度
- 跨 Agent 上下文共享
"""

from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass
import json
import time
import uuid


@dataclass
class ContextReference:
    """上下文引用"""
    ref_id: str
    ref_type: str  # "file", "summary", "compressed"
    file_path: str
    summary: str
    metadata: Dict[str, Any]
    importance: float  # 0-1，重要性评分
    created_at: float
    accessed_at: float
    access_count: int


class ContextManager:
    """
    上下文管理器
    
    核心职责：
    - 文件化存储所有大文本
    - 生成和管理引用
    - 智能压缩和摘要
    - 上下文检索和组装
    """
    
    def __init__(
        self,
        session_id: str,
        base_dir: Path,
        max_context_tokens: int = 100000,
        compression_threshold: int = 2000,
    ):
        self.session_id = session_id
        self.base_dir = Path(base_dir) / session_id
        self.max_context_tokens = max_context_tokens
        self.compression_threshold = compression_threshold
        
        # 初始化子目录
        self.raw_dir = self.base_dir / "raw"
        self.compressed_dir = self.base_dir / "compressed"
        self.summary_dir = self.base_dir / "summary"
        self.metadata_dir = self.base_dir / "metadata"
        
        for d in [self.raw_dir, self.compressed_dir, 
                  self.summary_dir, self.metadata_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        # 引用索引
        self.references: Dict[str, ContextReference] = {}
        self._load_references()
    
    def store_content(
        self,
        content: str,
        content_type: str,
        metadata: Optional[Dict[str, Any]] = None,
        importance: float = 0.5,
    ) -> ContextReference:
        """
        存储内容并返回引用
        
        Args:
            content: 待存储内容
            content_type: 内容类型（message, tool_output, code, etc.）
            metadata: 元数据
            importance: 重要性评分（0-1）
        
        Returns:
            ContextReference: 上下文引用
        """
        # 生成引用ID
        ref_id = self._generate_ref_id(content_type)
        
        # 存储原始内容
        raw_path = self.raw_dir / f"{ref_id}.txt"
        raw_path.write_text(content, encoding="utf-8")
        
        # 判断是否需要压缩
        if len(content) > self.compression_threshold:
            compressed = self._compress_content(content, content_type)
            compressed_path = self.compressed_dir / f"{ref_id}.json"
            compressed_path.write_text(
                json.dumps(compressed, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
        
        # 生成摘要
        summary = self._generate_summary(content, content_type, metadata)
        summary_path = self.summary_dir / f"{ref_id}_summary.txt"
        summary_path.write_text(summary, encoding="utf-8")
        
        # 创建引用
        ref = ContextReference(
            ref_id=ref_id,
            ref_type=content_type,
            file_path=str(raw_path),
            summary=summary,
            metadata=metadata or {},
            importance=importance,
            created_at=time.time(),
            accessed_at=time.time(),
            access_count=0,
        )
        
        self.references[ref_id] = ref
        self._save_references()
        
        return ref
    
    def retrieve_content(
        self,
        ref_id: str,
        use_compressed: bool = False,
    ) -> str:
        """
        检索内容
        
        Args:
            ref_id: 引用ID
            use_compressed: 是否使用压缩版本
        
        Returns:
            内容字符串
        """
        if ref_id not in self.references:
            return f"[错误] 引用不存在: {ref_id}"
        
        ref = self.references[ref_id]
        ref.accessed_at = time.time()
        ref.access_count += 1
        
        if use_compressed:
            compressed_path = self.compressed_dir / f"{ref_id}.json"
            if compressed_path.exists():
                return compressed_path.read_text(encoding="utf-8")
        
        return Path(ref.file_path).read_text(encoding="utf-8")
    
    def build_context(
        self,
        task_type: str,
        recent_refs: List[str],
        max_tokens: Optional[int] = None,
    ) -> str:
        """
        构建上下文
        
        根据任务类型和引用列表，智能组装上下文。
        
        Args:
            task_type: 任务类型（code_exploration, vuln_analysis）
            recent_refs: 最近的引用ID列表
            max_tokens: 最大token数
        
        Returns:
            组装后的上下文字符串
        """
        max_tokens = max_tokens or self.max_context_tokens
        
        # 按重要性和时间排序
        sorted_refs = self._sort_references(recent_refs)
        
        # 组装上下文
        context_parts = []
        current_tokens = 0
        
        for ref_id in sorted_refs:
            if ref_id not in self.references:
                continue
            
            ref = self.references[ref_id]
            
            # 优先使用摘要
            summary = ref.summary
            summary_tokens = self._estimate_tokens(summary)
            
            if current_tokens + summary_tokens <= max_tokens:
                context_parts.append(self._format_reference(ref, use_summary=True))
                current_tokens += summary_tokens
            else:
                break
        
        return "\n\n".join(context_parts)
    
    def _generate_ref_id(self, content_type: str) -> str:
        """生成引用ID"""
        timestamp = int(time.time() * 1000)
        unique_id = uuid.uuid4().hex[:8]
        return f"{content_type}_{timestamp}_{unique_id}"
    
    def _compress_content(self, content: str, content_type: str) -> Dict[str, Any]:
        """压缩内容（简单实现）"""
        # TODO: 实现更复杂的压缩策略
        lines = content.split('\n')
        return {
            "type": content_type,
            "total_lines": len(lines),
            "preview": '\n'.join(lines[:50]),
            "compressed": True,
        }
    
    def _generate_summary(
        self,
        content: str,
        content_type: str,
        metadata: Optional[Dict[str, Any]]
    ) -> str:
        """生成摘要（简单实现）"""
        # TODO: 使用 LLM 生成更智能的摘要
        lines = content.split('\n')
        preview = '\n'.join(lines[:5])
        return f"[{content_type}] {len(content)} 字符, {len(lines)} 行\n预览:\n{preview}"
    
    def _sort_references(self, ref_ids: List[str]) -> List[str]:
        """按重要性和时间排序引用"""
        valid_refs = [(ref_id, self.references[ref_id]) 
                      for ref_id in ref_ids 
                      if ref_id in self.references]
        
        # 按重要性降序，时间降序
        sorted_refs = sorted(
            valid_refs,
            key=lambda x: (x[1].importance, x[1].created_at),
            reverse=True
        )
        
        return [ref_id for ref_id, _ in sorted_refs]
    
    def _estimate_tokens(self, text: str) -> int:
        """估算token数（简单实现）"""
        # 粗略估算：1 token ≈ 4 字符
        return len(text) // 4
    
    def _format_reference(self, ref: ContextReference, use_summary: bool = True) -> str:
        """格式化引用为文本"""
        if use_summary:
            return f"""[FILE_REF:{ref.ref_id}]
摘要：{ref.summary}
类型：{ref.ref_type}
重要性：{'★' * int(ref.importance * 5)}
详细内容：使用 read_artifact("{ref.ref_id}") 查看
"""
        else:
            content = self.retrieve_content(ref.ref_id)
            return f"""[FILE_REF:{ref.ref_id}]
类型：{ref.ref_type}
内容：
{content}
"""
    
    def _load_references(self):
        """加载引用索引"""
        ref_file = self.metadata_dir / "references.json"
        if ref_file.exists():
            data = json.loads(ref_file.read_text(encoding="utf-8"))
            for ref_data in data:
                ref = ContextReference(**ref_data)
                self.references[ref.ref_id] = ref
    
    def _save_references(self):
        """保存引用索引"""
        ref_file = self.metadata_dir / "references.json"
        data = [
            {
                "ref_id": ref.ref_id,
                "ref_type": ref.ref_type,
                "file_path": ref.file_path,
                "summary": ref.summary,
                "metadata": ref.metadata,
                "importance": ref.importance,
                "created_at": ref.created_at,
                "accessed_at": ref.accessed_at,
                "access_count": ref.access_count,
            }
            for ref in self.references.values()
        ]
        ref_file.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
