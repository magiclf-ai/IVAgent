# -*- coding: utf-8 -*-
"""
JEB Client
用于与 JEB HTTP 服务器通信的客户端
"""

import json
import requests
from typing import Dict, List, Any, Optional


class JEBClient:
    """JEB HTTP 客户端"""

    def __init__(self, host: str = "127.0.0.1", port: int = 16161, timeout: int = 120):
        """
        初始化 JEB 客户端

        Args:
            host: JEB 服务器地址
            port: JEB 服务器端口
            timeout: 请求超时时间（秒）
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.base_url = f"http://{host}:{port}"

    def _call(self, method: str, params: Any = None) -> Any:
        """
        调用 JSON-RPC 方法

        Args:
            method: 方法名
            params: 参数（列表或字典）

        Returns:
            方法返回结果

        Raises:
            Exception: 调用失败时抛出异常
        """
        url = f"{self.base_url}/mcp"

        request_data = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params if params is not None else [],
            "id": 1
        }

        try:
            response = requests.post(
                url,
                json=request_data,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout
            )

            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code}: {response.text}")

            result = response.json()

            if "error" in result:
                error = result["error"]
                error_msg = f"[{error.get('code', -1)}] {error.get('message', 'Unknown error')}"
                if "data" in error:
                    error_msg += f"\n{error['data']}"
                raise Exception(error_msg)

            return result.get("result")

        except requests.exceptions.Timeout:
            raise Exception(f"Request timeout after {self.timeout} seconds")
        except requests.exceptions.ConnectionError:
            raise Exception(f"Failed to connect to JEB server at {self.base_url}")
        except json.JSONDecodeError as e:
            raise Exception(f"Invalid JSON response: {e}")
        except Exception as e:
            raise Exception(f"RPC call failed: {e}")

    def ping(self) -> str:
        """
        测试服务器连接

        Returns:
            "pong" 如果服务器正常响应
        """
        return self._call("ping")

    def get_manifest(self, filepath: str) -> str:
        """
        获取 APK 的 AndroidManifest.xml 文本

        Args:
            filepath: APK 文件的绝对路径

        Returns:
            Manifest XML 文本
        """
        return self._call("get_manifest", [filepath])

    def get_all_exported_activities(self, filepath: str) -> List[str]:
        """
        获取所有导出的 Activity 类名

        Args:
            filepath: APK 文件的绝对路径

        Returns:
            导出的 Activity 类名列表
        """
        return self._call("get_all_exported_activities", [filepath])

    def get_exported_services(self, filepath: str) -> List[str]:
        """
        获取所有导出的 Service 类名

        Args:
            filepath: APK 文件的绝对路径

        Returns:
            导出的 Service 类名列表
        """
        return self._call("get_exported_services", [filepath])

    def get_method_decompiled_code(self, filepath: str, method_signature: str) -> str:
        """
        获取指定方法的反编译代码

        Args:
            filepath: APK 文件的绝对路径
            method_signature: 方法的完整签名，例如 "Lcom/example/Class;->method(Ljava/lang/String;)V"

        Returns:
            方法的反编译 Java 代码
        """
        return self._call("get_method_decompiled_code", [filepath, method_signature])

    def get_method_smali_code(self, filepath: str, method_signature: str) -> str:
        """
        获取指定方法的 Smali 代码

        Args:
            filepath: APK 文件的绝对路径
            method_signature: 方法的完整签名

        Returns:
            方法的 Smali 代码
        """
        return self._call("get_method_smali_code", [filepath, method_signature])

    def get_class_decompiled_code(self, filepath: str, class_signature: str) -> str:
        """
        获取指定类的反编译代码

        Args:
            filepath: APK 文件的绝对路径
            class_signature: 类的完整签名，例如 "Lcom/example/Class;"

        Returns:
            类的反编译 Java 代码
        """
        return self._call("get_class_decompiled_code", [filepath, class_signature])

    def get_method_callees(self, filepath: str, method_signature: str) -> List[Dict[str, Any]]:
        return self._call("get_method_callees", [filepath, method_signature])

    def get_method_callers(self, filepath: str, method_signature: str) -> List[Dict[str, Any]]:
        """
        获取调用指定方法的所有位置

        Args:
            filepath: APK 文件的绝对路径
            method_signature: 方法的完整签名

        Returns:
            调用者列表，每个元素包含 address 和 details
        """
        return self._call("get_method_callers", [filepath, method_signature])

    def get_field_callers(self, filepath: str, field_signature: str) -> List[Dict[str, Any]]:
        """
        获取访问指定字段的所有位置

        Args:
            filepath: APK 文件的绝对路径
            field_signature: 字段的完整签名，例如 "Lcom/example/Class;->fieldName:Ljava/lang/String;"

        Returns:
            访问者列表，每个元素包含 address 和 details
        """
        return self._call("get_field_callers", [filepath, field_signature])

    def get_method_overrides(self, filepath: str, method_signature: str) -> List[str]:
        """
        获取指定方法的所有重写（overrides）

        Args:
            filepath: APK 文件的绝对路径
            method_signature: 方法的完整签名

        Returns:
            重写方法签名列表
        """
        return self._call("get_method_overrides", [filepath, method_signature])

    def get_superclass(self, filepath: str, class_signature: str) -> Optional[str]:
        """
        获取指定类的父类

        Args:
            filepath: APK 文件的绝对路径
            class_signature: 类的完整签名

        Returns:
            父类的完整签名，如果没有则返回 None
        """
        result = self._call("get_superclass", [filepath, class_signature])
        # 如果结果为空字符串或 None，返回 None
        return result if result else None

    def get_interfaces(self, filepath: str, class_signature: str) -> List[str]:
        """
        获取指定类实现的所有接口

        Args:
            filepath: APK 文件的绝对路径
            class_signature: 类的完整签名

        Returns:
            接口签名列表
        """
        return self._call("get_interfaces", [filepath, class_signature])

    def get_class_methods(self, filepath: str, class_signature: str) -> List[str]:
        """
        获取指定类的所有方法

        Args:
            filepath: APK 文件的绝对路径
            class_signature: 类的完整签名

        Returns:
            方法签名列表
        """
        return self._call("get_class_methods", [filepath, class_signature])

    def get_class_fields(self, filepath: str, class_signature: str) -> List[str]:
        """
        获取指定类的所有字段

        Args:
            filepath: APK 文件的绝对路径
            class_signature: 类的完整签名

        Returns:
            字段签名列表
        """
        return self._call("get_class_fields", [filepath, class_signature])

    def check_java_identifier(self, filepath: str, identifier: str) -> List[Dict[str, Any]]:
        """
        检查标识符并识别其类型（类、方法或字段）

        Args:
            filepath: APK 文件的绝对路径
            identifier: 标识符（完全限定名或签名）

        Returns:
            匹配结果列表，每个元素包含 type, signature, parent
        """
        return self._call("check_java_identifier", [filepath, identifier])

    def rename_class_name(self, filepath: str, class_signature: str, new_class_name: str) -> bool:
        """
        重命名类

        Args:
            filepath: APK 文件的绝对路径
            class_signature: 类的完整签名
            new_class_name: 新类名

        Returns:
            是否成功
        """
        return self._call("rename_class_name", [filepath, class_signature, new_class_name])

    def rename_method_name(
        self,
        filepath: str,
        class_signature: str,
        method_signature: str,
        new_method_name: str
    ) -> bool:
        """
        重命名方法

        Args:
            filepath: APK 文件的绝对路径
            class_signature: 类的完整签名
            method_signature: 方法的完整签名
            new_method_name: 新方法名

        Returns:
            是否成功
        """
        return self._call("rename_method_name", [filepath, class_signature, method_signature, new_method_name])

    def rename_class_field(
        self,
        filepath: str,
        class_signature: str,
        field_signature: str,
        new_field_name: str
    ) -> bool:
        """
        重命名字段

        Args:
            filepath: APK 文件的绝对路径
            class_signature: 类的完整签名
            field_signature: 字段的完整签名
            new_field_name: 新字段名

        Returns:
            是否成功
        """
        return self._call("rename_class_field", [filepath, class_signature, field_signature, new_field_name])
