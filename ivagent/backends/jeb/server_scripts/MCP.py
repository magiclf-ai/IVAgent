# -*- coding: utf-8 -*-

import json
import os
import threading
import traceback
import re
import time

from com.pnfsoftware.jeb.client.api import IScript
from com.pnfsoftware.jeb.core import Artifact, RuntimeProjectUtil
from com.pnfsoftware.jeb.core.actions import (
    ActionContext,
    ActionOverridesData,
    Actions,
    ActionXrefsData,
)
from com.pnfsoftware.jeb.core.input import FileInput
from com.pnfsoftware.jeb.core.output.text import TextDocumentUtil
from com.pnfsoftware.jeb.core.units.code.android import IApkUnit
from com.pnfsoftware.jeb.core.util import DecompilerHelper
from java.io import File

# Python 2.7 changes - use urlparse from urlparse module instead of urllib.parse
from urlparse import urlparse

# Python 2.7 doesn't have typing, so we'll define our own minimal substitutes
# and ignore most type annotations

from ASTExtractor import ASTExtractor

# Mock typing classes/functions for type annotation compatibility
class Any(object):
    pass


class Callable(object):
    pass


def get_type_hints(func):
    """Mock for get_type_hints that works with Python 2.7 functions"""
    hints = {}

    # Try to get annotations (modern Python way)
    if hasattr(func, "__annotations__"):
        hints.update(getattr(func, "__annotations__", {}))

    # For Python 2.7, inspect the function signature
    import inspect

    args, varargs, keywords, defaults = inspect.getargspec(func)

    # Add all positional parameters with Any type
    for arg in args:
        if arg not in hints:
            hints[arg] = Any

    return hints


class TypedDict(dict):
    pass


class Optional(object):
    pass


class Annotated(object):
    pass


class TypeVar(object):
    pass


class Generic(object):
    pass


# Use BaseHTTPServer instead of http.server
import BaseHTTPServer


class JSONRPCError(Exception):
    def __init__(self, code, message, data=None):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.data = data


class RPCRegistry(object):
    def __init__(self):
        self.methods = {}

    def register(self, func):
        self.methods[func.__name__] = func
        return func

    def dispatch(self, method, params):
        if method not in self.methods:
            raise JSONRPCError(-32601, "Method '{0}' not found".format(method))

        func = self.methods[method]
        hints = get_type_hints(func)

        # Remove return annotation if present
        if "return" in hints:
            hints.pop("return", None)

        if isinstance(params, list):
            if len(params) != len(hints):
                raise JSONRPCError(
                    -32602,
                    "Invalid params: expected {0} arguments, got {1}".format(
                        len(hints), len(params)
                    ),
                )

            # Python 2.7 doesn't support zip with items() directly
            # Convert to simpler validation approach
            converted_params = []
            param_items = hints.items()
            for i, value in enumerate(params):
                if i < len(param_items):
                    param_name, expected_type = param_items[i]
                    # In Python 2.7, we'll do minimal type checking
                    converted_params.append(value)
                else:
                    converted_params.append(value)

            return func(*converted_params)
        elif isinstance(params, dict):
            # Simplify type validation for Python 2.7
            if set(params.keys()) != set(hints.keys()):
                raise JSONRPCError(
                    -32602,
                    "Invalid params: expected {0}".format(list(hints.keys())),
                )

            # Validate and convert parameters
            converted_params = {}
            for param_name, expected_type in hints.items():
                value = params.get(param_name)
                # Skip detailed type validation in Python 2.7 version
                converted_params[param_name] = value

            return func(**converted_params)
        else:
            raise JSONRPCError(
                -32600, "Invalid Request: params must be array or object"
            )


rpc_registry = RPCRegistry()


def jsonrpc(func):
    """Decorator to register a function as a JSON-RPC method"""
    global rpc_registry
    return rpc_registry.register(func)


class JSONRPCRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def send_jsonrpc_error(self, code, message, id=None):
        response = {
            "jsonrpc": "2.0",
            "error": {"code": code, "message": message},
        }
        if id is not None:
            response["id"] = id
        response_body = json.dumps(response)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response_body))
        self.end_headers()
        self.wfile.write(response_body)

    def do_POST(self):
        global rpc_registry

        parsed_path = urlparse(self.path)
        if parsed_path.path != "/mcp":
            self.send_jsonrpc_error(-32098, "Invalid endpoint", None)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self.send_jsonrpc_error(-32700, "Parse error: missing request body", None)
            return

        request_body = self.rfile.read(content_length)
        try:
            request = json.loads(request_body)
        except ValueError:  # Python 2.7 uses ValueError instead of JSONDecodeError
            self.send_jsonrpc_error(-32700, "Parse error: invalid JSON", None)
            return

        # Prepare the response
        response = {
            "jsonrpc": "2.0"
        }
        if request.get("id") is not None:
            response["id"] = request.get("id")

        try:
            # Basic JSON-RPC validation
            if not isinstance(request, dict):
                raise JSONRPCError(-32600, "Invalid Request")
            if request.get("jsonrpc") != "2.0":
                raise JSONRPCError(-32600, "Invalid JSON-RPC version")
            if "method" not in request:
                raise JSONRPCError(-32600, "Method not specified")

            # Dispatch the method
            result = rpc_registry.dispatch(request["method"], request.get("params", []))
            response["result"] = result

        except JSONRPCError as e:
            response["error"] = {
                "code": e.code,
                "message": e.message
            }
            if e.data is not None:
                response["error"]["data"] = e.data
        except Exception as e:
            traceback.print_exc()
            response["error"] = {
                "code": -32603,
                "message": "Internal error (please report a bug)",
                "data": traceback.format_exc(),
            }

        try:
            response_body = json.dumps(response)
        except Exception as e:
            traceback.print_exc()
            response_body = json.dumps({
                "error": {
                    "code": -32603,
                    "message": "Internal error (please report a bug)",
                    "data": traceback.format_exc(),
                }
            })

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response_body))
        self.end_headers()
        self.wfile.write(response_body)

    def log_message(self, format, *args):
        # Suppress logging
        pass


class MCPHTTPServer(BaseHTTPServer.HTTPServer):
    allow_reuse_address = False


class Server(object):  # Use explicit inheritance from object for py2
    HOST = os.getenv("JEB_MCPC_HOST", "127.0.0.1")
    PORT = int(os.getenv("JEB_MCPC_PORT", "16161"))

    def __init__(self):
        self.server = None
        self.server_thread = None
        self.running = False

    def start(self):
        if self.running:
            print("[MCP] Server is already running")
            return

        # Python 2.7 doesn't support daemon parameter in Thread constructor
        self.server_thread = threading.Thread(target=self._run_server)
        self.server_thread.daemon = True  # Set daemon attribute after creation
        self.running = True
        self.server_thread.start()

    def stop(self):
        if not self.running:
            return

        self.running = False
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.server_thread:
            self.server_thread.join()
            self.server = None
        print("[MCP] Server stopped")

    def _run_server(self):
        try:
            # Create server in the thread to handle binding
            self.server = MCPHTTPServer((Server.HOST, Server.PORT), JSONRPCRequestHandler)
            print("[MCP] Server started at http://{0}:{1}".format(Server.HOST, Server.PORT))
            self.server.serve_forever()
        except OSError as e:
            if e.errno == 98 or e.errno == 10048:  # Port already in use (Linux/Windows)
                print("[MCP] Error: Port 13337 is already in use")
            else:
                print("[MCP] Server error: {0}".format(e))
            self.running = False
        except Exception as e:
            print("[MCP] Server error: {0}".format(e))
        finally:
            self.running = False


# 定义为 unicode 字符串 (u'...')
def preprocess_manifest_py2(manifest_text):
    """
    一个为 Python 2 设计的、健壮的 Manifest 预处理函数。
    它会清理非法字符，并强行移除所有 <meta-data> 标签以避免解析错误。
    """
    # 1. 确保输入是 unicode 字符串，并忽略解码错误
    if isinstance(manifest_text, str):
        try:
            manifest_text = manifest_text.decode('utf-8')
        except UnicodeDecodeError:
            manifest_text = manifest_text.decode('utf-8', 'ignore')

    # 2. 清理基本的非法 XML 字符
    # (保留这个作为基础卫生措施)
    cleaned_chars = []
    for char in manifest_text:
        codepoint = ord(char)
        if (codepoint == 0x9 or codepoint == 0xA or codepoint == 0xD or
           (codepoint >= 0x20 and codepoint <= 0xD7FF) or
           (codepoint >= 0xE000 and codepoint <= 0xFFFD) or
           (codepoint >= 0x10000 and codepoint <= 0x10FFFF)):
            cleaned_chars.append(char)
    text_no_illegal_chars = u"".join(cleaned_chars)

    # 3. 使用正则表达式，强行移除所有 <meta-data ... /> 标签
    # re.DOTALL 使得 '.' 可以匹配包括换行在内的任意字符
    # re.IGNORECASE 忽略大小写
    # ur'...' 定义一个 unicode 正则表达式
    text_no_metadata = re.sub(
        ur'<\s*meta-data.*?/>',
        u'',  # 替换为空字符串，即直接删除
        text_no_illegal_chars,
        flags=re.DOTALL | re.IGNORECASE
    )
    
    return text_no_metadata

@jsonrpc
def ping():
    """Do a simple ping to check server is alive and running"""
    return "pong"


# implement a FIFO queue to store the artifacts
artifactQueue = list()

def addArtifactToQueue(artifact):
    """Add an artifact to the queue"""
    artifactQueue.append(artifact)

def getArtifactFromQueue():
    """Get an artifact from the queue"""
    if len(artifactQueue) > 0:
        return artifactQueue.pop(0)
    return None

def clearArtifactQueue():
    """Clear the artifact queue"""
    global artifactQueue
    artifactQueue = list()

MAX_OPENED_ARTIFACTS = 1

# 全局缓存，目前只缓存了Mainfest文本和exported组件，加载新的apk文件时将被清除。
apk_cached_data = {}

def getOrLoadApk(filepath):
    if not os.path.exists(filepath):
        print("File not found: %s" % filepath)
        raise JSONRPCError(-1, ErrorMessages.LOAD_APK_NOT_FOUND)

    engctx = CTX.getEnginesContext()

    if not engctx:
        print('Back-end engines not initialized')
        raise JSONRPCError(-1, ErrorMessages.LOAD_APK_FAILED)

    # Create a project
    project = engctx.loadProject('MCPPluginProject')
    correspondingArtifact = None
    for artifact in project.getLiveArtifacts():
        if artifact.getArtifact().getName() == filepath:
            # If the artifact is already loaded, return it
            correspondingArtifact = artifact
            break
    if not correspondingArtifact:
        # try to load the artifact, but first check if the queue size has been exceeded
        if len(artifactQueue) >= MAX_OPENED_ARTIFACTS:
            # unload the oldest artifact
            oldestArtifact = getArtifactFromQueue()
            if oldestArtifact:
                # unload the artifact
                oldestArtifactName = oldestArtifact.getArtifact().getName()
                print('Unloading artifact: %s because queue size limit exeeded' % oldestArtifactName)
                RuntimeProjectUtil.destroyLiveArtifact(oldestArtifact)

        # Fix: 直接用filepath而不是basename作为Artifact的名称，否则如果加载了多个同名不同路径的apk，会出现问题。
        correspondingArtifact = project.processArtifact(Artifact(filepath, FileInput(File(filepath))))
        addArtifactToQueue(correspondingArtifact)
        apk_cached_data.clear()
    
    unit = correspondingArtifact.getMainUnit()
    if isinstance(unit, IApkUnit):
        # If the unit is already loaded, return it
        return unit    
    raise JSONRPCError(-1, ErrorMessages.LOAD_APK_FAILED)


@jsonrpc
def get_manifest(filepath):
    """Get the manifest of the given APK file in path, note filepath needs to be an absolute path"""
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)  # Fixed: use getOrLoadApk function to load the APK
    
    if 'manifest' in apk_cached_data:
        return apk_cached_data['manifest']
    
    man = apk.getManifest()
    if man is None:
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)
    
    doc = man.getFormatter().getPresentation(0).getDocument()
    text = TextDocumentUtil.getText(doc)
    #engctx.unloadProjects(True)
    apk_cached_data['manifest'] = text
    return text


@jsonrpc
def get_all_exported_activities(filepath):
    """
    Get all exported Activity components from the APK and normalize their class names.

    An Activity is considered "exported" if:
    - It explicitly sets android:exported="true", or
    - It omits android:exported but includes an <intent-filter> (implicitly exported)

    Note:
    - If android:exported="false" is explicitly set, the Activity is NOT exported, even if it has intent-filters.

    Class name normalization rules:
    - If it starts with '.', prepend the package name (e.g., .MainActivity -> com.example.app.MainActivity)
    - If it has no '.', include both the original and package-prefixed versions
    - If it's a full class name, keep as-is

    Returns a list of fully qualified exported Activity class names (for use in decompilation, etc.)
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)
    
    from xml.etree import ElementTree as ET

    manifest_text = get_manifest(filepath)
    manifest_text = preprocess_manifest_py2(manifest_text)

    if not manifest_text:
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)
    
    # 首先尝试在缓存中取，跳过XML解析。
    if 'exported_activities' in apk_cached_data:
        return apk_cached_data['exported_activities']

    try:
        root = ET.fromstring(manifest_text.encode('utf-8'))
    except Exception as e:
        print("[MCP] Error parsing manifest:", e)
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    ANDROID_NS = 'http://schemas.android.com/apk/res/android'
    exported_activities = []

    # 获取包名
    package_name = root.attrib.get('package', '').strip()

    # 查找 <application> 节点
    app_node = root.find('application')
    if app_node is None:
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    for activity in app_node.findall('activity'):
        name = activity.attrib.get('{' + ANDROID_NS + '}name')
        exported = activity.attrib.get('{' + ANDROID_NS + '}exported')
        has_intent_filter = len(activity.findall('intent-filter')) > 0

        if not name:
            continue

        if exported == "true" or (exported is None and has_intent_filter):
            normalized = set()

            if name.startswith('.'):
                normalized.add(package_name + name)
            elif '.' not in name:
                normalized.add(name)
                normalized.add(package_name + '.' + name)
            else:
                normalized.add(name)

            exported_activities.extend(normalized)
    # 缓存导出Activity数据
    apk_cached_data['exported_activities'] = exported_activities
    return exported_activities


@jsonrpc
def get_exported_services(filepath):
    """
    Get all exported Service components from the APK and normalize their class names.

    A Service is considered "exported" if:
    - It explicitly sets android:exported="true", or
    - It omits android:exported but includes an <intent-filter> (implicitly exported)

    Note:
    - If android:exported="false" is explicitly set, the Service is NOT exported, even if it has intent-filters.

    Class name normalization rules:
    - If it starts with '.', prepend the package name (e.g., .MainService -> com.example.app.MainService)
    - If it has no '.', include both the original and package-prefixed versions
    - If it's a full class name, keep as-is

    Returns a list of fully qualified exported Service class names (for use in decompilation, etc.)
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)
    
    from xml.etree import ElementTree as ET

    manifest_text = get_manifest(filepath)
    manifest_text = preprocess_manifest_py2(manifest_text)

    if not manifest_text:
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)
    
    # 首先尝试在缓存中取，跳过XML解析。
    if 'exported_services' in apk_cached_data:
        return apk_cached_data['exported_services']

    try:
        root = ET.fromstring(manifest_text.encode('utf-8'))
    except Exception as e:
        print("[MCP] Error parsing manifest:", e)
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    ANDROID_NS = 'http://schemas.android.com/apk/res/android'
    exported_services = []

    # 获取包名
    package_name = root.attrib.get('package', '').strip()

    # 查找 <application> 节点
    app_node = root.find('application')
    if app_node is None:
        raise JSONRPCError(-1, ErrorMessages.GET_MANIFEST_FAILED)

    for activity in app_node.findall('service'):
        name = activity.attrib.get('{' + ANDROID_NS + '}name')
        exported = activity.attrib.get('{' + ANDROID_NS + '}exported')
        has_intent_filter = len(activity.findall('intent-filter')) > 0

        if not name:
            continue

        if exported == "true" or (exported is None and has_intent_filter):
            normalized = set()

            if name.startswith('.'):
                normalized.add(package_name + name)
            elif '.' not in name:
                normalized.add(name)
                normalized.add(package_name + '.' + name)
            else:
                normalized.add(name)

            exported_services.extend(normalized)
    # 缓存导出Service数据
    apk_cached_data['exported_services'] = exported_services
    return exported_services


@jsonrpc
def get_method_decompiled_code(filepath, method_signature):
    """Get the decompiled code of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    Dex units use Java-style internal addresses to identify items:
    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z
    note filepath needs to be an absolute path
    """
    if not filepath or not method_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    
    codeUnit = apk.getDex()
    method = codeUnit.getMethod(method_signature)
    decomp = DecompilerHelper.getDecompiler(codeUnit)
    if not decomp:
        print('Cannot acquire decompiler for unit: %s' % decomp)
        raise JSONRPCError(-1, ErrorMessages.DECOMPILE_FAILED)
    
    if method is None:
        print('Method not found: %s' % method_signature)
        raise_method_not_found(method_signature)

    if not decomp.decompileMethod(method.getSignature()):
        print('Failed decompiling method')
        raise JSONRPCError(-1, ErrorMessages.DECOMPILE_FAILED)

    text = decomp.getDecompiledMethodText(method.getSignature())
    return text


@jsonrpc
def get_method_smali_code(filepath, method_signature):
    """Get the smali code of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    Dex units use Java-style internal addresses to identify items:
    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z
    note filepath needs to be an absolute path
    """
    if not filepath or not method_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    
    codeUnit = apk.getDex()
    method = codeUnit.getMethod(method_signature)

    if method is None:
        print('Method not found: %s' % method_signature)
        raise_method_not_found(method_signature)
    
    instructions = method.getInstructions()
    smali_code = ""
    for instruction in instructions:
        smali_code = smali_code + instruction.format(None)  + "\n"

    return smali_code


@jsonrpc
def get_class_decompiled_code(filepath, class_signature):
    """Get the decompiled code of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    Dex units use Java-style internal addresses to identify items:
    - package: Lcom/abc/
    - type: Lcom/abc/Foo;
    - method: Lcom/abc/Foo;->bar(I[JLjava/Lang/String;)V
    - field: Lcom/abc/Foo;->flag1:Z
    note filepath needs to be an absolute path
    """
    if not filepath or not class_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    
    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    if clazz is None:
        print('Class not found: %s' % class_signature)
        raise_class_not_found(class_signature)

    decomp = DecompilerHelper.getDecompiler(codeUnit)
    if not decomp:
        print('Cannot acquire decompiler for unit: %s' % codeUnit)
        return ErrorMessages.DECOMPILE_FAILED

    if not decomp.decompileClass(clazz.getSignature()):
        print('Failed decompiling class: %s' % class_signature)
        return ErrorMessages.DECOMPILE_FAILED

    text = decomp.getDecompiledClassText(clazz.getSignature())
    return text


@jsonrpc
def get_method_callees(filepath, method_signature):
    """
    Get the callees of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    note filepath needs to be an absolute path
    """
    if not filepath or not method_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    
    ret = []
    codeUnit = apk.getDex()
    method = codeUnit.getMethod(method_signature)
    if method is None:
        print("Method not found: %s" % method_signature)
        raise_method_not_found(method_signature)

    decomp = DecompilerHelper.getDecompiler(codeUnit)

    if not decomp.decompileMethod(method.getSignature()):
        print('Failed decompiling method')
        raise JSONRPCError(-1, ErrorMessages.DECOMPILE_FAILED)

    extractor = ASTExtractor(decomp)
    ret = extractor.extract_callee_by_method_signature(method_signature)
    return ret



@jsonrpc
def get_method_callers(filepath, method_signature):
    """
    Get the callers of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    note filepath needs to be an absolute path
    """
    if not filepath or not method_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    
    ret = []
    codeUnit = apk.getDex()
    method = codeUnit.getMethod(method_signature)
    if method is None:
        print("Method not found: %s" % method_signature)
        raise_method_not_found(method_signature)
        
    actionXrefsData = ActionXrefsData()
    actionContext = ActionContext(codeUnit, Actions.QUERY_XREFS, method.getItemId(), None)
    if codeUnit.prepareExecution(actionContext,actionXrefsData):
        for i in range(actionXrefsData.getAddresses().size()):
            ret.append({
                "address": actionXrefsData.getAddresses()[i],
                "details": actionXrefsData.getDetails()[i]
            })
    return ret


@jsonrpc
def get_field_callers(filepath, field_signature):
    """
    Get the callers of the given field in the APK file, the passed in field_signature needs to be a fully-qualified signature
    note filepath needs to be an absolute path
    """
    if not filepath or not field_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    
    ret = []
    codeUnit = apk.getDex()
    field = codeUnit.getField(field_signature)
    if field is None:
        print("Field not found: %s" % field_signature)
        raise_field_not_found(field_signature)
        
    actionXrefsData = ActionXrefsData()
    actionContext = ActionContext(codeUnit, Actions.QUERY_XREFS, field.getItemId(), None)
    if codeUnit.prepareExecution(actionContext,actionXrefsData):
        for i in range(actionXrefsData.getAddresses().size()):
            ret.append({
                "address": actionXrefsData.getAddresses()[i],
                "details": actionXrefsData.getDetails()[i]
            })
    return ret


@jsonrpc
def get_method_overrides(filepath, method_signature):
    """
    Get the overrides of the given method in the APK file, the passed in method_signature needs to be a fully-qualified signature
    note filepath needs to be an absolute path
    """
    if not filepath or not method_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)
    
    ret = []
    codeUnit = apk.getDex()
    method = codeUnit.getMethod(method_signature)
    # FIXME: 
    # 当前如果method_signature在apk中没有任何使用super调用原函数的地方
    # 则这里无法获取到method导致后面拿不到QUERY_OVERRIDES
    # 需要解决这个问题。
    if method is None:
        print("Method not found: %s" % method_signature)
        raise_method_not_found(method_signature)
        
    data = ActionOverridesData()
    actionContext = ActionContext(codeUnit, Actions.QUERY_OVERRIDES, method.getItemId(), None)
    if codeUnit.prepareExecution(actionContext,data):
        for i in range(data.getAddresses().size()):
            ret.append(data.getAddresses()[i])
    return ret


@jsonrpc
def get_superclass(filepath, class_signature):
    """
    Get the superclass of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    if not filepath or not class_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)
    
    apk = getOrLoadApk(filepath)

    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    if clazz is None:
        raise_class_not_found(class_signature)

    return clazz.getSupertypeSignature(True)


@jsonrpc
def get_interfaces(filepath, class_signature):
    """
    Get the interfaces of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    if not filepath or not class_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)

    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    if clazz is None:
        print("Class not found: %s" % class_signature)
        raise_class_not_found(class_signature)
    
    interfaces = []
    interfaces_array = clazz.getInterfaceSignatures(True)
    for interface in interfaces_array:
        interfaces.append(interface)

    return interfaces


@jsonrpc
def get_all_classes(filepath):
    """
    Get all classes from the APK file.
    Returns a list of dictionaries containing class name and signature.
    The passed in filepath needs to be a fully-qualified absolute path.
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)

    codeUnit = apk.getDex()

    class_list = codeUnit.getClasses()
    result = []

    for clazz in class_list:
        if clazz:
            result.append({
                "name": clazz.getName(),
                "signature": clazz.getSignature(True)
            })

    return result


@jsonrpc
def get_all_methods(filepath):
    """
    Get all methods from the APK file.
    Returns a list of dictionaries containing method name and signature.
    The passed in filepath needs to be a fully-qualified absolute path.
    """
    if not filepath:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)

    codeUnit = apk.getDex()

    method_list = codeUnit.getMethods()
    result = []

    for method in method_list:
        if method:
            result.append({
                "name": method.getName(),
                "signature": method.getSignature(True)
            })

    return result


@jsonrpc
def get_class_methods(filepath, class_signature):
    """
    Get the methods of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    if not filepath or not class_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)

    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    if clazz is None:
        print("Class not found: %s" % class_signature)
        raise_class_not_found(class_signature)

    method_signatures = []
    dex_methods = clazz.getMethods()
    for method in dex_methods:
        if method:
            method_signatures.append(method.getSignature(True))

    return method_signatures


@jsonrpc
def get_class_fields(filepath, class_signature):
    """
    Get the fields of the given class in the APK file, the passed in class_signature needs to be a fully-qualified signature
    the passed in filepath needs to be a fully-qualified absolute path
    """
    if not filepath or not class_signature:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)

    apk = getOrLoadApk(filepath)

    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    if clazz is None:
        print("Class not found: %s" % class_signature)
        raise_class_not_found(class_signature)
    
    field_signatures = []
    dex_field = clazz.getFields()
    for field in dex_field:
        if field:
            field_signatures.append(field.getSignature(True))

    return field_signatures


@jsonrpc
def rename_class_name(filepath, class_signature, new_class_name):
    if not filepath or not class_signature:
        return False

    apk = getOrLoadApk(filepath)
    if apk is None:
        return False

    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    if clazz is None:
        return False

    print("rename class:", clazz.getName(), "to", new_class_name)
    clazz.setName(new_class_name)
    return True


@jsonrpc
def rename_method_name(
    filepath, class_signature, method_signature, new_method_name
):
    if not filepath or not class_signature:
        return False

    apk = getOrLoadApk(filepath)
    if apk is None:
        return False

    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    if clazz is None:
        return False
    for method in clazz.getMethods():
        signature = method.getSignature()
        print("method signature:", signature, "looking for:", method_signature)
        if signature == method_signature:
            print("rename method:", method.getName(), "to", new_method_name)
            method.setName(new_method_name)
            break
    return True


@jsonrpc
def rename_class_field(
    filepath, class_signature, field_signature, new_field_name
):
    if not filepath or not class_signature:
        return False

    apk = getOrLoadApk(filepath)
    if apk is None:
        return False

    codeUnit = apk.getDex()
    clazz = codeUnit.getClass(class_signature)
    if clazz is None:
        return False

    dex_field = clazz.getFields()
    for field in dex_field:
        signature = field.getSignature()
        print("method signature:", signature, "looking for:", field_signature)
        if signature == field_signature:
            print("rename field:", field.getName(), "to", new_field_name)
            field.setName(new_field_name)
            break
    return True


def replace_last_once(s, old, new):
    parts = s.rsplit(old, 1)
    return new.join(parts) if len(parts) > 1 else s


@jsonrpc
def check_java_identifier(filepath, identifier):
    """
    Check an identifier in the APK file and recognize if this is a class, method or field.
    the passed in identifier needs to be a fully-qualified name (like `com.abc.def.Foo`) or a signature;
    the passed in filepath needs to be a fully-qualified absolute path;
    the return value will be a list to tell you the possible type of the passed identifier.
    """
    if not filepath or not identifier:
        raise JSONRPCError(-1, ErrorMessages.MISSING_PARAM)
    
    apk = getOrLoadApk(filepath)

    codeUnit = apk.getDex()
    
    result = []

    class_list = codeUnit.getClasses()

    if identifier.startswith("L") and identifier.endswith(";"):
        fake_class_signature = identifier
    else:
        fake_class_signature = "L" + identifier.replace(".", "/") + ";"
    
    for clazz in class_list:
        if clazz.getSignature(True) == fake_class_signature:
            result.append({
                "type": "class",
                "signature": clazz.getSignature(True),
                "parent": clazz.getPackage().getSignature(True)
            })
            # If an identifier is a class, it will never be a method or field.
            return result

    method_list = codeUnit.getMethods()

    if identifier.startswith("L") and ";->" in identifier:
        fake_method_signature = identifier
    else:
        fake_method_signature = replace_last_once("L" + identifier.replace(".", "/"), "/", ";->")

    for method in method_list:
        if method.getSignature(True).startswith(fake_method_signature):
            result.append({
                "type": "method",
                "signature": method.getSignature(True),
                "parent": method.getClassType().getSignature(True)
            })

    field_list = codeUnit.getFields()

    if identifier.startswith("L") and ";->" in identifier:
        fake_field_signature = identifier
    else:
        fake_field_signature = replace_last_once("L" + identifier.replace(".", "/"), "/", ";->")
    
    for field in field_list:
        if field.getSignature(True).startswith(fake_field_signature):
            result.append({
                "type": "field",
                "signature": field.getSignature(True),
                "parent": field.getClassType().getSignature(True)
            })
            break
    
    if len(result) == 0:
        if identifier.startswith("dalvik") or identifier.startswith("Landroid"):
            result.append({
                "type": "Android base type",
                "signature": "N/A",
                "parent": "N/A"
            })
        elif identifier.startswith("Ljava"):
            result.append({
                "type": "Java base type",
                "signature": "N/A",
                "parent": "N/A"
            })
        else:
            result.append({
                "type": "Not found",
                "signature": "N/A",
                "parent": "N/A"
            })
    return result


def raise_class_not_found(class_signature):
    if class_signature.startswith("Ldalvik") or class_signature.startswith("Ljava") or class_signature.startswith("Landroid"):
        raise JSONRPCError(-1, ErrorMessages.CLASS_NOT_FOUND_WITHOUT_CHECK)
    else:
        raise JSONRPCError(-1, ErrorMessages.CLASS_NOT_FOUND)


def raise_method_not_found(method_signature):
    if method_signature.startswith("Ldalvik") or method_signature.startswith("Ljava") or method_signature.startswith("Landroid"):
        raise JSONRPCError(-1, ErrorMessages.METHOD_NOT_FOUND_WITHOUT_CHECK)
    else:
        raise JSONRPCError(-1, ErrorMessages.METHOD_NOT_FOUND)


def raise_field_not_found(field_signature):
    if field_signature.startswith("Ldalvik") or field_signature.startswith("Ljava") or field_signature.startswith("Landroid"):
        raise JSONRPCError(-1, ErrorMessages.FIELD_NOT_FOUND_WITHOUT_CHECK)
    else:
        raise JSONRPCError(-1, ErrorMessages.FIELD_NOT_FOUND)


class ErrorMessages:
    SUCCESS = "[Success]"
    MISSING_PARAM = "[Error] Missing parameter."
    LOAD_APK_FAILED = "[Error] Load apk failed."
    LOAD_APK_NOT_FOUND = "[Error] Apk file not found."
    GET_MANIFEST_FAILED = "[Error] Get AndroidManifest text failed."
    INDEX_OUT_OF_BOUNDS = "[Error] Index out of bounds."
    DECOMPILE_FAILED = "[Error] Failed to decompile code."
    METHOD_NOT_FOUND = "[Error] Method not found in current apk, use check_java_identifier tool check your input first."
    METHOD_NOT_FOUND_WITHOUT_CHECK = "[Error] Method not found in current apk."
    CLASS_NOT_FOUND = "[Error] Class not found in current apk, use check_java_identifier tool check your input first."
    CLASS_NOT_FOUND_WITHOUT_CHECK = "[Error] Class not found in current apk."
    FIELD_NOT_FOUND = "[Error] Field not found in current apk, use check_java_identifier tool check your input first."
    FIELD_NOT_FOUND_WITHOUT_CHECK = "[Error] Field not found in current apk."


CTX = None
class MCP(IScript):
    def __init__(self):
        self.server = Server()
        print("[MCP] Plugin loaded")

    def run(self, ctx):
        global CTX  # Fixed: use global keyword to modify global variable
        CTX = ctx
        self.server.start()
        print("[MCP] Plugin running")

        is_daemon = int(os.getenv("JEB_MCP_DAEMON", "0"))
        if is_daemon == 1:
            try:
                while True:
                    time.sleep(10)
            except KeyboardInterrupt:
                print("Exiting...")

    def term(self):
        self.server.stop()
