/**
 * Redis 缓存管理系统 - 前端应用
 */

// API 基础 URL
const API_BASE = '';

// 全局状态
const state = {
    keys: [],
    selectedKeys: new Set(),
    pagination: {
        page: 1,
        limit: 20,
        total: 0
    },
    filters: {
        pattern: '*',
        namespace: '',
        key_type: ''
    },
    connected: false,
    currentKey: null
};

// 防抖计时器
let searchDebounceTimer = null;

// DOM 元素
const elements = {};

// 初始化
function init() {
    cacheElements();
    bindEvents();
    loadStats();
    loadNamespaces();
    // 连接检查后再决定是否搜索，避免未连接时弹窗
    checkConnectionAndSearch();
}

// 检查连接状态后再搜索
async function checkConnectionAndSearch() {
    try {
        const stats = await apiGet('/api/redis/stats');
        state.connected = stats.connected;
        updateConnectionStatus(stats.connected);
        if (stats.connected) {
            searchKeys();
        }
    } catch (error) {
        console.error('Connection check failed:', error);
        state.connected = false;
        updateConnectionStatus(false);
    }
}

// 缓存 DOM 元素
function cacheElements() {
    // 统计
    elements.statTotalKeys = document.getElementById('stat-total-keys');
    elements.statMemory = document.getElementById('stat-memory');
    elements.statNamespaces = document.getElementById('stat-namespaces');
    elements.redisStatus = document.getElementById('redis-status');
    elements.redisStatusText = document.getElementById('redis-status-text');
    
    // 搜索
    elements.redisSearch = document.getElementById('redis-search');
    elements.keySearch = document.getElementById('key-search');
    elements.clearSearchBtn = document.getElementById('clear-search');
    elements.searchIndicator = document.getElementById('search-indicator');
    elements.namespaceFilter = document.getElementById('namespace-filter');
    elements.typeFilter = document.getElementById('type-filter');
    elements.searchBtn = document.getElementById('search-btn');
    
    // 表格
    elements.keysTableBody = document.querySelector('#keys-table tbody');
    elements.selectAll = document.getElementById('select-all');
    
    // 分页
    elements.paginationInfo = document.getElementById('pagination-info');
    elements.currentPage = document.getElementById('current-page');
    elements.prevPage = document.getElementById('prev-page');
    elements.nextPage = document.getElementById('next-page');
    
    // 按钮
    elements.refreshBtn = document.getElementById('refresh-btn');
    elements.connectBtn = document.getElementById('connect-btn');
    elements.batchDeleteBtn = document.getElementById('batch-delete-btn');
    elements.clearAllBtn = document.getElementById('clear-all-btn');
    
    // 清空全部弹窗
    elements.clearAllModal = document.getElementById('clear-all-modal');
    elements.closeClearAllModal = document.getElementById('close-clear-all-btn');
    elements.clearAllCount = document.getElementById('clear-all-count');
    elements.confirmClearAllBtn = document.getElementById('confirm-clear-all-btn');
    
    // 连接弹窗
    elements.connectModal = document.getElementById('connect-modal');
    elements.closeConnectModal = document.getElementById('close-connect-modal');
    elements.connectForm = document.getElementById('connect-form');
    elements.testConnectBtn = document.getElementById('test-connect-btn');
    elements.redisHost = document.getElementById('redis-host');
    elements.redisPort = document.getElementById('redis-port');
    elements.redisDb = document.getElementById('redis-db');
    elements.redisPassword = document.getElementById('redis-password');
    
    // 值弹窗
    elements.valueModal = document.getElementById('value-modal');
    elements.closeValueModal = document.getElementById('close-value-modal');
    elements.valueModalBody = document.getElementById('value-modal-body');
    
    // TTL 弹窗
    elements.ttlModal = document.getElementById('ttl-modal');
    elements.closeTtlModal = document.getElementById('close-ttl-modal');
    elements.closeTtlBtn = document.getElementById('close-ttl-btn');
    elements.ttlForm = document.getElementById('ttl-form');
    elements.ttlKey = document.getElementById('ttl-key');
    elements.ttlValue = document.getElementById('ttl-value');
}

// 绑定事件
function bindEvents() {
    // 搜索按钮点击
    elements.searchBtn.addEventListener('click', () => {
        state.pagination.page = 1;
        searchKeys();
    });
    
    // 回车搜索
    elements.keySearch.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            state.pagination.page = 1;
            searchKeys();
        }
    });
    
    // 实时搜索（防抖）
    elements.keySearch.addEventListener('input', (e) => {
        // 清除之前的计时器
        if (searchDebounceTimer) {
            clearTimeout(searchDebounceTimer);
        }
        // 设置新的计时器，300ms 后执行搜索
        searchDebounceTimer = setTimeout(() => {
            state.pagination.page = 1;
            searchKeys();
        }, 300);
    });
    
    // 清除搜索按钮
    elements.clearSearchBtn.addEventListener('click', () => {
        elements.keySearch.value = '';
        elements.keySearch.focus();
        state.pagination.page = 1;
        searchKeys();
    });
    
    // 命名空间筛选变化时实时搜索
    elements.namespaceFilter.addEventListener('change', () => {
        state.pagination.page = 1;
        searchKeys();
    });
    
    // 类型筛选变化时实时搜索
    elements.typeFilter.addEventListener('change', () => {
        state.pagination.page = 1;
        searchKeys();
    });
    
    // 分页
    elements.prevPage.addEventListener('click', () => changePage(-1));
    elements.nextPage.addEventListener('click', () => changePage(1));
    
    // 刷新
    elements.refreshBtn.addEventListener('click', () => {
        loadStats();
        searchKeys();
    });
    
    // 连接设置
    elements.connectBtn.addEventListener('click', () => {
        elements.connectModal.classList.add('active');
    });
    
    elements.closeConnectModal.addEventListener('click', () => {
        elements.connectModal.classList.remove('active');
    });
    
    elements.connectModal.addEventListener('click', (e) => {
        if (e.target === elements.connectModal) {
            elements.connectModal.classList.remove('active');
        }
    });
    
    // 测试连接
    elements.testConnectBtn.addEventListener('click', testConnection);
    
    // 连接表单提交
    elements.connectForm.addEventListener('submit', (e) => {
        e.preventDefault();
        saveConnection();
    });
    
    // 全选
    elements.selectAll.addEventListener('change', (e) => {
        const checkboxes = elements.keysTableBody.querySelectorAll('.key-checkbox');
        checkboxes.forEach(cb => {
            cb.checked = e.target.checked;
            const key = cb.dataset.key;
            if (e.target.checked) {
                state.selectedKeys.add(key);
            } else {
                state.selectedKeys.delete(key);
            }
        });
        updateBatchDeleteButton();
    });
    
    // 批量删除
    elements.batchDeleteBtn.addEventListener('click', batchDelete);
    
    // 清空全部按钮
    elements.clearAllBtn.addEventListener('click', openClearAllModal);
    
    // 清空全部弹窗关闭
    elements.closeClearAllModal.addEventListener('click', closeClearAllModal);
    elements.clearAllModal.addEventListener('click', (e) => {
        if (e.target === elements.clearAllModal) {
            closeClearAllModal();
        }
    });
    
    // 清空全部确认按钮点击
    elements.confirmClearAllBtn.addEventListener('click', confirmClearAll);
    
    // 值弹窗关闭
    elements.closeValueModal.addEventListener('click', () => {
        elements.valueModal.classList.remove('active');
    });
    
    elements.valueModal.addEventListener('click', (e) => {
        if (e.target === elements.valueModal) {
            elements.valueModal.classList.remove('active');
        }
    });
    
    // TTL 弹窗
    elements.closeTtlModal.addEventListener('click', () => {
        elements.ttlModal.classList.remove('active');
    });
    
    elements.closeTtlBtn.addEventListener('click', () => {
        elements.ttlModal.classList.remove('active');
    });
    
    elements.ttlModal.addEventListener('click', (e) => {
        if (e.target === elements.ttlModal) {
            elements.ttlModal.classList.remove('active');
        }
    });
    
    elements.ttlForm.addEventListener('submit', (e) => {
        e.preventDefault();
        updateTTL();
    });
    
    // 快捷键
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            elements.connectModal.classList.remove('active');
            elements.valueModal.classList.remove('active');
            elements.ttlModal.classList.remove('active');
            elements.clearAllModal.classList.remove('active');
        }
        if (e.key === 'r' && e.ctrlKey) {
            e.preventDefault();
            loadStats();
            searchKeys();
        }
    });
    
    // Sidebar Toggle
    const menuToggle = document.getElementById('menu-toggle');
    if (menuToggle) {
        menuToggle.addEventListener('click', (e) => {
            e.preventDefault();
            document.getElementById('wrapper').classList.toggle('toggled');
        });
    }
    
    // Clear All Modal Cancel Button
    const cancelClearAllBtn = document.getElementById('cancel-clear-all-btn');
    if (cancelClearAllBtn) {
        cancelClearAllBtn.addEventListener('click', closeClearAllModal);
    }
}

// ==================== API 调用 ====================

// 带超时的 fetch 封装
async function fetchWithTimeout(url, options = {}, timeoutMs = 10000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    
    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal
        });
        clearTimeout(timeoutId);
        return response;
    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            throw new Error('请求超时');
        }
        throw error;
    }
}

// 带重试机制的 API 请求
async function apiRequestWithRetry(url, options = {}, maxRetries = 2) {
    let lastError;
    
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        try {
            const response = await fetchWithTimeout(url, options);
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.detail || `HTTP ${response.status}`);
            }
            return response;
        } catch (error) {
            lastError = error;
            console.warn(`API请求失败 (尝试 ${attempt + 1}/${maxRetries + 1}):`, error.message);
            
            if (attempt < maxRetries) {
                const delay = Math.min(1000 * Math.pow(2, attempt), 3000);
                await new Promise(resolve => setTimeout(resolve, delay));
            }
        }
    }
    
    throw lastError;
}

async function apiGet(endpoint) {
    const response = await apiRequestWithRetry(`${API_BASE}${endpoint}`);
    return response.json();
}

async function apiPost(endpoint, data) {
    const response = await apiRequestWithRetry(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    return response.json();
}

async function apiDelete(endpoint, data) {
    const options = {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' }
    };
    if (data) {
        options.body = JSON.stringify(data);
    }
    const response = await apiRequestWithRetry(`${API_BASE}${endpoint}`, options);
    return response.json();
}

async function apiPut(endpoint, data) {
    const response = await apiRequestWithRetry(`${API_BASE}${endpoint}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || `HTTP ${response.status}`);
    }
    return response.json();
}

// ==================== 数据加载 ====================

async function loadStats() {
    try {
        const stats = await apiGet('/api/redis/stats');
        
        state.connected = stats.connected;
        updateConnectionStatus(stats.connected);
        
        if (stats.connected) {
            elements.statTotalKeys.textContent = stats.total_keys.toLocaleString();
            elements.statMemory.textContent = stats.memory_used;
            elements.statNamespaces.textContent = Object.keys(stats.namespaces).length.toString();
        } else {
            elements.statTotalKeys.textContent = '-';
            elements.statMemory.textContent = '-';
            elements.statNamespaces.textContent = '-';
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
        state.connected = false;
        updateConnectionStatus(false);
    }
}

async function loadNamespaces() {
    try {
        const data = await apiGet('/api/redis/namespaces');
        const options = '<option value="">所有命名空间</option>' +
            data.namespaces.map(ns => `<option value="${ns}">${ns}</option>`).join('');
        elements.namespaceFilter.innerHTML = options;
    } catch (error) {
        console.error('Failed to load namespaces:', error);
    }
}

async function searchKeys() {
    if (!state.connected) {
        // 未连接时不弹窗，静默返回
        return;
    }
    
    // 显示搜索指示器
    setSearchingState(true);
    
    try {
        const pattern = elements.keySearch.value || '*';
        const namespace = elements.namespaceFilter.value;
        const keyType = elements.typeFilter.value;
        
        const request = {
            pattern: pattern,
            namespace: namespace || null,
            key_type: keyType || null,
            limit: state.pagination.limit,
            offset: (state.pagination.page - 1) * state.pagination.limit
        };
        
        const result = await apiPost('/api/redis/keys/search', request);
        
        state.keys = result.keys;
        state.pagination.total = result.total;
        
        updateKeysTable(result.keys);
        updatePagination();
        
        // 清空选择
        state.selectedKeys.clear();
        elements.selectAll.checked = false;
        updateBatchDeleteButton();
        
    } catch (error) {
        console.error('Failed to search keys:', error);
        showError('搜索失败: ' + error.message);
    } finally {
        // 隐藏搜索指示器
        setSearchingState(false);
    }
}

// 设置搜索状态（显示/隐藏搜索指示器）
function setSearchingState(searching) {
    if (elements.searchIndicator) {
        elements.searchIndicator.classList.toggle('active', searching);
    }
    if (elements.redisSearch) {
        elements.redisSearch.classList.toggle('searching', searching);
    }
}

// ==================== UI 更新 ====================

function updateConnectionStatus(connected) {
    if (elements.redisStatus) {
        elements.redisStatus.classList.remove('online', 'offline');
        elements.redisStatus.classList.add(connected ? 'online' : 'offline');
    }
    if (elements.redisStatusText) {
        elements.redisStatusText.textContent = connected ? '已连接' : '未连接';
    }
}

function updateKeysTable(keys) {
    if (keys.length === 0) {
        elements.keysTableBody.innerHTML = `
            <tr><td colspan="7" class="empty-state">暂无数据</td></tr>
        `;
        return;
    }
    
    elements.keysTableBody.innerHTML = keys.map(key => `
        <tr data-key="${escapeHtml(key.key)}">
            <td class="checkbox-col">
                <input type="checkbox" class="key-checkbox" data-key="${escapeHtml(key.key)}"
                    ${state.selectedKeys.has(key.key) ? 'checked' : ''}>
            </td>
            <td class="key-name" title="${escapeHtml(key.key)}">
                <code>${escapeHtml(truncateKey(key.key))}</code>
            </td>
            <td><span class="type-badge type-${key.type}">${key.type}</span></td>
            <td>${formatSize(key.size, key.type)}</td>
            <td>${formatTTL(key.ttl)}</td>
            <td>${key.expires_at ? formatTime(key.expires_at) : '-'}</td>
            <td class="actions-cell">
                <button class="btn btn-sm btn-secondary" onclick="viewKey('${escapeHtml(key.key)}')">查看</button>
                <button class="btn btn-sm btn-secondary" onclick="editTTL('${escapeHtml(key.key)}', ${key.ttl})">TTL</button>
                <button class="btn btn-sm btn-danger" onclick="deleteKey('${escapeHtml(key.key)}')">删除</button>
            </td>
        </tr>
    `).join('');
    
    // 绑定复选框事件
    elements.keysTableBody.querySelectorAll('.key-checkbox').forEach(cb => {
        cb.addEventListener('change', (e) => {
            const key = e.target.dataset.key;
            if (e.target.checked) {
                state.selectedKeys.add(key);
            } else {
                state.selectedKeys.delete(key);
            }
            updateBatchDeleteButton();
        });
    });
    
    // 绑定行双击事件 - 点击查看 key 值
    elements.keysTableBody.querySelectorAll('tr').forEach(row => {
        row.addEventListener('dblclick', (e) => {
            // 避免在复选框和按钮上触发
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'BUTTON' || e.target.closest('button')) {
                return;
            }
            const key = row.dataset.key;
            if (key) {
                viewKey(key);
            }
        });
    });
}

function updatePagination() {
    elements.currentPage.textContent = state.pagination.page;
    elements.prevPage.disabled = state.pagination.page <= 1;
    elements.nextPage.disabled = state.pagination.page * state.pagination.limit >= state.pagination.total;
    elements.paginationInfo.textContent = `共 ${state.pagination.total} 条，第 ${state.pagination.page} 页`;
}

function updateBatchDeleteButton() {
    elements.batchDeleteBtn.disabled = state.selectedKeys.size === 0;
    elements.batchDeleteBtn.textContent = `批量删除 (${state.selectedKeys.size})`;
}

// ==================== 交互功能 ====================

function changePage(delta) {
    const newPage = state.pagination.page + delta;
    if (newPage < 1) return;
    
    state.pagination.page = newPage;
    searchKeys();
}

async function testConnection() {
    const config = {
        host: elements.redisHost.value || 'localhost',
        port: parseInt(elements.redisPort.value) || 6379,
        db: parseInt(elements.redisDb.value) || 0,
        password: elements.redisPassword.value || null
    };
    
    try {
        const result = await apiPost('/api/redis/connect', config);
        showNotification('连接成功', result.message);
    } catch (error) {
        showError('连接失败: ' + error.message);
    }
}

async function saveConnection() {
    const config = {
        host: elements.redisHost.value || 'localhost',
        port: parseInt(elements.redisPort.value) || 6379,
        db: parseInt(elements.redisDb.value) || 0,
        password: elements.redisPassword.value || null
    };
    
    try {
        const result = await apiPost('/api/redis/connect', config);
        showNotification('连接成功', result.message);
        elements.connectModal.classList.remove('active');
        loadStats();
        loadNamespaces();
        searchKeys();
    } catch (error) {
        showError('连接失败: ' + error.message);
    }
}

async function viewKey(key) {
    try {
        const data = await apiGet(`/api/redis/keys/${encodeURIComponent(key)}`);
        showKeyValue(data);
    } catch (error) {
        showError('获取键值失败: ' + error.message);
    }
}

function showKeyValue(data) {
    state.currentKey = data.key;
    
    let valueHtml = renderValueByType(data.type, data.value);
    
    elements.valueModalBody.innerHTML = `
        <div class="log-detail">
            <div class="detail-section">
                <h4>基本信息</h4>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">键名</span>
                        <span class="detail-value id"><code>${escapeHtml(data.key)}</code></span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">类型</span>
                        <span class="detail-value"><span class="type-badge type-${data.type}">${data.type}</span></span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">大小</span>
                        <span class="detail-value">${formatSize(data.size, data.type)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">TTL</span>
                        <span class="detail-value">${formatTTL(data.ttl)}</span>
                    </div>
                    ${data.expires_at ? `
                    <div class="detail-item">
                        <span class="detail-label">过期时间</span>
                        <span class="detail-value">${formatTime(data.expires_at)}</span>
                    </div>
                    ` : ''}
                </div>
            </div>
            
            <div class="detail-section">
                <h4>值内容</h4>
                ${valueHtml}
            </div>
        </div>
    `;
    
    elements.valueModal.classList.add('active');
}

function renderValueByType(type, value) {
    if (type === 'string') {
        return renderDecodedValue(value);
    } else if (type === 'hash') {
        return renderHashValue(value);
    } else if (type === 'list') {
        return renderListValue(value);
    } else if (type === 'set') {
        return renderSetValue(value);
    } else if (type === 'zset') {
        return renderZSetValue(value);
    }
    return renderRawValue(value);
}

function renderDecodedValue(value) {
    // 处理解码后的值对象
    if (value && typeof value === 'object' && value.type) {
        const { type, format, value: actualValue, preview, truncated, class_name, data_type, is_dataclass } = value;
        
        // 特殊处理 FunctionSummary 类型
        if (data_type === 'function_summary' || data_type === 'function_summary_dict') {
            return renderFunctionSummary(actualValue, data_type);
        }
        
        // 特殊处理分析状态类型
        if (data_type === 'analysis_state') {
            return renderAnalysisState(actualValue);
        }
        
        if (type === 'structured') {
            // 结构化数据（对象、数组等）
            const jsonStr = JSON.stringify(actualValue, null, 2);
            return renderValueCard('JSON', 'bi-braces', jsonStr, 'json');
        } else if (type === 'text') {
            // 文本数据
            const displayValue = truncated ? preview : actualValue;
            return renderValueCard('Text', 'bi-file-text', displayValue, 'text', truncated);
        } else if (type === 'number' || type === 'boolean' || type === 'null') {
            // 简单类型
            return renderSimpleValueCard(class_name || type, actualValue, type);
        } else if (type === 'object') {
            // 自定义对象
            return renderValueCard(class_name || 'Object', 'bi-box', preview || String(actualValue), 'object', truncated);
        }
    }
    
    // 原始值（未解码格式）
    return renderRawValue(value);
}

// 渲染值卡片（参照日志详情的 message-card 样式）
function renderValueCard(title, icon, content, contentType, truncated = false) {
    let contentHtml = '';
    
    if (contentType === 'json') {
        contentHtml = `<pre class="value-content json-value"><code>${escapeHtml(content)}</code></pre>`;
    } else if (contentType === 'text') {
        contentHtml = `<pre class="value-content text-value">${escapeHtml(content)}</pre>`;
    } else if (contentType === 'object') {
        contentHtml = `<pre class="value-content object-value">${escapeHtml(content)}</pre>`;
    } else {
        contentHtml = `<div class="value-content">${escapeHtml(String(content))}</div>`;
    }
    
    return `
        <div class="message-list">
            <div class="message-card">
                <div class="message-card-header" onclick="toggleMessageCard(this)">
                    <div class="message-meta">
                        <span class="msg-type-badge badge-system">
                            <i class="bi ${icon}"></i> ${title}
                        </span>
                        ${truncated ? '<span class="value-size-warning">已截断</span>' : ''}
                    </div>
                    <i class="bi bi-chevron-down message-toggle-icon"></i>
                </div>
                <div class="message-card-body">
                    ${contentHtml}
                </div>
            </div>
        </div>
    `;
}

// 渲染简单值卡片
function renderSimpleValueCard(typeName, value, type) {
    const typeColors = {
        'number': '#059669',
        'boolean': '#7c3aed',
        'null': '#94a3b8',
        'string': '#1e40af'
    };
    const color = typeColors[type] || 'var(--text-main)';
    
    return `
        <div class="message-list">
            <div class="message-card">
                <div class="message-card-header" onclick="toggleMessageCard(this)">
                    <div class="message-meta">
                        <span class="msg-type-badge badge-ai">
                            <i class="bi bi-hash"></i> ${typeName}
                        </span>
                    </div>
                    <i class="bi bi-chevron-down message-toggle-icon"></i>
                </div>
                <div class="message-card-body">
                    <div class="value-content simple-value ${type}-value" style="color: ${color}; font-size: 24px; font-weight: 600; text-align: center; padding: 40px;">
                        ${escapeHtml(String(value))}
                    </div>
                </div>
            </div>
        </div>
    `;
}

// 渲染原始值
function renderRawValue(value) {
    const displayValue = typeof value === 'object' 
        ? JSON.stringify(value, null, 2) 
        : String(value);
    
    return `
        <div class="message-list">
            <div class="message-card">
                <div class="message-card-header" onclick="toggleMessageCard(this)">
                    <div class="message-meta">
                        <span class="msg-type-badge badge-default">
                            <i class="bi bi-file-binary"></i> Raw Value
                        </span>
                    </div>
                    <i class="bi bi-chevron-down message-toggle-icon"></i>
                </div>
                <div class="message-card-body">
                    <pre class="value-content raw-value">${escapeHtml(displayValue)}</pre>
                </div>
            </div>
        </div>
    `;
}

// 渲染函数摘要（FunctionSummary）
function renderFunctionSummary(data, dataType) {
    // 提取实际的摘要对象
    let summary = data;
    if (data && data.value) {
        summary = data.value;
    }
    if (!summary || typeof summary !== 'object') {
        return renderRawValue(data);
    }
    
    // 提取 SimpleFunctionSummary 的关键信息
    const functionName = summary.function_identifier || summary.function_name || 'Unknown';
    const behaviorSummary = summary.behavior_summary || '';
    const returnValue = summary.return_value_meaning || '';
    const globalVarOps = summary.global_var_operations || '';
    const paramConstraints = Array.isArray(summary.param_constraints) ? summary.param_constraints : [];
    
    // 构建内容 HTML
    let contentHtml = `
        <div class="fs-content">
            <!-- 函数基本信息 -->
            <div class="fs-section">
                <h5 class="fs-section-title"><i class="bi bi-link"></i> 函数信息</h5>
                <div class="detail-grid" style="grid-template-columns: 1fr;">
                    <div class="detail-item">
                        <span class="detail-label">函数签名</span>
                        <code class="detail-value" style="font-size: 13px;">${escapeHtml(functionName)}</code>
                    </div>
                    ${returnValue ? `
                    <div class="detail-item">
                        <span class="detail-label">返回值</span>
                        <span class="detail-value">${escapeHtml(returnValue)}</span>
                    </div>` : ''}
                </div>
            </div>
            
            <!-- 行为总结 -->
            ${behaviorSummary ? `
            <div class="fs-section">
                <h5 class="fs-section-title"><i class="bi bi-info-circle"></i> 行为总结</h5>
                <div class="fs-text-content">${escapeHtml(behaviorSummary)}</div>
            </div>` : ''}
            
            <!-- 参数约束 -->
            <div class="fs-section">
                <h5 class="fs-section-title"><i class="bi bi-list-check"></i> 参数约束 (${paramConstraints.length})</h5>
                ${paramConstraints.length > 0 ? `
                <div class="fs-constraints-list">
                    ${paramConstraints.map((constraint, idx) => `
                        <div class="fs-constraint-item">
                            <span class="fs-constraint-num">${idx + 1}.</span>
                            <span class="fs-constraint-text">${escapeHtml(constraint)}</span>
                        </div>
                    `).join('')}
                </div>` : '<p class="fs-empty-hint">该函数没有参数约束信息</p>'}
            </div>
            
            <!-- 全局变量操作 -->
            ${globalVarOps ? `
            <div class="fs-section">
                <h5 class="fs-section-title"><i class="bi bi-globe"></i> 全局变量操作</h5>
                <div class="fs-text-content">${escapeHtml(globalVarOps)}</div>
            </div>` : ''}
            
            <!-- JSON 原始数据 -->
            <div class="fs-section">
                <h5 class="fs-section-title"><i class="bi bi-braces"></i> JSON 数据</h5>
                <pre class="value-content json-value"><code>${escapeHtml(JSON.stringify(summary, null, 2))}</code></pre>
            </div>
        </div>
    `;
    
    return renderCollectionCard('FunctionSummary', 'bi-code-square', '函数摘要', contentHtml);
}

function renderHashValue(value) {
    if (!value || Object.keys(value).length === 0) {
        return renderEmptyValueCard('Hash', '空 Hash');
    }
    
    const entries = Object.entries(value);
    const tableHtml = `
        <table class="value-table hash-table">
            <thead><tr><th>字段</th><th>值</th></tr></thead>
            <tbody>
                ${entries.map(([k, v]) => `
                    <tr>
                        <td class="field-name"><code>${escapeHtml(k)}</code></td>
                        <td class="field-value">${renderInlineValue(v)}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
    
    return renderCollectionCard('Hash', 'bi-diagram-2', `${entries.length} 字段`, tableHtml);
}

function renderListValue(value) {
    if (!value || value.length === 0) {
        return renderEmptyValueCard('List', '空 List');
    }
    
    const listHtml = `
        <ol class="value-list structured-list">
            ${value.map((v, i) => `
                <li>
                    <span class="list-index">[${i}]</span>
                    ${renderInlineValue(v)}
                </li>
            `).join('')}
        </ol>
    `;
    
    return renderCollectionCard('List', 'bi-list-ol', `${value.length} 项`, listHtml);
}

function renderSetValue(value) {
    if (!value || value.length === 0) {
        return renderEmptyValueCard('Set', '空 Set');
    }
    
    const listHtml = `
        <ul class="value-list structured-list set-list">
            ${value.map(v => `<li>${renderInlineValue(v)}</li>`).join('')}
        </ul>
    `;
    
    return renderCollectionCard('Set', 'bi-collection', `${value.length} 项`, listHtml);
}

function renderZSetValue(value) {
    if (!value || value.length === 0) {
        return renderEmptyValueCard('ZSet', '空 ZSet');
    }
    
    const tableHtml = `
        <table class="value-table zset-table">
            <thead><tr><th>成员</th><th>分数</th></tr></thead>
            <tbody>
                ${value.map(item => `
                    <tr>
                        <td>${renderInlineValue(item.member)}</td>
                        <td class="score-value">${item.score}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
    
    return renderCollectionCard('ZSet', 'bi-sort-numeric-down', `${value.length} 项`, tableHtml);
}

function renderInlineValue(value) {
    // 处理解码后的值
    if (value && typeof value === 'object' && value.type) {
        const { type, format, preview, value: actualValue } = value;
        
        if (type === 'structured') {
            const jsonStr = JSON.stringify(actualValue);
            const display = jsonStr.length > 100 ? jsonStr.substring(0, 100) + '...' : jsonStr;
            return `<code class="inline-code structured" title="${format}">${escapeHtml(display)}</code>`;
        } else if (type === 'text') {
            const text = preview || actualValue;
            const display = text.length > 100 ? text.substring(0, 100) + '...' : text;
            return `<span class="inline-text" title="${format}">${escapeHtml(display)}</span>`;
        } else if (type === 'number' || type === 'boolean') {
            return `<code class="inline-code ${type}">${escapeHtml(String(actualValue))}</code>`;
        }
    }
    
    // 原始值
    const str = typeof value === 'object' ? JSON.stringify(value) : String(value);
    const display = str.length > 100 ? str.substring(0, 100) + '...' : str;
    return `<code class="inline-code">${escapeHtml(display)}</code>`;
}

// 渲染集合卡片
function renderCollectionCard(title, icon, sizeInfo, contentHtml) {
    return `
        <div class="message-list">
            <div class="message-card">
                <div class="message-card-header" onclick="toggleMessageCard(this)">
                    <div class="message-meta">
                        <span class="msg-type-badge badge-tool">
                            <i class="bi ${icon}"></i> ${title}
                        </span>
                        <span class="value-size-info">${sizeInfo}</span>
                    </div>
                    <i class="bi bi-chevron-down message-toggle-icon"></i>
                </div>
                <div class="message-card-body">
                    ${contentHtml}
                </div>
            </div>
        </div>
    `;
}

// 渲染空值卡片
function renderEmptyValueCard(type, message) {
    return `
        <div class="message-list">
            <div class="message-card">
                <div class="message-card-header" onclick="toggleMessageCard(this)">
                    <div class="message-meta">
                        <span class="msg-type-badge badge-default">
                            <i class="bi bi-inbox"></i> ${type}
                        </span>
                    </div>
                    <i class="bi bi-chevron-down message-toggle-icon"></i>
                </div>
                <div class="message-card-body">
                    <div class="empty-value" style="text-align: center; padding: 40px; color: var(--text-secondary);">
                        <i class="bi bi-inbox" style="font-size: 32px; display: block; margin-bottom: 12px; opacity: 0.5;"></i>
                        ${message}
                    </div>
                </div>
            </div>
        </div>
    `;
}

// 切换消息卡片折叠状态（参照 app.js）
function toggleMessageCard(header) {
    const card = header.closest('.message-card');
    const body = card.querySelector('.message-card-body');
    const icon = header.querySelector('.message-toggle-icon');
    
    if (body) {
        const isCollapsed = body.style.display === 'none';
        body.style.display = isCollapsed ? 'block' : 'none';
        icon.style.transform = isCollapsed ? 'rotate(0deg)' : 'rotate(-90deg)';
    }
}

function editTTL(key, currentTTL) {
    state.currentKey = key;
    elements.ttlKey.value = key;
    elements.ttlValue.value = currentTTL > 0 ? currentTTL : -1;
    elements.ttlModal.classList.add('active');
}

async function updateTTL() {
    const key = elements.ttlKey.value;
    const ttl = parseInt(elements.ttlValue.value);
    
    try {
        await apiPut('/api/redis/keys/ttl', { key, ttl });
        showNotification('成功', 'TTL 已更新');
        elements.ttlModal.classList.remove('active');
        searchKeys();
    } catch (error) {
        showError('更新 TTL 失败: ' + error.message);
    }
}

async function deleteKey(key) {
    if (!confirm(`确定要删除键 "${key}" 吗？`)) {
        return;
    }
    
    try {
        await apiDelete('/api/redis/keys', { keys: [key] });
        showNotification('成功', '键已删除');
        searchKeys();
        loadStats();
    } catch (error) {
        showError('删除失败: ' + error.message);
    }
}

async function batchDelete() {
    const keys = Array.from(state.selectedKeys);
    if (keys.length === 0) return;
    
    if (!confirm(`确定要删除选中的 ${keys.length} 个键吗？`)) {
        return;
    }
    
    try {
        await apiDelete('/api/redis/keys', { keys });
        showNotification('成功', `已删除 ${keys.length} 个键`);
        state.selectedKeys.clear();
        searchKeys();
        loadStats();
    } catch (error) {
        showError('批量删除失败: ' + error.message);
    }
}

// ==================== 清空全部功能 ====================

function openClearAllModal() {
    if (!state.connected) {
        showError('Redis 未连接');
        return;
    }
    
    // 获取当前键数
    const totalKeys = state.pagination.total;
    elements.clearAllCount.textContent = totalKeys.toLocaleString();
    
    // 重置按钮状态
    elements.confirmClearAllBtn.disabled = false;
    elements.confirmClearAllBtn.textContent = '确认清空';
    
    // 显示弹窗
    elements.clearAllModal.classList.add('active');
}

function closeClearAllModal() {
    elements.clearAllModal.classList.remove('active');
}

async function confirmClearAll() {
    try {
        elements.confirmClearAllBtn.disabled = true;
        elements.confirmClearAllBtn.textContent = '清空中...';
        
        const result = await apiDelete('/api/redis/flush?confirm=DELETE ALL');
        
        showNotification('成功', result.message);
        closeClearAllModal();
        
        // 刷新数据
        searchKeys();
        loadStats();
    } catch (error) {
        showError('清空失败: ' + error.message);
    } finally {
        elements.confirmClearAllBtn.disabled = false;
        elements.confirmClearAllBtn.textContent = '确认清空';
    }
}

// ==================== 调试功能 ====================

async function toggleDebugPanel() {
    const panel = document.getElementById('debug-panel');
    const content = document.getElementById('debug-content');
    const btn = document.getElementById('show-debug-btn');
    
    if (panel.style.display === 'none') {
        panel.style.display = 'block';
        btn.style.display = 'none';
        
        // 加载所有键
        content.innerHTML = '<p>加载中...</p>';
        try {
            const result = await apiPost('/api/redis/keys/search', {
                pattern: '*',
                limit: 1000,
                offset: 0
            });
            
            if (result.keys.length === 0) {
                content.innerHTML = '<p>没有键</p>';
            } else {
                const listHtml = result.keys.map(k => `
                    <div class="debug-key-item">
                        <code>${escapeHtml(k.key)}</code>
                        <span class="debug-key-type">${k.type}</span>
                        <span class="debug-key-size">${formatSize(k.size, k.type)}</span>
                    </div>
                `).join('');
                content.innerHTML = `<div class="debug-key-list">${listHtml}</div><p>共 ${result.total} 个键</p>`;
            }
        } catch (error) {
            content.innerHTML = `<p class="error">加载失败: ${error.message}</p>`;
        }
    } else {
        panel.style.display = 'none';
        btn.style.display = 'inline-block';
    }
}

// ==================== 工具函数 ====================

function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString('zh-CN', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function formatTTL(ttl) {
    if (ttl < 0) return '永不过期';
    if (ttl < 60) return `${ttl} 秒`;
    if (ttl < 3600) return `${Math.floor(ttl / 60)} 分钟`;
    if (ttl < 86400) return `${Math.floor(ttl / 3600)} 小时`;
    return `${Math.floor(ttl / 86400)} 天`;
}

function formatSize(size, type) {
    if (type === 'string') {
        if (size < 1024) return `${size} B`;
        if (size < 1024 * 1024) return `${(size / 1024).toFixed(2)} KB`;
        return `${(size / (1024 * 1024)).toFixed(2)} MB`;
    }
    return `${size} 项`;
}

function truncateKey(key, maxLength = 50) {
    if (key.length <= maxLength) return key;
    return key.substring(0, maxLength) + '...';
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showNotification(title, message) {
    // 简单的通知实现
    console.log(`[${title}] ${message}`);
    // 可以扩展为 toast 通知
}

// 显示错误信息（在页面上静默显示，不使用 alert）
function showError(message) {
    // 只在控制台输出，不弹窗打扰用户
    console.error('[Error]', message);
    
    // 在页面顶部显示一个非侵入式的提示条
    let errorBar = document.getElementById('error-notification-bar');
    if (!errorBar) {
        errorBar = document.createElement('div');
        errorBar.id = 'error-notification-bar';
        errorBar.style.cssText = 'position: fixed; top: 0; left: 0; right: 0; background: #dc3545; color: white; padding: 8px 16px; text-align: center; z-index: 9999; font-size: 14px; display: none;';
        document.body.prepend(errorBar);
    }
    
    errorBar.textContent = message;
    errorBar.style.display = 'block';
    
    // 3秒后自动隐藏
    setTimeout(() => {
        errorBar.style.display = 'none';
    }, 3000);
}

// 渲染分析状态
function renderAnalysisState(stateValue) {
    const stateColors = {
        'pending': { bg: '#fef3c7', text: '#92400e', border: '#fbbf24', label: '等待中', icon: 'bi-hourglass' },
        'analyzing': { bg: '#dbeafe', text: '#1e40af', border: '#60a5fa', label: '分析中', icon: 'bi-arrow-repeat' },
        'completed': { bg: '#d1fae5', text: '#065f46', border: '#34d399', label: '已完成', icon: 'bi-check-circle' },
        'failed': { bg: '#fee2e2', text: '#991b1b', border: '#f87171', label: '失败', icon: 'bi-x-circle' }
    };
    
    const stateInfo = stateColors[stateValue] || { bg: '#f3f4f6', text: '#4b5563', border: '#d1d5db', label: stateValue, icon: 'bi-question-circle' };
    
    const contentHtml = `
        <div class="analysis-state-content" style="padding: 24px; text-align: center;">
            <div class="state-badge" style="
                display: inline-flex;
                align-items: center;
                gap: 12px;
                padding: 16px 32px;
                background: ${stateInfo.bg};
                color: ${stateInfo.text};
                border: 1px solid ${stateInfo.border};
                border-radius: 12px;
                font-size: 18px;
                font-weight: 600;
            ">
                <i class="bi ${stateInfo.icon}" style="font-size: 20px;"></i>
                <span class="state-indicator" style="
                    width: 12px;
                    height: 12px;
                    background: ${stateInfo.border};
                    border-radius: 50%;
                    ${stateValue === 'analyzing' ? 'animation: pulse 1.5s infinite;' : ''}
                "></span>
                ${escapeHtml(stateInfo.label)}
            </div>
            <div class="state-raw" style="margin-top: 20px; font-size: 13px; color: var(--text-secondary);">
                原始值: <code>${escapeHtml(stateValue)}</code>
            </div>
        </div>
    `;
    
    return renderCollectionCard('AnalysisState', 'bi-activity', '分析状态', contentHtml);
}

// 启动应用
document.addEventListener('DOMContentLoaded', init);
