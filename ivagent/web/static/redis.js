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
        }
        if (e.key === 'r' && e.ctrlKey) {
            e.preventDefault();
            loadStats();
            searchKeys();
        }
    });
}

// ==================== API 调用 ====================

async function apiGet(endpoint) {
    const response = await fetch(`${API_BASE}${endpoint}`);
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || `HTTP ${response.status}`);
    }
    return response.json();
}

async function apiPost(endpoint, data) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || `HTTP ${response.status}`);
    }
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
    const response = await fetch(`${API_BASE}${endpoint}`, options);
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || `HTTP ${response.status}`);
    }
    return response.json();
}

async function apiPut(endpoint, data) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
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
    elements.redisStatus.classList.toggle('connected', connected);
    elements.redisStatusText.textContent = connected ? '已连接' : '未连接';
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
        <div class="key-detail">
            <div class="detail-section">
                <h4>基本信息</h4>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">键名</span>
                        <span class="detail-value"><code>${escapeHtml(data.key)}</code></span>
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
                <div class="value-container">
                    ${valueHtml}
                </div>
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
    return `<pre class="value-content">${escapeHtml(String(value))}</pre>`;
}

function renderDecodedValue(value) {
    // 处理解码后的值对象
    if (value && typeof value === 'object' && value.type) {
        const { type, format, value: actualValue, preview, truncated, class_name, data_type, is_dataclass } = value;
        
        let formatBadge = format ? `<span class="format-badge">${format}</span>` : '';
        let typeBadge = `<span class="value-type-badge">${class_name || type}</span>`;
        let dataTypeBadge = data_type ? `<span class="data-type-badge" data-type="${data_type}">${data_type}</span>` : '';
        
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
            return `
                <div class="value-header">
                    ${typeBadge}
                    ${dataTypeBadge}
                    ${formatBadge}
                    <span class="value-size">${value.size || 0} bytes</span>
                </div>
                <pre class="value-content json-value"><code>${escapeHtml(jsonStr)}</code></pre>
            `;
        } else if (type === 'text') {
            // 文本数据
            const displayValue = truncated ? preview : actualValue;
            return `
                <div class="value-header">
                    ${typeBadge}
                    ${dataTypeBadge}
                    ${formatBadge}
                    <span class="value-size">${value.size || 0} chars</span>
                </div>
                <pre class="value-content text-value">${escapeHtml(displayValue)}</pre>
                ${truncated ? '<div class="value-truncated">内容已截断，完整数据更大</div>' : ''}
            `;
        } else if (type === 'number' || type === 'boolean' || type === 'null') {
            // 简单类型
            return `
                <div class="value-header">
                    ${typeBadge}
                    ${dataTypeBadge}
                    ${formatBadge}
                </div>
                <div class="value-content simple-value ${type}-value">${escapeHtml(String(actualValue))}</div>
            `;
        } else if (type === 'object') {
            // 自定义对象
            return `
                <div class="value-header">
                    ${typeBadge}
                    ${dataTypeBadge}
                    ${formatBadge}
                </div>
                <pre class="value-content object-value">${escapeHtml(preview || String(actualValue))}</pre>
                ${truncated ? '<div class="value-truncated">内容已截断</div>' : ''}
            `;
        }
    }
    
    // 原始值（未解码格式）
    const displayValue = typeof value === 'object' 
        ? JSON.stringify(value, null, 2) 
        : String(value);
    return `<pre class="value-content raw-value">${escapeHtml(displayValue)}</pre>`;
}

// 渲染函数摘要（FunctionSummary）
function renderFunctionSummary(data, dataType) {
    console.log('renderFunctionSummary called with:', data);
    
    // 提取实际的摘要对象
    let summary = data;
    if (data && data.value) {
        summary = data.value;
    }
    if (!summary || typeof summary !== 'object') {
        console.log('Invalid summary data:', summary);
        return `<pre class="value-content raw-value">${escapeHtml(String(data))}</pre>`;
    }
    
    // 调试：输出实际的数据内容
    console.log('FunctionSummary summary:', summary);
    console.log('param_constraints:', summary.param_constraints);
    console.log('Array.isArray(param_constraints):', Array.isArray(summary.param_constraints));
    
    // 提取 SimpleFunctionSummary 的关键信息
    const functionName = summary.function_signature || summary.function_name || 'Unknown';
    const behaviorSummary = summary.behavior_summary || '';
    const returnValue = summary.return_value_meaning || '';
    const globalVarOps = summary.global_var_operations || '';
    const paramConstraints = Array.isArray(summary.param_constraints) ? summary.param_constraints : [];
    console.log('paramConstraints extracted:', paramConstraints);
    
    return `
        <div class="value-header">
            <span class="value-type-badge function-summary">SimpleFunctionSummary</span>
            <span class="data-type-badge" data-type="function_summary">函数摘要</span>
        </div>
        <div class="function-summary-container">
            <!-- 函数基本信息 -->
            <div class="fs-section">
                <h4 class="fs-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
                        <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
                    </svg>
                    函数信息
                </h4>
                <div class="fs-info-grid">
                    <div class="fs-info-item">
                        <span class="fs-label">函数签名</span>
                        <code class="fs-value">${escapeHtml(functionName)}</code>
                    </div>
                    ${returnValue ? `
                    <div class="fs-info-item">
                        <span class="fs-label">返回值</span>
                        <span class="fs-value">${escapeHtml(returnValue)}</span>
                    </div>` : ''}
                </div>
            </div>
            
            <!-- 行为总结 -->
            ${behaviorSummary ? `
            <div class="fs-section">
                <h4 class="fs-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="12" y1="16" x2="12" y2="12"></line>
                        <line x1="12" y1="8" x2="12.01" y2="8"></line>
                    </svg>
                    行为总结
                </h4>
                <p class="fs-behavior">${escapeHtml(behaviorSummary)}</p>
            </div>` : ''}
            
            <!-- 参数约束 -->
            <div class="fs-section">
                <h4 class="fs-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="4" y1="9" x2="20" y2="9"></line>
                        <line x1="4" y1="15" x2="20" y2="15"></line>
                        <line x1="10" y1="3" x2="8" y2="21"></line>
                        <line x1="16" y1="3" x2="14" y2="21"></line>
                    </svg>
                    参数约束 (${paramConstraints.length})
                </h4>
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
                <h4 class="fs-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
                        <polyline points="2 17 12 22 22 17"></polyline>
                        <polyline points="2 12 12 17 22 12"></polyline>
                    </svg>
                    全局变量操作
                </h4>
                <p class="fs-global-ops">${escapeHtml(globalVarOps)}</p>
            </div>` : ''}
            
            <!-- JSON 原始数据 -->
            <div class="fs-section">
                <h4 class="fs-title">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="16 18 22 12 16 6"></polyline>
                        <polyline points="8 6 2 12 8 18"></polyline>
                    </svg>
                    JSON 数据
                </h4>
                <pre class="fs-json-content"><code>${escapeHtml(JSON.stringify(summary, null, 2))}</code></pre>
            </div>
        </div>
    `;
}

function renderHashValue(value) {
    if (!value || Object.keys(value).length === 0) {
        return '<div class="empty-value">空 Hash</div>';
    }
    
    const entries = Object.entries(value);
    return `
        <div class="value-header">
            <span class="value-type-badge">Hash</span>
            <span class="value-size">${entries.length} 字段</span>
        </div>
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
}

function renderListValue(value) {
    if (!value || value.length === 0) {
        return '<div class="empty-value">空 List</div>';
    }
    
    return `
        <div class="value-header">
            <span class="value-type-badge">List</span>
            <span class="value-size">${value.length} 项</span>
        </div>
        <ol class="value-list structured-list">
            ${value.map((v, i) => `
                <li>
                    <span class="list-index">[${i}]</span>
                    ${renderInlineValue(v)}
                </li>
            `).join('')}
        </ol>
    `;
}

function renderSetValue(value) {
    if (!value || value.length === 0) {
        return '<div class="empty-value">空 Set</div>';
    }
    
    return `
        <div class="value-header">
            <span class="value-type-badge">Set</span>
            <span class="value-size">${value.length} 项</span>
        </div>
        <ul class="value-list structured-list set-list">
            ${value.map(v => `<li>${renderInlineValue(v)}</li>`).join('')}
        </ul>
    `;
}

function renderZSetValue(value) {
    if (!value || value.length === 0) {
        return '<div class="empty-value">空 ZSet</div>';
    }
    
    return `
        <div class="value-header">
            <span class="value-type-badge">ZSet</span>
            <span class="value-size">${value.length} 项</span>
        </div>
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

function showError(message) {
    alert(message);
}

// 渲染分析状态
function renderAnalysisState(state) {
    const stateColors = {
        'pending': { bg: '#fef3c7', text: '#92400e', border: '#fbbf24', label: '等待中' },
        'analyzing': { bg: '#dbeafe', text: '#1e40af', border: '#60a5fa', label: '分析中' },
        'completed': { bg: '#d1fae5', text: '#065f46', border: '#34d399', label: '已完成' },
        'failed': { bg: '#fee2e2', text: '#991b1b', border: '#f87171', label: '失败' }
    };
    
    const stateInfo = stateColors[state] || { bg: '#f3f4f6', text: '#4b5563', border: '#d1d5db', label: state };
    
    return `
        <div class="value-header">
            <span class="value-type-badge" style="background: ${stateInfo.bg}; color: ${stateInfo.text}; border-color: ${stateInfo.border};">
                AnalysisState
            </span>
            <span class="data-type-badge" data-type="analysis_state">分析状态</span>
        </div>
        <div class="analysis-state-container">
            <div class="state-badge" style="
                display: inline-flex;
                align-items: center;
                gap: 8px;
                padding: 12px 24px;
                background: ${stateInfo.bg};
                color: ${stateInfo.text};
                border: 1px solid ${stateInfo.border};
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
            ">
                <span class="state-indicator" style="
                    width: 10px;
                    height: 10px;
                    background: ${stateInfo.border};
                    border-radius: 50%;
                    ${state === 'analyzing' ? 'animation: pulse 1.5s infinite;' : ''}
                "></span>
                ${escapeHtml(stateInfo.label)}
            </div>
            <div class="state-raw" style="margin-top: 16px; font-size: 12px; color: #6b7280;">
                原始值: <code>${escapeHtml(state)}</code>
            </div>
        </div>
    `;
}

// 启动应用
document.addEventListener('DOMContentLoaded', init);
