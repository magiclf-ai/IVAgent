/**
 * LLM 交互日志可视化系统 - 前端应用
 */

// API 基础 URL
const API_BASE = '';

// 全局状态
const state = {
    currentView: 'dashboard',
    logs: [],
    sessions: [],
    stats: {},
    pagination: {
        page: 1,
        limit: 20,
        total: 0
    },
    filters: {
        session_id: '',
        call_type: '',
        model: '',
        success: '',
        start_time: '',
        end_time: '',
        search: ''
    },
    charts: {}
};

// 日志状态管理（已查看、标注）
const logStateManager = {
    VIEWED_KEY: 'llm_logger_viewed_logs',
    STARRED_KEY: 'llm_logger_starred_logs',
    
    // 获取已查看的日志ID集合
    getViewedLogs() {
        const data = localStorage.getItem(this.VIEWED_KEY);
        return data ? new Set(JSON.parse(data)) : new Set();
    },
    
    // 标记日志为已查看
    markAsViewed(logId) {
        const viewed = this.getViewedLogs();
        viewed.add(logId);
        localStorage.setItem(this.VIEWED_KEY, JSON.stringify([...viewed]));
    },
    
    // 检查日志是否已查看
    isViewed(logId) {
        return this.getViewedLogs().has(logId);
    },
    
    // 获取已标注的日志ID集合
    getStarredLogs() {
        const data = localStorage.getItem(this.STARRED_KEY);
        return data ? new Set(JSON.parse(data)) : new Set();
    },
    
    // 切换日志标注状态
    toggleStarred(logId) {
        const starred = this.getStarredLogs();
        if (starred.has(logId)) {
            starred.delete(logId);
        } else {
            starred.add(logId);
        }
        localStorage.setItem(this.STARRED_KEY, JSON.stringify([...starred]));
        return starred.has(logId);
    },
    
    // 检查日志是否已标注
    isStarred(logId) {
        return this.getStarredLogs().has(logId);
    }
};

// DOM 元素
const elements = {};

// 初始化
async function init() {
    cacheElements();
    bindEvents();
    
    // 先加载页面数据，确保页面快速渲染
    await loadDashboard();
    
    // 延迟加载筛选器
    setTimeout(loadFilters, 100);
    
    // 启动 RESTful 轮询
    startPolling();
}

// 缓存 DOM 元素
function cacheElements() {
    // 导航
    elements.navItems = document.querySelectorAll('.nav-item');
    elements.views = document.querySelectorAll('.view');
    
    // 仪表盘
    elements.statSuccess = document.getElementById('stat-success');
    elements.statFailed = document.getElementById('stat-failed');
    elements.statTotal = document.getElementById('stat-total');
    elements.statRate = document.getElementById('stat-rate');
    
    // 日志列表
    elements.logsTableBody = document.querySelector('#logs-table tbody');
    elements.paginationInfo = document.getElementById('pagination-info');
    elements.currentPage = document.getElementById('current-page');
    elements.prevPage = document.getElementById('prev-page');
    elements.nextPage = document.getElementById('next-page');
    
    // 筛选器
    elements.filterSession = document.getElementById('filter-session');
    elements.filterModel = document.getElementById('filter-model');
    elements.filterType = document.getElementById('filter-type');
    elements.filterStatus = document.getElementById('filter-status');
    elements.filterStart = document.getElementById('filter-start');
    elements.filterEnd = document.getElementById('filter-end');
    elements.filterSearch = document.getElementById('filter-search');
    elements.applyFilters = document.getElementById('apply-filters');
    elements.clearFilters = document.getElementById('clear-filters');
    
    // Agent 筛选器
    elements.filterAgentType = document.getElementById('filter-agent-type');
    elements.filterAgentStatus = document.getElementById('filter-agent-status');
    elements.applyAgentFilters = document.getElementById('apply-agent-filters');
    elements.clearAgentFilters = document.getElementById('clear-agent-filters');
    elements.agentsTimeline = document.getElementById('agents-timeline');
    
    // 会话
    elements.sessionsGrid = document.getElementById('sessions-grid');
    
    // 弹窗
    elements.modal = document.getElementById('log-modal');
    elements.modalBody = document.getElementById('modal-body');
    elements.closeModal = document.getElementById('close-modal');
    
    // 其他
    elements.refreshBtn = document.getElementById('refresh-btn');
    elements.exportBtn = document.getElementById('export-btn');
    elements.wsStatus = document.getElementById('ws-status');
    elements.wsText = document.getElementById('ws-text');
    
    // 全局搜索
    elements.globalSearch = document.getElementById('global-search');
    elements.searchBtn = document.getElementById('search-btn');
}

// 绑定事件
function bindEvents() {
    // 导航切换
    elements.navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            const view = item.dataset.view;
            // 如果没有 data-view 属性（如 Redis 链接），允许默认跳转
            if (!view) {
                return; // 不阻止默认行为，允许跳转到 href
            }
            e.preventDefault();
            switchView(view);
        });
    });
    
    // 分页
    elements.prevPage.addEventListener('click', () => changePage(-1));
    elements.nextPage.addEventListener('click', () => changePage(1));
    
    // 筛选
    elements.applyFilters.addEventListener('click', applyFilters);
    elements.clearFilters.addEventListener('click', clearFilters);
    
    // Agent 筛选
    if (elements.applyAgentFilters) {
        elements.applyAgentFilters.addEventListener('click', applyAgentFilters);
    }
    if (elements.clearAgentFilters) {
        elements.clearAgentFilters.addEventListener('click', clearAgentFilters);
    }
    
    // 弹窗
    elements.closeModal.addEventListener('click', closeModal);
    elements.modal.addEventListener('click', (e) => {
        if (e.target === elements.modal) closeModal();
    });
    
    // 刷新
    elements.refreshBtn.addEventListener('click', () => {
        loadDashboard();
        if (state.currentView === 'logs') loadLogs();
        if (state.currentView === 'sessions') loadSessions();
    });
    
    // 导出
    elements.exportBtn.addEventListener('click', exportLogs);
    
    // 全局搜索
    if (elements.searchBtn) {
        elements.searchBtn.addEventListener('click', performGlobalSearch);
    }
    if (elements.globalSearch) {
        elements.globalSearch.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                performGlobalSearch();
            }
        });
    }
    
    // 日志列表搜索框回车键
    if (elements.filterSearch) {
        elements.filterSearch.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                applyFilters();
            }
        });
    }
    
    // 快捷键
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeModal();
        if (e.key === 'r' && e.ctrlKey) {
            e.preventDefault();
            loadDashboard();
        }
    });
}

// 全局搜索
function performGlobalSearch() {
    const keyword = elements.globalSearch ? elements.globalSearch.value.trim() : '';
    if (!keyword) return;
    
    // 切换到日志列表视图
    switchView('logs');
    
    // 设置搜索值并应用筛选
    if (elements.filterSearch) {
        elements.filterSearch.value = keyword;
    }
    state.filters.search = keyword;
    state.pagination.page = 1;
    loadLogs();
}

// 切换视图
function switchView(view) {
    state.currentView = view;
    
    // 更新导航
    elements.navItems.forEach(item => {
        item.classList.toggle('active', item.dataset.view === view);
    });
    
    // 更新视图
    elements.views.forEach(v => {
        v.classList.toggle('active', v.id === `view-${view}`);
    });
    
    // 加载数据
    if (view === 'logs' && state.logs.length === 0) {
        loadLogs();
    } else if (view === 'sessions' && state.sessions.length === 0) {
        loadSessions();
    } else if (view === 'agents') {
        loadAgentsTimeline();
    } else if (view === 'analytics') {
        loadAnalytics();
    }
}

// ==================== RESTful 轮询 ====================

let pollTimer = null;
let lastLogCount = 0;

function startPolling() {
    // 立即执行一次
    checkNewLogs();
    // 每 5 秒轮询一次
    pollTimer = setInterval(checkNewLogs, 5000);
}

function stopPolling() {
    if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
    }
}

async function checkNewLogs() {
    try {
        const stats = await apiGet('/api/stats');
        const currentCount = stats.total_calls;
        
        // 如果有新日志，刷新仪表盘
        if (lastLogCount > 0 && currentCount > lastLogCount) {
            if (state.currentView === 'dashboard') {
                loadDashboard();
            }
        }
        lastLogCount = currentCount;
        
        // 更新连接状态为在线
        updateConnectionStatus(true);
    } catch (error) {
        console.error('Polling error:', error);
        updateConnectionStatus(false);
    }
}

function updateConnectionStatus(connected) {
    elements.wsStatus.classList.toggle('connected', connected);
    elements.wsText.textContent = connected ? '在线' : '离线';
}

// ==================== API 调用 ====================

async function apiGet(endpoint) {
    const response = await fetch(`${API_BASE}${endpoint}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
}

async function apiPost(endpoint, data) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
}

// ==================== 数据加载 ====================

async function loadDashboard() {
    try {
        // 并行加载统计数据和最近日志
        const [stats, logs] = await Promise.all([
            apiGet('/api/stats'),
            apiGet('/api/logs?limit=10')
        ]);
        
        updateStats(stats);
        updateRecentLogs(logs);
        
    } catch (error) {
        console.error('Failed to load dashboard:', error);
        showError('加载仪表盘失败');
    }
}

async function loadLogs() {
    try {
        const params = new URLSearchParams({
            limit: state.pagination.limit,
            offset: (state.pagination.page - 1) * state.pagination.limit
        });
        
        if (state.filters.session_id) params.append('session_id', state.filters.session_id);
        if (state.filters.call_type) params.append('call_type', state.filters.call_type);
        if (state.filters.model) params.append('model', state.filters.model);
        if (state.filters.success !== '') params.append('success', state.filters.success);
        if (state.filters.start_time) params.append('start_time', state.filters.start_time);
        if (state.filters.end_time) params.append('end_time', state.filters.end_time);
        if (state.filters.search) params.append('search', state.filters.search);
        
        const logs = await apiGet(`/api/logs?${params}`);
        state.logs = logs;
        
        updateLogsTable(logs);
        updatePagination();
        
    } catch (error) {
        console.error('Failed to load logs:', error);
        showError('加载日志失败');
    }
}

async function loadSessions() {
    try {
        const sessions = await apiGet('/api/sessions');
        state.sessions = sessions;
        updateSessionsGrid(sessions);
    } catch (error) {
        console.error('Failed to load sessions:', error);
        showError('加载会话失败');
    }
}

async function loadAnalytics() {
    try {
        const stats = await apiGet('/api/stats');
        drawCallTypeChart(stats.call_type_distribution);
        
        // 延迟分析需要更多数据
        const logs = await apiGet('/api/logs?limit=1000');
        drawLatencyChart(logs);
    } catch (error) {
        console.error('Failed to load analytics:', error);
    }
}

async function loadFilters() {
    try {
        // 并行加载所有筛选器数据
        const [sessions, models, types] = await Promise.all([
            apiGet('/api/sessions'),
            apiGet('/api/models'),
            apiGet('/api/call-types')
        ]);
        
        elements.filterSession.innerHTML = '<option value="">全部会话</option>' +
            sessions.map(s => `<option value="${s.session_id}">${s.session_id.slice(0, 8)}...</option>`).join('');
        
        elements.filterModel.innerHTML = '<option value="">全部模型</option>' +
            models.models.map(m => `<option value="${m}">${m}</option>`).join('');
        
        elements.filterType.innerHTML = '<option value="">全部类型</option>' +
            types.call_types.map(t => `<option value="${t}">${t}</option>`).join('');
        
    } catch (error) {
        console.error('Failed to load filters:', error);
    }
}

// ==================== Agent 时间轴 ====================

async function loadAgentsTimeline() {
    try {
        console.log('[DEBUG] Loading agents timeline...');
        const data = await apiGet('/api/agents/timeline/all');
        console.log('[DEBUG] Loaded agents:', data.length, data);
        state.agentsTimeline = data;
        updateAgentsTimeline(data);
        
        // 更新 Agent 类型筛选器
        const agentTypes = [...new Set(data.map(a => a.agent_type))];
        if (elements.filterAgentType) {
            elements.filterAgentType.innerHTML = '<option value="">全部类型</option>' +
                agentTypes.map(t => `<option value="${t}">${t}</option>`).join('');
        }
    } catch (error) {
        console.error('Failed to load agents timeline:', error);
        showError('加载 Agent 时间轴失败');
    }
}

function updateAgentsTimeline(agents) {
    console.log('[DEBUG] updateAgentsTimeline called with', agents.length, 'agents');
    console.log('[DEBUG] elements.agentsTimeline:', elements.agentsTimeline);
    
    if (!elements.agentsTimeline) {
        console.error('[DEBUG] agentsTimeline element not found!');
        return;
    }
    
    if (agents.length === 0) {
        elements.agentsTimeline.innerHTML = `
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="12" y1="8" x2="12" y2="12"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>
                <p>暂无 Agent 数据</p>
            </div>
        `;
        return;
    }
    
    elements.agentsTimeline.innerHTML = agents.map(agent => `
        <div class="agent-timeline-card" data-agent-id="${agent.agent_id}">
            <div class="agent-header">
                <div class="agent-info">
                    <span class="agent-type">${agent.agent_type}</span>
                    <span class="agent-id"><code>${agent.agent_id.slice(0, 16)}...</code></span>
                </div>
                <div class="agent-status">
                    ${renderAgentStatus(agent.status)}
                </div>
            </div>
            <div class="agent-target">${agent.target_function || 'Unknown target'}</div>
            <div class="agent-stats">
                <span class="agent-stat">总调用: ${agent.total_calls}</span>
            </div>
            <div class="agent-calls-timeline">
                ${agent.calls.map(call => `
                    <div class="call-item ${call.status}" onclick="viewLog('${call.id}')" title="${call.call_type} - ${call.model}">
                        <span class="call-time">${formatShortTime(call.timestamp)}</span>
                        <span class="call-type">${call.call_type}</span>
                        <span class="call-status">${renderStatus(call.status, call.success)}</span>
                        <span class="call-latency">${call.latency_ms.toFixed(0)}ms</span>
                    </div>
                `).join('')}
            </div>
        </div>
    `).join('');
}

function renderAgentStatus(status) {
    const statusMap = {
        'running': '<span class="status-badge warning">运行中</span>',
        'completed': '<span class="status-badge success">已完成</span>',
        'failed': '<span class="status-badge error">失败</span>',
        'pending': '<span class="status-badge info">等待中</span>',
    };
    return statusMap[status] || `<span class="status-badge">${status}</span>`;
}

function formatShortTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('zh-CN', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

function applyAgentFilters() {
    if (!state.agentsTimeline) return;
    
    const typeFilter = elements.filterAgentType ? elements.filterAgentType.value : '';
    const statusFilter = elements.filterAgentStatus ? elements.filterAgentStatus.value : '';
    
    let filtered = state.agentsTimeline;
    
    if (typeFilter) {
        filtered = filtered.filter(a => a.agent_type === typeFilter);
    }
    
    if (statusFilter) {
        filtered = filtered.filter(a => a.status === statusFilter);
    }
    
    updateAgentsTimeline(filtered);
}

function clearAgentFilters() {
    if (elements.filterAgentType) elements.filterAgentType.value = '';
    if (elements.filterAgentStatus) elements.filterAgentStatus.value = '';
    
    if (state.agentsTimeline) {
        updateAgentsTimeline(state.agentsTimeline);
    }
}

// ==================== UI 更新 ====================

function updateStats(stats) {
    elements.statSuccess.textContent = stats.success_calls.toLocaleString();
    elements.statFailed.textContent = stats.failed_calls.toLocaleString();
    elements.statTotal.textContent = stats.total_calls.toLocaleString();
    elements.statRate.textContent = (stats.success_rate * 100).toFixed(1) + '%';
}

function updateLogsTable(logs) {
    if (logs.length === 0) {
        elements.logsTableBody.innerHTML = `
            <tr><td colspan="8" class="empty-state">暂无日志数据</td></tr>
        `;
        return;
    }
    
    elements.logsTableBody.innerHTML = logs.map(log => {
        const isViewed = logStateManager.isViewed(log.id);
        const isStarred = logStateManager.isStarred(log.id);
        const rowClass = isViewed ? 'log-row viewed' : 'log-row';
        
        return `
        <tr data-id="${log.id}" class="${rowClass}" ondblclick="viewLog('${log.id}')">
            <td>${formatTime(log.timestamp)}</td>
            <td>${renderAgentType(log.agent_type)}</td>
            <td><code>${log.target_function || '-'}</code></td>
            <td>${log.latency_ms.toFixed(0)}ms</td>
            <td>${log.retry_count}</td>
            <td>${renderStatus(log.status, log.success)}</td>
            <td class="star-cell">
                <button class="star-btn ${isStarred ? 'starred' : ''}" onclick="toggleLogStar('${log.id}', this)" title="${isStarred ? '取消标注' : '标注为关键日志'}">
                    <svg viewBox="0 0 24 24" fill="${isStarred ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="2">
                        <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon>
                    </svg>
                </button>
            </td>
            <td class="actions-cell">
                <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); viewLog('${log.id}')">查看</button>
            </td>
        </tr>
    `}).join('');
}

// 切换日志标注状态 - 日志列表
function toggleLogStar(logId, btn) {
    event.stopPropagation();
    const isStarred = logStateManager.toggleStarred(logId);
    
    // 直接更新按钮状态，无需刷新整个表格
    if (btn) {
        btn.classList.toggle('starred', isStarred);
        btn.title = isStarred ? '取消标注' : '标注为关键日志';
        const svg = btn.querySelector('svg');
        if (svg) {
            svg.setAttribute('fill', isStarred ? 'currentColor' : 'none');
        }
    }
    
    // 显示提示
    const message = isStarred ? '已标注为关键日志' : '已取消标注';
    showNotification('提示', message);
}

function updateRecentLogs(logs) {
    const tbody = document.querySelector('#recent-logs-table tbody');
    if (logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="empty-state">暂无数据</td></tr>`;
        return;
    }
    
    tbody.innerHTML = logs.map(log => {
        const isViewed = logStateManager.isViewed(log.id);
        const isStarred = logStateManager.isStarred(log.id);
        const rowClass = isViewed ? 'log-row viewed' : 'log-row';
        
        return `
        <tr data-id="${log.id}" class="${rowClass}" ondblclick="viewLog('${log.id}')">
            <td>${formatTime(log.timestamp)}</td>
            <td>${renderAgentType(log.agent_type)}</td>
            <td><code>${log.target_function || '-'}</code></td>
            <td>${log.latency_ms.toFixed(0)}ms</td>
            <td>${renderStatus(log.status, log.success)}</td>
            <td class="star-cell">
                <button class="star-btn ${isStarred ? 'starred' : ''}" onclick="toggleLogStar('${log.id}', this)" title="${isStarred ? '取消标注' : '标注为关键日志'}">
                    <svg viewBox="0 0 24 24" fill="${isStarred ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="2">
                        <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon>
                    </svg>
                </button>
            </td>
            <td class="actions-cell">
                <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); viewLog('${log.id}')">查看</button>
            </td>
        </tr>
    `}).join('');
}

function updateSessionsGrid(sessions) {
    if (sessions.length === 0) {
        elements.sessionsGrid.innerHTML = `
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="12" y1="8" x2="12" y2="12"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>
                <p>暂无会话数据</p>
            </div>
        `;
        return;
    }
    
    elements.sessionsGrid.innerHTML = sessions.map(session => `
        <div class="session-card" onclick="viewSession('${session.session_id}')">
            <div class="session-header">
                <span class="session-id">${session.session_id.slice(0, 16)}...</span>
                <span class="session-time">${formatTime(session.start_time)}</span>
            </div>
            <div class="session-stats">
                <div class="session-stat">
                    <span class="session-stat-value">${session.total_calls}</span>
                    <span class="session-stat-label">总调用</span>
                </div>
                <div class="session-stat">
                    <span class="session-stat-value" style="color: var(--success)">${session.success_calls}</span>
                    <span class="session-stat-label">成功</span>
                </div>
                <div class="session-stat">
                    <span class="session-stat-value" style="color: var(--error)">${session.failed_calls}</span>
                    <span class="session-stat-label">失败</span>
                </div>
            </div>
        </div>
    `).join('');
}

function updatePagination() {
    elements.currentPage.textContent = state.pagination.page;
    elements.prevPage.disabled = state.pagination.page <= 1;
    elements.nextPage.disabled = state.logs.length < state.pagination.limit;
    elements.paginationInfo.textContent = `第 ${state.pagination.page} 页`;
}

// ==================== 图表 ====================

function drawCallTypeChart(distribution) {
    const ctx = document.getElementById('calltype-chart');
    if (!ctx) return;
    
    const labels = Object.keys(distribution);
    const data = Object.values(distribution);
    
    // 如果图表已存在，只更新数据
    if (state.charts.calltype) {
        const chart = state.charts.calltype;
        const needUpdate = JSON.stringify(chart.data.labels) !== JSON.stringify(labels) ||
                          JSON.stringify(chart.data.datasets[0].data) !== JSON.stringify(data);
        
        if (needUpdate) {
            chart.data.labels = labels;
            chart.data.datasets[0].data = data;
            chart.update('none');
        }
        return;
    }
    
    // 首次创建图表
    state.charts.calltype = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: '调用次数',
                data: data,
                backgroundColor: '#2563eb'
            }]
        },
        options: {
            responsive: true,
            animation: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: { beginAtZero: true }
            }
        }
    });
}

function drawLatencyChart(logs) {
    const ctx = document.getElementById('latency-chart');
    if (!ctx || logs.length === 0) return;
    
    // 按时间排序
    const sorted = [...logs].sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    const labels = sorted.map(l => formatTime(l.timestamp));
    const data = sorted.map(l => l.latency_ms);
    
    // 如果图表已存在，只更新数据
    if (state.charts.latency) {
        const chart = state.charts.latency;
        chart.data.labels = labels;
        chart.data.datasets[0].data = data;
        chart.update('none');
        return;
    }
    
    // 首次创建图表
    state.charts.latency = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: '延迟 (ms)',
                data: data,
                borderColor: '#f59e0b',
                backgroundColor: 'rgba(245, 158, 11, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 3
            }]
        },
        options: {
            responsive: true,
            animation: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: { beginAtZero: true }
            }
        }
    });
}

// ==================== 交互功能 ====================

function changePage(delta) {
    const newPage = state.pagination.page + delta;
    if (newPage < 1) return;
    
    state.pagination.page = newPage;
    loadLogs();
}

function applyFilters() {
    state.filters.session_id = elements.filterSession.value;
    state.filters.call_type = elements.filterType.value;
    state.filters.model = elements.filterModel.value;
    state.filters.success = elements.filterStatus.value;
    state.filters.start_time = elements.filterStart.value;
    state.filters.end_time = elements.filterEnd.value;
    state.filters.search = elements.filterSearch ? elements.filterSearch.value : '';
    
    state.pagination.page = 1;
    loadLogs();
}

function clearFilters() {
    elements.filterSession.value = '';
    elements.filterType.value = '';
    elements.filterModel.value = '';
    elements.filterStatus.value = '';
    elements.filterStart.value = '';
    elements.filterEnd.value = '';
    if (elements.filterSearch) elements.filterSearch.value = '';
    
    state.filters = {
        session_id: '',
        call_type: '',
        model: '',
        success: '',
        start_time: '',
        end_time: '',
        search: ''
    };
    
    state.pagination.page = 1;
    loadLogs();
}

async function viewLog(logId) {
    try {
        const log = await apiGet(`/api/logs/${logId}`);
        
        // 标记为已查看
        logStateManager.markAsViewed(logId);
        // 更新表格显示（当前行变灰）
        const row = document.querySelector(`tr[data-id="${logId}"]`);
        if (row) {
            row.classList.add('viewed');
        }
        
        showLogDetail(log);
    } catch (error) {
        console.error('Failed to load log:', error);
        showError('加载日志详情失败');
    }
}

function showLogDetail(log) {
    // 分离 system prompt 和非 system 消息
    const messages = log.messages || [];
    const systemMessages = messages.filter(m => {
        const msgType = (m.type || m.role || '').toLowerCase();
        return msgType === 'system' || msgType === 'systemmessage';
    });
    
    const nonSystemMessages = messages.filter(m => {
        const msgType = (m.type || m.role || '').toLowerCase();
        return msgType !== 'system' && msgType !== 'systemmessage';
    });
    
    // 生成 system prompt 折叠区域（如果有）
    const systemPromptHtml = systemMessages.length > 0 ? `
        <div class="detail-section system-prompt-section">
            <h4 class="collapsible-header collapsed" onclick="toggleSystemPrompt(this)">
                <span>System Prompt (${systemMessages.length})</span>
                <svg class="collapse-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
            </h4>
            <div class="collapsible-content" id="system-prompt-content" style="display: none;">
                <div class="message-list">
                    ${systemMessages.map(m => `
                        <div class="message-item system-message">
                            <div class="message-header">
                                <span class="message-type system">${m.type || m.role || 'system'}</span>
                                ${m.name ? `<span>${m.name}</span>` : ''}
                            </div>
                            <div class="message-content">${escapeHtml(m.content)}</div>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    ` : '';
    
    elements.modalBody.innerHTML = `
        <div class="log-detail">
            <div class="detail-section">
                <h4>基本信息</h4>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">ID</span>
                        <span class="detail-value id">${log.id}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">时间</span>
                        <span class="detail-value">${formatTime(log.timestamp)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">会话</span>
                        <span class="detail-value id">${log.session_id}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Agent</span>
                        <span class="detail-value id">${log.agent_id || '-'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">模型</span>
                        <span class="detail-value">${log.model}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">类型</span>
                        <span class="detail-value">${log.call_type}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">状态</span>
                        <span class="detail-value">${renderStatus(log.status, log.success)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">延迟</span>
                        <span class="detail-value">${log.latency_ms.toFixed(2)}ms</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">重试次数</span>
                        <span class="detail-value">${log.retry_count}</span>
                    </div>
                </div>
            </div>
            
            ${systemPromptHtml}
            
            <div class="detail-section">
                <h4>消息 (${nonSystemMessages.length})</h4>
                <div class="message-list">
                    ${nonSystemMessages.length > 0 ? nonSystemMessages.map(m => `
                        <div class="message-item">
                            <div class="message-header">
                                <span class="message-type">${m.type || m.role || 'unknown'}</span>
                                ${m.name ? `<span>${m.name}</span>` : ''}
                            </div>
                            <div class="message-content">${escapeHtml(m.content)}</div>
                        </div>
                    `).join('') : '<p class="empty-hint">无消息</p>'}
                </div>
            </div>
            
            ${log.output_schema ? `
            <div class="detail-section">
                <h4>输出模式</h4>
                <div class="detail-content">
                    <pre>${log.output_schema}</pre>
                </div>
            </div>
            ` : ''}
            
            ${log.response ? `
            <div class="detail-section">
                <h4>响应</h4>
                <div class="detail-content">
                    <pre><code class="language-json">${escapeHtml(JSON.stringify(log.response, null, 2))}</code></pre>
                </div>
            </div>
            ` : ''}
            
            ${log.error ? `
            <div class="detail-section">
                <h4>错误</h4>
                <div class="detail-content" style="border-color: var(--error);">
                    <pre style="color: var(--error);">${escapeHtml(log.error)}</pre>
                </div>
            </div>
            ` : ''}
        </div>
    `;
    
    // 高亮代码
    elements.modalBody.querySelectorAll('pre code').forEach(block => {
        hljs.highlightElement(block);
    });
    
    elements.modal.classList.add('active');
}

// 切换 system prompt 折叠状态
function toggleSystemPrompt(header) {
    const content = document.getElementById('system-prompt-content');
    const icon = header.querySelector('.collapse-icon');
    if (content) {
        const isHidden = content.style.display === 'none';
        content.style.display = isHidden ? 'block' : 'none';
        header.classList.toggle('collapsed', !isHidden);
    }
}

function closeModal() {
    elements.modal.classList.remove('active');
}

function viewSession(sessionId) {
    // 切换到日志视图并筛选会话
    switchView('logs');
    elements.filterSession.value = sessionId;
    applyFilters();
}

async function exportLogs() {
    const filepath = prompt('请输入导出文件路径:', 'logs_export.json');
    if (!filepath) return;
    
    try {
        const result = await apiPost('/api/export', { filepath });
        showNotification('导出成功', `已导出 ${result.exported} 条日志到 ${result.filepath}`);
    } catch (error) {
        showError('导出失败');
    }
}

// ==================== 工具函数 ====================

function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString('zh-CN', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

function renderStatus(status, success) {
    // 优先使用 status 字段，兼容旧数据使用 success
    if (status === 'completed' || (status === undefined && success === true)) {
        return '<span class="status-badge success">成功</span>';
    } else if (status === 'failed' || (status === undefined && success === false)) {
        return '<span class="status-badge error">失败</span>';
    } else if (status === 'running') {
        return '<span class="status-badge warning">进行中</span>';
    } else if (status === 'pending') {
        return '<span class="status-badge info">等待中</span>';
    } else {
        return '<span class="status-badge">' + (status || 'unknown') + '</span>';
    }
}

function renderAgentType(agentType) {
    // 渲染 Agent 类型为友好的中文名称
    if (!agentType) return '<span class="agent-type-tag">-</span>';
    
    const typeMap = {
        'DeepVulnAgent': '<span class="agent-type-tag vuln">漏洞挖掘</span>',
        'FunctionSummaryAgent': '<span class="agent-type-tag summary">摘要分析</span>',
        'DecisionAgent': '<span class="agent-type-tag decision">决策分析</span>',
        'SubFunctionAgent': '<span class="agent-type-tag subfunc">子函数分析</span>',
        'ProgramAnalyzer': '<span class="agent-type-tag program">程序分析</span>',
    };
    
    return typeMap[agentType] || `<span class="agent-type-tag">${agentType}</span>`;
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showNotification(title, message) {
    // 简单的通知实现
    if ('Notification' in window && Notification.permission === 'granted') {
        new Notification(title, { body: message });
    } else {
        console.log(`[${title}] ${message}`);
    }
}

function showError(message) {
    alert(message);
}

// 请求通知权限
if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
}

// ==================== Tool Call 日志功能 ====================

const tcState = {
    logs: [],
    pagination: {
        page: 1,
        limit: 20,
        total: 0
    },
    filters: {
        agent_id: '',
        success: ''
    },
    charts: {}
};

async function loadToolCallStats() {
    try {
        const stats = await apiGet('/api/tool-calls/stats');
        
        // 更新统计卡片
        const statTotal = document.getElementById('tc-stat-total');
        const statSuccess = document.getElementById('tc-stat-success');
        const statTools = document.getElementById('tc-stat-tools');
        
        if (statTotal) statTotal.textContent = stats.total_tool_calls.toLocaleString();
        if (statSuccess) statSuccess.textContent = stats.success_count.toLocaleString();
        if (statTools) statTools.textContent = stats.avg_tools_per_call.toFixed(1);
        
        // 绘制工具使用分布图
        drawToolUsageChart(stats.tool_usage_distribution);
    } catch (error) {
        console.error('Failed to load tool call stats:', error);
    }
}

async function loadToolCalls() {
    try {
        const params = new URLSearchParams({
            limit: tcState.pagination.limit,
            offset: (tcState.pagination.page - 1) * tcState.pagination.limit
        });
        
        if (tcState.filters.agent_id) {
            params.append('agent_id', tcState.filters.agent_id);
        }
        if (tcState.filters.success !== '') {
            params.append('success', tcState.filters.success);
        }
        
        const logs = await apiGet(`/api/tool-calls?${params}`);
        tcState.logs = logs;
        
        renderToolCallsTable(logs);
        updateToolCallPagination();
    } catch (error) {
        console.error('Failed to load tool calls:', error);
        showError('加载 Tool Call 日志失败');
    }
}

function renderToolCallsTable(logs) {
    const tbody = document.querySelector('#toolcalls-table tbody');
    if (!tbody) return;
    
    if (logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="empty">暂无 Tool Call 日志</td></tr>';
        return;
    }
    
    tbody.innerHTML = logs.map(log => `
        <tr>
            <td>${formatTime(log.timestamp)}</td>
            <td><span class="id-short" title="${log.agent_id || '-'}">${log.agent_id ? log.agent_id.substring(0, 8) + '...' : '-'}</span></td>
            <td>${log.target_function || '-'}</td>
            <td>${log.tool_names.map(t => `<span class="tool-tag">${t}</span>`).join(' ')}</td>
            <td>${log.tool_count}</td>
            <td>${log.latency_ms.toFixed(2)}ms</td>
            <td>${renderStatus(log.status, log.success)}</td>
            <td>
                <button class="btn btn-sm" onclick="viewToolCallDetail('${log.id}')">查看</button>
            </td>
        </tr>
    `).join('');
}

function updateToolCallPagination() {
    const info = document.getElementById('tc-pagination-info');
    const currentPage = document.getElementById('tc-current-page');
    const prevBtn = document.getElementById('tc-prev-page');
    const nextBtn = document.getElementById('tc-next-page');
    
    if (info) info.textContent = `第 ${tcState.pagination.page} 页`;
    if (currentPage) currentPage.textContent = tcState.pagination.page;
    if (prevBtn) prevBtn.disabled = tcState.pagination.page <= 1;
    // 假设还有更多数据（没有总数的情况下）
    if (nextBtn) nextBtn.disabled = tcState.logs.length < tcState.pagination.limit;
}

function changeToolCallPage(delta) {
    const newPage = tcState.pagination.page + delta;
    if (newPage < 1) return;
    
    tcState.pagination.page = newPage;
    loadToolCalls();
}

function applyToolCallFilters() {
    const agentFilter = document.getElementById('tc-filter-agent');
    const statusFilter = document.getElementById('tc-filter-status');
    
    tcState.filters.agent_id = agentFilter ? agentFilter.value : '';
    tcState.filters.success = statusFilter ? statusFilter.value : '';
    tcState.pagination.page = 1;
    
    loadToolCalls();
}

function clearToolCallFilters() {
    const agentFilter = document.getElementById('tc-filter-agent');
    const statusFilter = document.getElementById('tc-filter-status');
    
    if (agentFilter) agentFilter.value = '';
    if (statusFilter) statusFilter.value = '';
    
    tcState.filters = { agent_id: '', success: '' };
    tcState.pagination.page = 1;
    
    loadToolCalls();
}

async function viewToolCallDetail(logId) {
    try {
        const log = await apiGet(`/api/tool-calls/${logId}`);
        showToolCallDetail(log);
    } catch (error) {
        console.error('Failed to load tool call detail:', error);
        showError('加载详情失败');
    }
}

function showToolCallDetail(log) {
    const modalBody = document.getElementById('modal-body');
    if (!modalBody) return;
    
    // 构建工具调用详情
    const toolCallsHtml = log.tool_calls && log.tool_calls.length > 0 
        ? log.tool_calls.map(tc => `
            <div class="tool-call-item">
                <div class="tool-call-header">
                    <span class="tool-name">${tc.name || 'unknown'}</span>
                    <span class="tool-id">${tc.id || ''}</span>
                </div>
                <div class="tool-call-args">
                    <pre><code class="language-json">${escapeHtml(JSON.stringify(tc.args || tc.arguments || {}, null, 2))}</code></pre>
                </div>
            </div>
        `).join('')
        : '<p class="empty">无工具调用</p>';
    
    // 构建工具信息
    const toolsHtml = log.tools && log.tools.length > 0
        ? log.tools.map(t => `
            <div class="tool-info-item">
                <span class="tool-info-name">${t.name}</span>
                <span class="tool-info-sig">${t.signature || ''}</span>
            </div>
        `).join('')
        : '<p class="empty">无工具信息</p>';
    
    modalBody.innerHTML = `
        <div class="log-detail">
            <div class="detail-section">
                <h4>基本信息</h4>
                <div class="detail-grid">
                    <div class="detail-item">
                        <span class="detail-label">ID</span>
                        <span class="detail-value id">${log.id}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">时间</span>
                        <span class="detail-value">${formatTime(log.timestamp)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Agent</span>
                        <span class="detail-value id">${log.agent_id || '-'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Agent 类型</span>
                        <span class="detail-value">${log.agent_type || '-'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">目标函数</span>
                        <span class="detail-value">${log.target_function || '-'}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">模型</span>
                        <span class="detail-value">${log.model}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">状态</span>
                        <span class="detail-value">${renderStatus(log.status, log.success)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">延迟</span>
                        <span class="detail-value">${log.latency_ms.toFixed(2)}ms</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">重试次数</span>
                        <span class="detail-value">${log.retry_count}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">工具数量</span>
                        <span class="detail-value">${log.tool_count}</span>
                    </div>
                </div>
            </div>
            
            <div class="detail-section">
                <h4>可用工具 (${log.tools ? log.tools.length : 0})</h4>
                <div class="tool-list">
                    ${toolsHtml}
                </div>
            </div>
            
            <div class="detail-section">
                <h4>工具调用 (${log.tool_calls ? log.tool_calls.length : 0})</h4>
                <div class="tool-calls-list">
                    ${toolCallsHtml}
                </div>
            </div>
            
            ${log.response_content ? `
            <div class="detail-section">
                <h4>文本响应</h4>
                <div class="detail-content">
                    <pre>${escapeHtml(log.response_content)}</pre>
                </div>
            </div>
            ` : ''}
            
            ${log.error ? `
            <div class="detail-section">
                <h4>错误</h4>
                <div class="detail-content" style="border-color: var(--error);">
                    <pre style="color: var(--error);">${escapeHtml(log.error)}</pre>
                </div>
            </div>
            ` : ''}
            
            ${log.response ? `
            <div class="detail-section">
                <h4>完整响应</h4>
                <div class="detail-content">
                    <pre><code class="language-json">${escapeHtml(JSON.stringify(log.response, null, 2))}</code></pre>
                </div>
            </div>
            ` : ''}
        </div>
    `;
    
    // 高亮代码
    modalBody.querySelectorAll('pre code').forEach(block => {
        if (window.hljs) {
            hljs.highlightElement(block);
        }
    });
    
    // 显示弹窗
    const modal = document.getElementById('log-modal');
    if (modal) modal.classList.add('active');
}

function drawToolUsageChart(distribution) {
    const ctx = document.getElementById('tool-usage-chart');
    if (!ctx) return;
    
    const labels = Object.keys(distribution);
    const data = Object.values(distribution);
    
    if (labels.length === 0) {
        ctx.parentElement.innerHTML += '<p class="empty" style="text-align:center;padding:20px;">暂无数据</p>';
        return;
    }
    
    // 如果图表已存在，只更新数据
    if (tcState.charts.usage) {
        const chart = tcState.charts.usage;
        chart.data.labels = labels;
        chart.data.datasets[0].data = data;
        chart.update('none');
        return;
    }
    
    // 首次创建图表
    tcState.charts.usage = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: [
                    '#2563eb', '#16a34a', '#dc2626', '#f59e0b', '#8b5cf6',
                    '#ec4899', '#06b6d4', '#84cc16', '#f97316', '#6366f1'
                ]
            }]
        },
        options: {
            responsive: true,
            animation: false,
            plugins: {
                legend: {
                    position: 'right'
                }
            }
        }
    });
}

// 在初始化时绑定 Tool Call 相关事件
function bindToolCallEvents() {
    // 筛选器
    const applyBtn = document.getElementById('tc-apply-filters');
    const clearBtn = document.getElementById('tc-clear-filters');
    
    if (applyBtn) applyBtn.addEventListener('click', applyToolCallFilters);
    if (clearBtn) clearBtn.addEventListener('click', clearToolCallFilters);
    
    // 分页
    const prevBtn = document.getElementById('tc-prev-page');
    const nextBtn = document.getElementById('tc-next-page');
    
    if (prevBtn) prevBtn.addEventListener('click', () => changeToolCallPage(-1));
    if (nextBtn) nextBtn.addEventListener('click', () => changeToolCallPage(1));
}

// 在 view switch 时加载 Tool Call 数据
const originalSwitchView = switchView;
switchView = function(viewName) {
    originalSwitchView(viewName);
    
    if (viewName === 'toolcalls') {
        loadToolCallStats();
        loadToolCalls();
    }
};

// 启动应用
document.addEventListener('DOMContentLoaded', () => {
    init();
    bindToolCallEvents();
});
