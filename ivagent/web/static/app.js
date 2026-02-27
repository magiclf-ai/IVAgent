/**
 * LLM 交互日志可视化系统 - 前端应用
 */

// API 基础 URL
const API_BASE = '';

// 行高配置（用于计算每页显示行数）
const ROW_HEIGHTS = {
    table: 56,  // 表格行高
    agent: 200, // Agent时间轴卡片高度
    session: 160 // 会话卡片高度
};

// 计算每页显示行数
function calculatePageSize(rowHeight, minRows = 5) {
    const navbarHeight = 64;
    const padding = 24;  // 上下各12px的紧凑布局
    const filterHeight = state.currentView === 'logs' ? 140 : 80;  // 日志筛选器实际高度约140px
    const paginationHeight = 56;  // 分页器高度约56px
    const cardHeaderHeight = 48;  // 卡片头部高度约48px
    const availableHeight = window.innerHeight - navbarHeight - padding - filterHeight - paginationHeight - cardHeaderHeight;
    const rows = Math.max(minRows, Math.floor(availableHeight / rowHeight));
    return rows;
}

// 获取当前视图的分页配置
function getPaginationConfig() {
    const base = { page: 1, limit: 20, total: 0 };
    
    switch (state.currentView) {
        case 'logs':
            return { ...base, limit: calculatePageSize(ROW_HEIGHTS.table) };
        case 'dashboard':
            return { ...base, limit: calculatePageSize(ROW_HEIGHTS.table) };
        case 'agents':
            return { ...base, limit: calculatePageSize(ROW_HEIGHTS.agent, 3) };
        case 'toolcalls':
            return { ...base, limit: calculatePageSize(ROW_HEIGHTS.table) };
        default:
            return base;
    }
}

// 全局状态
const state = {
    currentView: 'dashboard',
    logs: [],
    sessions: [],
    stats: {},
    recentLogs: [],
    recentPagination: {
        page: 1,
        limit: 20,
        total: 0
    },
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
    charts: {},
    session: {
        page: 1,
        limit: 12, // 3x4 grid
        data: [], // Full list
        filtered: [], // Filtered list
        search: '',
        sort: 'newest'
    },
    agentsTimeline: {
        data: [],
        filtered: [],
        page: 1,
        limit: 2, // 每页只显示 1-2 个 Agent
        total: 0
    },
    batchSelection: {
        enabled: false,
        selectedIds: new Set(),
        logDetails: new Map() // 存储已加载的日志详情
    }
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
let bsModal = null;
let currentLogDetail = null;
let copyResetTimer = null;
let batchCopyResetTimer = null;

// 初始化
async function init() {
    cacheElements();
    
    // Initialize Bootstrap Modal
    if (elements.modal) {
        if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
            try {
                bsModal = new bootstrap.Modal(elements.modal);
            } catch (e) {
                console.error("Failed to initialize Bootstrap Modal:", e);
            }
        } else {
             console.error("Bootstrap is not defined or Modal is missing. Check if bootstrap.bundle.min.js is loaded.");
        }
    }

    bindEvents();
    
    // Check hash for initial view
    const hash = window.location.hash.slice(1);
    if (hash && ['dashboard', 'logs', 'agents', 'toolcalls'].includes(hash)) {
        switchView(hash);
    } else {
        // 先加载页面数据，确保页面快速渲染
        await loadDashboard();
    }
    
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
    elements.recentPaginationInfo = document.getElementById('recent-pagination-info');

    // 日志列表
    elements.logsTableBody = document.querySelector('#logs-table tbody');
    elements.paginationInfo = document.getElementById('pagination-info');
    
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
    elements.sessionSearch = document.getElementById('session-search');
    elements.sessionSort = document.getElementById('session-sort');
    elements.sessionsPrevPage = document.getElementById('sessions-prev-page');
    elements.sessionsNextPage = document.getElementById('sessions-next-page');
    elements.sessionsCurrentPage = document.getElementById('sessions-current-page');
    elements.sessionsPaginationInfo = document.getElementById('sessions-pagination-info');
    
    // 弹窗
    elements.modal = document.getElementById('log-modal');
    elements.modalBody = document.getElementById('modal-body');
    elements.closeModal = document.getElementById('close-modal');
    elements.copyIncludeMetadata = document.getElementById('copy-include-metadata');
    elements.copyLogData = document.getElementById('copy-log-data');
    
    // 其他
    elements.refreshBtn = document.getElementById('refresh-btn');
    elements.exportBtn = document.getElementById('export-btn');
    elements.wsStatus = document.getElementById('ws-status');
    elements.wsText = document.getElementById('ws-text');
    
    // 全局搜索
    elements.globalSearch = document.getElementById('global-search');
    elements.searchBtn = document.getElementById('search-btn');
    
    // 批量选择相关
    elements.toggleBatchMode = document.getElementById('toggle-batch-mode');
    elements.batchActionsBar = document.getElementById('batch-actions-bar');
    elements.selectAllLogs = document.getElementById('select-all-logs');
    elements.selectAllPage = document.getElementById('select-all-page');
    elements.selectedCount = document.getElementById('selected-count');
    elements.copySelectedLogs = document.getElementById('copy-selected-logs');
    elements.cancelSelection = document.getElementById('cancel-selection');
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
    
    // 分页事件已改为动态绑定

    // 会话交互
    if (elements.sessionsPrevPage) {
        elements.sessionsPrevPage.addEventListener('click', () => changeSessionPage(-1));
        elements.sessionsNextPage.addEventListener('click', () => changeSessionPage(1));
        elements.sessionSearch.addEventListener('input', debounce(filterSessions, 300));
        elements.sessionSort.addEventListener('change', filterSessions);
    }
    
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
    if (elements.copyLogData) {
        elements.copyLogData.addEventListener('click', copyInteractionData);
    }
    if (elements.copyIncludeMetadata) {
        elements.copyIncludeMetadata.addEventListener('change', () => {
            if (currentLogDetail) {
                elements.copyLogData.focus();
            }
        });
    }
    if (elements.modal) {
        elements.modal.addEventListener('hidden.bs.modal', () => {
            currentLogDetail = null;
            setCopyLogButtonState(false);
            setCopyMetadataToggle(false);
        });
    }
    
    // 批量选择相关事件
    if (elements.toggleBatchMode) {
        elements.toggleBatchMode.addEventListener('click', (e) => {
            e.preventDefault();
            toggleBatchSelectionMode();
        });
    }
    if (elements.cancelSelection) {
        elements.cancelSelection.addEventListener('click', exitBatchSelectionMode);
    }
    if (elements.selectAllLogs) {
        elements.selectAllLogs.addEventListener('change', (e) => toggleSelectAllLogs(e.target.checked));
    }
    if (elements.selectAllPage) {
        elements.selectAllPage.addEventListener('change', (e) => toggleSelectAllPage(e.target.checked));
    }
    if (elements.copySelectedLogs) {
        elements.copySelectedLogs.addEventListener('click', copySelectedLogsAsLLMFormat);
    }
    
    // 刷新
    elements.refreshBtn.addEventListener('click', () => {
        if (state.currentView === 'dashboard') {
            state.recentPagination.page = 1;
            loadDashboard();
        } else if (state.currentView === 'logs') {
            loadLogs();
        } else if (state.currentView === 'sessions') {
            loadSessions();
        }
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
        // 添加实时搜索（防抖）
        elements.globalSearch.addEventListener('input', debounce(() => {
            if (elements.globalSearch.value.trim()) {
                performGlobalSearch();
            }
        }, 500));
    }
    
    // Sidebar Toggle
    const sidebarToggle = document.getElementById('sidebarToggle');
    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', (e) => {
            e.preventDefault();
            document.getElementById('wrapper').classList.toggle('toggled');
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
        
        // 方向键翻页（仅在模态框关闭时生效）
        if (bsModal && !document.querySelector('.modal.show')) {
            if (e.key === 'ArrowLeft') {
                e.preventDefault();
                handlePagination(-1);
            } else if (e.key === 'ArrowRight') {
                e.preventDefault();
                handlePagination(1);
            }
        }
    });
    
    // 窗口大小改变时重新计算分页
    let resizeTimer;
    window.addEventListener('resize', () => {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            const config = getPaginationConfig();
            let currentLimit;
            
            switch (state.currentView) {
                case 'logs':
                    currentLimit = state.pagination.limit;
                    if (currentLimit !== config.limit) {
                        state.pagination.limit = config.limit;
                        state.pagination.page = 1;
                        loadLogs();
                    }
                    break;
                case 'dashboard':
                    currentLimit = state.recentPagination.limit;
                    if (currentLimit !== config.limit) {
                        state.recentPagination.limit = config.limit;
                        state.recentPagination.page = 1;
                        loadDashboard();
                    }
                    break;
                case 'toolcalls':
                    if (typeof tcState !== 'undefined') {
                        currentLimit = tcState.pagination.limit;
                        if (currentLimit !== config.limit) {
                            tcState.pagination.limit = config.limit;
                            tcState.pagination.page = 1;
                            if (typeof loadToolCalls === 'function') loadToolCalls();
                        }
                    }
                    break;
            }
        }, 300);
    });
}

// 统一的分页处理函数
function handlePagination(delta) {
    switch (state.currentView) {
        case 'dashboard':
            changeRecentPage(delta);
            break;
        case 'logs':
            changePage(delta);
            break;
        case 'agents':
            changeAgentsPage(delta);
            break;
        case 'toolcalls':
            if (typeof changeToolCallPage === 'function') {
                changeToolCallPage(delta);
            }
            break;
    }
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
    // 已移除的视图重定向到仪表盘
    if (view === 'sessions' || view === 'analytics') {
        view = 'dashboard';
    }
    
    state.currentView = view;
    
    // 更新导航
    elements.navItems.forEach(item => {
        item.classList.toggle('active', item.dataset.view === view);
    });
    
    // 更新视图
    elements.views.forEach(v => {
        v.classList.toggle('active', v.id === `view-${view}`);
    });
    
    // 根据视图更新分页限制
    const config = getPaginationConfig();
    switch (view) {
        case 'dashboard':
            state.recentPagination.limit = config.limit;
            loadDashboard();
            break;
        case 'logs':
            state.pagination.limit = config.limit;
            if (state.logs.length === 0) {
                loadLogs();
            }
            break;
        case 'agents':
            loadAgentsTimeline();
            break;
        case 'toolcalls':
            if (typeof tcState !== 'undefined') {
                tcState.pagination.limit = config.limit;
            }
            if (typeof loadToolCallStats === 'function') loadToolCallStats();
            if (typeof loadToolCalls === 'function') loadToolCalls();
            break;
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
        
        // 如果日志数量变化，刷新当前视图
        if (currentCount !== lastLogCount) {
            if (state.currentView === 'dashboard') {
                loadDashboard();
            } else if (state.currentView === 'logs') {
                loadLogs();
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
    if (elements.wsStatus) {
        elements.wsStatus.classList.remove('online', 'offline');
        elements.wsStatus.classList.add(connected ? 'online' : 'offline');
    }
    if (elements.wsText) {
        elements.wsText.textContent = connected ? '在线' : '离线';
    }
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

async function apiDelete(endpoint) {
    const response = await fetch(`${API_BASE}${endpoint}`, {
        method: 'DELETE'
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
            apiGet(`/api/logs?limit=${state.recentPagination.limit}&offset=${(state.recentPagination.page - 1) * state.recentPagination.limit}`)
        ]);

        updateStats(stats);
        state.recentLogs = logs;
        updateRecentLogs(logs);
        updateRecentPagination();

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
        // Show loading state
        if (elements.sessionsGrid) {
            elements.sessionsGrid.innerHTML = '<div class="col-12 text-center py-5"><div class="spinner-border text-primary" role="status"></div><p class="mt-2 text-secondary">加载会话中...</p></div>';
        }
        
        const params = new URLSearchParams({
            limit: state.session.limit,
            offset: (state.session.page - 1) * state.session.limit
        });
        
        if (state.session.search) {
            params.append('search', state.session.search);
        }
        
        // Note: Sort is not supported by API yet, always by newest
        
        const response = await apiGet(`/api/sessions?${params}`);
        
        state.session.data = response.sessions;
        state.session.total = response.total;
        
        renderSessions();
        
    } catch (error) {
        console.error('Failed to load sessions:', error);
        showError('加载会话失败');
        if (elements.sessionsGrid) {
            elements.sessionsGrid.innerHTML = `<div class="col-12 text-center py-5 text-danger"><p>加载失败: ${error.message}</p></div>`;
        }
    }
}

function filterSessions() {
    const search = elements.sessionSearch ? elements.sessionSearch.value.trim() : '';
    
    // Update state and reload
    state.session.search = search;
    state.session.page = 1;
    loadSessions();
}

function changeSessionPage(delta) {
    const maxPage = Math.ceil(state.session.total / state.session.limit);
    const newPage = state.session.page + delta;
    
    if (newPage < 1 || newPage > maxPage) return;
    
    state.session.page = newPage;
    loadSessions();
}

function renderSessions() {
    const sessions = state.session.data;
    const { page, limit, total } = state.session;
    const totalPages = Math.ceil(total / limit);
    
    // Update Grid
    if (sessions.length === 0) {
        elements.sessionsGrid.innerHTML = `
            <div class="col-12 empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="12" y1="8" x2="12" y2="12"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>
                <p>未找到匹配的会话</p>
            </div>
        `;
    } else {
        elements.sessionsGrid.innerHTML = sessions.map(session => `
            <div class="col-md-6 col-lg-4 col-xl-3">
                <div class="session-card" onclick="viewSession('${session.session_id}')">
                    <div class="session-header">
                        <span class="session-id" title="${session.session_id}">${session.session_id.slice(0, 8)}...${session.session_id.slice(-4)}</span>
                        <span class="session-time">${formatShortTime(session.start_time)}</span>
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
            </div>
        `).join('');
    }
    
    // Update Pagination Controls
    if (elements.sessionsPaginationInfo) {
        const start = (page - 1) * limit;
        const end = start + sessions.length;
        elements.sessionsPaginationInfo.textContent = `显示 ${start + 1}-${end} 条，共 ${total} 条`;
        elements.sessionsCurrentPage.textContent = page;
        elements.sessionsPrevPage.disabled = page <= 1;
        elements.sessionsNextPage.disabled = page >= totalPages;
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
        const [sessionsResponse, models, types] = await Promise.all([
            apiGet('/api/sessions?limit=100'), // Limit to 100 for dropdown
            apiGet('/api/models'),
            apiGet('/api/call-types')
        ]);
        
        const sessions = sessionsResponse.sessions || [];

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
        
        // 更新状态
        state.agentsTimeline.data = data;
        state.agentsTimeline.filtered = data;
        state.agentsTimeline.total = data.length;
        state.agentsTimeline.page = 1;
        
        // 渲染当前页
        renderAgentsTimelinePage();
        
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

// 渲染当前页的 Agent
function renderAgentsTimelinePage() {
    const { data, filtered, page, limit } = state.agentsTimeline;
    const agentsToShow = filtered.length > 0 ? filtered : data;
    
    // 计算分页
    const start = (page - 1) * limit;
    const end = Math.min(start + limit, agentsToShow.length);
    const pageAgents = agentsToShow.slice(start, end);
    
    updateAgentsTimeline(pageAgents);
    updateAgentsPagination();
}

// 更新分页控件
function updateAgentsPagination() {
    const { page, limit, total } = state.agentsTimeline;
    const totalPages = Math.ceil(total / limit);
    
    // 查找或创建分页容器
    let paginationContainer = document.getElementById('agents-pagination');
    if (!paginationContainer) {
        paginationContainer = document.createElement('div');
        paginationContainer.id = 'agents-pagination';
        paginationContainer.className = 'pagination-footer mt-4';
        elements.agentsTimeline.parentNode.insertBefore(paginationContainer, elements.agentsTimeline.nextSibling);
    }
    
    if (total <= limit) {
        paginationContainer.innerHTML = '';
        paginationContainer.style.display = 'none';
        return;
    }
    
    paginationContainer.style.display = 'flex';
    paginationContainer.innerHTML = `
        <span class="pagination-info">共 ${total} 个 Agent，第 ${page} / ${totalPages} 页</span>
        <div class="pagination-nav">
            <button class="pagination-btn" onclick="changeAgentsPage(-1)" ${page <= 1 ? 'disabled' : ''}>
                <i class="bi bi-chevron-left"></i>
            </button>
            <span class="pagination-current">${page}</span>
            <button class="pagination-btn" onclick="changeAgentsPage(1)" ${page >= totalPages ? 'disabled' : ''}>
                <i class="bi bi-chevron-right"></i>
            </button>
        </div>
    `;
}

// 翻页函数
function changeAgentsPage(delta) {
    const { page, limit, total } = state.agentsTimeline;
    const totalPages = Math.ceil(total / limit);
    const newPage = page + delta;
    
    if (newPage < 1 || newPage > totalPages) return;
    
    state.agentsTimeline.page = newPage;
    renderAgentsTimelinePage();
    
    // 滚动到顶部
    elements.agentsTimeline.scrollIntoView({ behavior: 'smooth', block: 'start' });
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

    // 限制每个 Agent 显示的 calls 数量，避免单个 Agent 记录过多导致卡顿
    const MAX_CALLS_PER_AGENT = 20;

    elements.agentsTimeline.innerHTML = agents.map(agent => {
        const callsToShow = agent.calls.slice(0, MAX_CALLS_PER_AGENT);
        const hasMoreCalls = agent.calls.length > MAX_CALLS_PER_AGENT;

        return `
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
            <div class="agent-calls-list">
                ${callsToShow.map(call => `
                    <div class="call-list-item ${call.status}" onclick="viewLog('${call.id}')" title="${call.call_type} - ${call.model}">
                        <span class="call-time">${formatShortTime(call.timestamp)}</span>
                        <span class="call-type">${call.call_type}</span>
                        <span class="call-status">${renderStatus(call.status, call.success)}</span>
                        <span class="call-latency">${call.latency_ms.toFixed(0)}ms</span>
                    </div>
                `).join('')}
                ${hasMoreCalls ? `
                    <div class="call-list-more">
                        <span>还有 ${agent.calls.length - MAX_CALLS_PER_AGENT} 条记录...</span>
                    </div>
                ` : ''}
            </div>
        </div>
    `}).join('');
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
    if (!state.agentsTimeline.data) return;

    const typeFilter = elements.filterAgentType ? elements.filterAgentType.value : '';
    const statusFilter = elements.filterAgentStatus ? elements.filterAgentStatus.value : '';

    let filtered = [...state.agentsTimeline.data];

    if (typeFilter) {
        filtered = filtered.filter(a => a.agent_type === typeFilter);
    }

    if (statusFilter) {
        filtered = filtered.filter(a => a.status === statusFilter);
    }

    state.agentsTimeline.filtered = filtered;
    state.agentsTimeline.total = filtered.length;
    state.agentsTimeline.page = 1;

    renderAgentsTimelinePage();
}

function clearAgentFilters() {
    if (elements.filterAgentType) elements.filterAgentType.value = '';
    if (elements.filterAgentStatus) elements.filterAgentStatus.value = '';

    state.agentsTimeline.filtered = state.agentsTimeline.data;
    state.agentsTimeline.total = state.agentsTimeline.data.length;
    state.agentsTimeline.page = 1;

    renderAgentsTimelinePage();
}

// ==================== UI 更新 ====================

function updateStats(stats) {
    elements.statSuccess.textContent = stats.success_calls.toLocaleString();
    elements.statFailed.textContent = stats.failed_calls.toLocaleString();
    elements.statTotal.textContent = stats.total_calls.toLocaleString();
    elements.statRate.textContent = (stats.success_rate * 100).toFixed(1) + '%';
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function estimateTokens(log) {
    let totalChars = 0;
    
    // system_prompt
    if (log.system_prompt) {
        totalChars += log.system_prompt.length;
    }
    
    // messages
    if (log.messages) {
        log.messages.forEach(m => {
            if (m.content) totalChars += m.content.length;
        });
    }
    
    // response_content
    if (log.response_content) {
        totalChars += log.response_content.length;
    }
    
    // response (object stringify)
    if (log.response && typeof log.response === 'object') {
        totalChars += JSON.stringify(log.response).length;
    }
    
    // tool_calls in messages
    if (log.messages) {
        log.messages.forEach(m => {
            if (m.tool_calls) {
                m.tool_calls.forEach(tc => {
                    const args = tc.args || tc.arguments || (tc.function && tc.function.arguments);
                    if (args) {
                        totalChars += (typeof args === 'string') ? args.length : JSON.stringify(args).length;
                    }
                    if (tc.name) totalChars += tc.name.length;
                    if (tc.function && tc.function.name) totalChars += tc.function.name.length;
                });
            }
        });
    }
    
    // 粗略估算：1 token ≈ 4 字符
    return Math.ceil(totalChars / 4);
}

function formatTokenCount(tokens) {
    if (tokens >= 10000) {
        return (tokens / 1000).toFixed(1) + 'k';
    } else if (tokens >= 1000) {
        return (tokens / 1000).toFixed(2) + 'k';
    }
    return tokens.toString();
}

function renderLogRows(logs, showToken = false) {
    const batchEnabled = state.batchSelection.enabled;
    const baseColCount = showToken ? 8 : 7;
    const colCount = baseColCount + (batchEnabled ? 1 : 0);
    
    if (logs.length === 0) {
        return `<tr><td colspan="${colCount}" class="empty-state">暂无日志数据</td></tr>`;
    }
    
    return logs.map(log => {
        const isViewed = logStateManager.isViewed(log.id);
        const isStarred = logStateManager.isStarred(log.id);
        const isSelected = state.batchSelection.selectedIds.has(log.id);
        const rowClass = isViewed ? 'log-row viewed' : 'log-row';
        const safeId = String(log.id).replace(/'/g, "\\'");
        const tokenCount = estimateTokens(log);
        
        // 复选框列（仅在批量模式下显示）
        const selectCol = batchEnabled ? `
            <td class="batch-select-col text-center">
                <input type="checkbox" class="form-check-input log-select-checkbox" data-log-id="${log.id}" ${isSelected ? 'checked' : ''}>
            </td>` : '';
        
        return `
        <tr data-id="${log.id}" class="${rowClass}">
            ${selectCol}
            <td>${formatTime(log.timestamp)}</td>
            <td>${renderAgentType(log.agent_type)}</td>
            <td class="target-function-cell"><span class="target-function-tag" title="${escapeHtml(log.target_function || '-')}">${escapeHtml(log.target_function || '-')}</span></td>
            <td>${log.latency_ms.toFixed(0)}ms</td>
            ${showToken ? `<td>${formatTokenCount(tokenCount)}</td>` : ''}
            <td>${renderStatus(log.status, log.success)}</td>
            <td class="star-cell">
                <button class="star-btn ${isStarred ? 'starred' : ''}" data-log-id="${log.id}" title="${isStarred ? '取消标注' : '标注为关键日志'}">
                    <svg viewBox="0 0 24 24" fill="${isStarred ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="2">
                        <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon>
                    </svg>
                </button>
            </td>
            <td class="actions-cell">
                <button class="btn-icon danger btn-delete" data-log-id="${log.id}" title="删除日志">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="3 6 5 6 21 6"></polyline>
                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                    </svg>
                </button>
            </td>
        </tr>
    `}).join('');
}

function updateLogsTable(logs) {
    elements.logsTableBody.innerHTML = renderLogRows(logs, true);
    bindTableEvents(elements.logsTableBody);
}

// 切换日志标注状态 - 日志列表
function toggleLogStar(logId, btn) {
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
    tbody.innerHTML = renderLogRows(logs, false);
    bindTableEvents(tbody);
}

function updateRecentPagination() {
    state.recentPagination.total = state.recentLogs.length;
    const totalPages = Math.ceil(state.recentPagination.total / state.recentPagination.limit) || 1;
    const current = state.recentPagination.page;

    if (elements.recentPaginationInfo) {
        elements.recentPaginationInfo.textContent = `共 ${state.recentPagination.total} 条 · ${totalPages} 页`;
    }
    
    // 渲染分页按钮
    const paginationNav = document.querySelector('#view-dashboard .pagination-nav');
    if (paginationNav) {
        paginationNav.innerHTML = renderPaginationButtons(current, totalPages, 'recent');
    }
}

function changeRecentPage(delta) {
    const newPage = state.recentPagination.page + delta;
    const totalPages = Math.ceil(state.recentPagination.total / state.recentPagination.limit) || 1;

    if (newPage < 1 || newPage > totalPages) return;

    state.recentPagination.page = newPage;
    loadDashboard();
}

// 绑定表格事件（双击查看、点击按钮）
function bindTableEvents(tbody) {
    if (!tbody) return;
    
    // 行双击事件 - 查看详情（仅在非批量模式下）
    tbody.querySelectorAll('tr[data-id]').forEach(row => {
        row.addEventListener('dblclick', () => {
            if (state.batchSelection.enabled) return;
            const logId = row.dataset.id;
            if (logId) {
                // 标记为已查看
                logStateManager.markAsViewed(logId);
                row.classList.add('viewed');
                viewLog(logId);
            }
        });
    });
    
    // 删除按钮点击事件
    tbody.querySelectorAll('.btn-delete').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const logId = btn.dataset.logId;
            if (logId) deleteLog(logId);
        });
    });
    
    // 标注按钮点击事件
    tbody.querySelectorAll('.star-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const logId = btn.dataset.logId;
            if (logId) toggleLogStar(logId, btn);
        });
    });
    
    // 批量选择复选框事件
    tbody.querySelectorAll('.log-select-checkbox').forEach(cb => {
        cb.addEventListener('change', (e) => {
            e.stopPropagation();
            const logId = cb.dataset.logId;
            if (logId) toggleLogSelection(logId, e.target.checked);
        });
    });
}

// ==================== 批量选择功能 ====================

function toggleBatchSelectionMode() {
    state.batchSelection.enabled = !state.batchSelection.enabled;
    updateBatchSelectionUI();
}

function exitBatchSelectionMode() {
    state.batchSelection.enabled = false;
    state.batchSelection.selectedIds.clear();
    state.batchSelection.logDetails.clear();
    updateBatchSelectionUI();
}

function updateBatchSelectionUI() {
    const enabled = state.batchSelection.enabled;
    
    // 显示/隐藏批量操作栏
    if (elements.batchActionsBar) {
        elements.batchActionsBar.style.display = enabled ? 'block' : 'none';
    }
    
    // 显示/隐藏表格中的选择列
    document.querySelectorAll('.batch-select-col').forEach(col => {
        col.style.display = enabled ? 'table-cell' : 'none';
    });
    
    // 更新表格行显示
    updateLogsTable(state.logs);
    
    // 更新选择计数
    updateSelectedCount();
    
    // 更新按钮状态
    if (elements.toggleBatchMode) {
        elements.toggleBatchMode.classList.toggle('active', enabled);
    }
}

function toggleSelectAllLogs(checked) {
    if (checked) {
        // 选择所有可见的日志
        state.logs.forEach(log => {
            state.batchSelection.selectedIds.add(log.id);
        });
    } else {
        state.batchSelection.selectedIds.clear();
    }
    
    // 更新UI
    document.querySelectorAll('.log-select-checkbox').forEach(cb => {
        cb.checked = checked;
    });
    
    if (elements.selectAllPage) {
        elements.selectAllPage.checked = checked;
    }
    
    updateSelectedCount();
}

function toggleSelectAllPage(checked) {
    const checkboxes = document.querySelectorAll('.log-select-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = checked;
        const logId = cb.dataset.logId;
        if (logId) {
            if (checked) {
                state.batchSelection.selectedIds.add(logId);
            } else {
                state.batchSelection.selectedIds.delete(logId);
            }
        }
    });
    updateSelectedCount();
}

function toggleLogSelection(logId, checked) {
    if (checked) {
        state.batchSelection.selectedIds.add(logId);
    } else {
        state.batchSelection.selectedIds.delete(logId);
    }
    updateSelectedCount();
}

function updateSelectedCount() {
    const count = state.batchSelection.selectedIds.size;
    if (elements.selectedCount) {
        elements.selectedCount.textContent = `已选择 ${count} 条`;
    }
    if (elements.copySelectedLogs) {
        elements.copySelectedLogs.disabled = count === 0;
    }
    if (elements.selectAllLogs) {
        elements.selectAllLogs.checked = count > 0 && count === state.logs.length;
    }
}

async function copySelectedLogsAsLLMFormat() {
    const selectedIds = Array.from(state.batchSelection.selectedIds);
    if (selectedIds.length === 0) {
        showError('请先选择至少一条日志');
        return;
    }
    
    // 显示加载状态
    const originalText = elements.copySelectedLogs.innerHTML;
    elements.copySelectedLogs.disabled = true;
    elements.copySelectedLogs.innerHTML = '<i class="bi bi-hourglass-split"></i> 加载中...';
    
    try {
        // 获取所有选中日志的详情
        const logs = [];
        for (const logId of selectedIds) {
            // 优先使用已缓存的详情
            let logDetail = state.batchSelection.logDetails.get(logId);
            if (!logDetail) {
                logDetail = await apiGet(`/api/logs/${logId}`);
                state.batchSelection.logDetails.set(logId, logDetail);
            }
            logs.push(logDetail);
        }
        
        // 按时间排序
        logs.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
        
        // 生成格式化的文本
        const formattedText = formatMultipleLogsForLLM(logs);
        
        // 复制到剪贴板
        await navigator.clipboard.writeText(formattedText);
        
        // 显示成功状态
        elements.copySelectedLogs.classList.add('copied');
        elements.copySelectedLogs.innerHTML = '<i class="bi bi-check2"></i> 已复制';
        
        if (batchCopyResetTimer) clearTimeout(batchCopyResetTimer);
        batchCopyResetTimer = setTimeout(() => {
            elements.copySelectedLogs.classList.remove('copied');
            elements.copySelectedLogs.innerHTML = originalText;
            elements.copySelectedLogs.disabled = false;
        }, 2000);
        
    } catch (error) {
        console.error('Failed to copy logs:', error);
        showError('复制失败: ' + error.message);
        elements.copySelectedLogs.innerHTML = originalText;
        elements.copySelectedLogs.disabled = false;
    }
}

function formatMultipleLogsForLLM(logs) {
    const sections = [];
    
    sections.push('# LLM 交互日志集合');
    sections.push('');
    sections.push(`共 ${logs.length} 条日志，按时间顺序排列`);
    sections.push('');
    sections.push('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    sections.push('');
    
    logs.forEach((log, index) => {
        const isFirst = index === 0;
        const isLast = index === logs.length - 1;
        
        // 日志头部分隔线
        sections.push('╔══════════════════════════════════════════════════════════════════════════════╗');
        sections.push(`║  日志 ${String(index + 1).padStart(2, '0')} / ${String(logs.length).padStart(2, '0')}                                                          ║`);
        sections.push('╚══════════════════════════════════════════════════════════════════════════════╝');
        sections.push('');
        
        // 日志内容
        sections.push(formatInteractionDataMarkdown(log, false));
        
        // 日志尾部分隔线
        if (!isLast) {
            sections.push('');
            sections.push('───────────────────────────────────────────────────────────────────────────────');
            sections.push('');
        }
    });
    
    // 整体结束标记
    sections.push('');
    sections.push('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    sections.push('');
    sections.push('// 日志集合结束');
    sections.push('');
    
    return sections.join('\n');
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
    const current = state.pagination.page;
    // 通过判断返回的数据是否少于 limit 来估算是否有下一页
    const hasMore = state.logs.length >= state.pagination.limit;
    
    if (elements.paginationInfo) {
        elements.paginationInfo.textContent = `第 ${current} 页 · 每页 ${state.pagination.limit} 条`;
    }
    
    // 渲染分页按钮
    const paginationNav = document.querySelector('#view-logs .pagination-nav');
    if (paginationNav) {
        paginationNav.innerHTML = renderPaginationButtons(current, null, 'logs', !hasMore);
    }
}

// 通用的分页按钮渲染函数
function renderPaginationButtons(current, totalPages, type, isLastPage = false) {
    const isFirst = current <= 1;
    const isLast = totalPages ? current >= totalPages : isLastPage;
    
    let buttons = '';
    
    // 首页按钮
    buttons += `
        <button class="pagination-btn ${isFirst ? 'disabled' : ''}" 
                ${isFirst ? 'disabled' : ''} 
                onclick="goTo${type.charAt(0).toUpperCase() + type.slice(1)}Page(1)" 
                title="首页 (Home)">
            <i class="bi bi-chevron-double-left"></i>
        </button>
    `;
    
    // 上一页按钮
    buttons += `
        <button class="pagination-btn ${isFirst ? 'disabled' : ''}" 
                ${isFirst ? 'disabled' : ''} 
                onclick="${type === 'recent' ? 'changeRecentPage' : type === 'logs' ? 'changePage' : 'changeToolCallPage'}(-1)" 
                title="上一页 (←)">
            <i class="bi bi-chevron-left"></i>
        </button>
    `;
    
    // 当前页显示
    buttons += `<span class="pagination-current">${current}${totalPages ? ' / ' + totalPages : ''}</span>`;
    
    // 下一页按钮
    buttons += `
        <button class="pagination-btn ${isLast ? 'disabled' : ''}" 
                ${isLast ? 'disabled' : ''} 
                onclick="${type === 'recent' ? 'changeRecentPage' : type === 'logs' ? 'changePage' : 'changeToolCallPage'}(1)" 
                title="下一页 (→)">
            <i class="bi bi-chevron-right"></i>
        </button>
    `;
    
    // 末页按钮（如果有总页数）
    if (totalPages) {
        buttons += `
            <button class="pagination-btn ${isLast ? 'disabled' : ''}" 
                    ${isLast ? 'disabled' : ''} 
                    onclick="goTo${type.charAt(0).toUpperCase() + type.slice(1)}Page(${totalPages})" 
                    title="末页 (End)">
                <i class="bi bi-chevron-double-right"></i>
            </button>
        `;
    }
    
    return buttons;
}

// 跳转到指定页
function goToRecentPage(page) {
    if (page < 1) return;
    state.recentPagination.page = page;
    loadDashboard();
}

function goToLogsPage(page) {
    if (page < 1) return;
    state.pagination.page = page;
    loadLogs();
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
                backgroundColor: '#6366f1',
                borderRadius: 8,
                borderSkipped: false
            }]
        },
        options: {
            responsive: true,
            animation: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: { 
                    beginAtZero: true,
                    grid: { color: '#e2e8f0' },
                    ticks: { color: '#64748b' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#64748b' }
                }
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
    const context = ctx.getContext('2d');
    const gradient = context.createLinearGradient(0, 0, 0, 400);
    gradient.addColorStop(0, 'rgba(99, 102, 241, 0.2)');
    gradient.addColorStop(1, 'rgba(99, 102, 241, 0)');

    state.charts.latency = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: '延迟 (ms)',
                data: data,
                borderColor: '#6366f1',
                backgroundColor: gradient,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                pointHoverRadius: 6,
                pointBackgroundColor: '#6366f1',
                pointBorderColor: '#fff',
                pointBorderWidth: 2
            }]
        },
        options: {
            responsive: true,
            animation: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: { 
                    beginAtZero: true,
                    grid: { color: '#e2e8f0' },
                    ticks: { color: '#64748b' }
                },
                x: {
                    grid: { display: false },
                    ticks: { display: false } // 隐藏时间轴标签，避免太拥挤
                }
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
    console.log('[DEBUG] viewLog called with ID:', logId);
    try {
        const log = await apiGet(`/api/logs/${logId}`);
        console.log('[DEBUG] Log details fetched:', log);
        
        // 标记为已查看
        logStateManager.markAsViewed(logId);
        // 更新表格显示（当前行变灰）
        try {
            const safeSelectorId = String(logId).replace(/"/g, '\\"');
            const row = document.querySelector(`tr[data-id="${safeSelectorId}"]`);
            if (row) {
                row.classList.add('viewed');
            }
        } catch (e) {
            console.warn("Could not highlight row:", e);
        }
        
        showLogDetail(log);
    } catch (error) {
        console.error('Failed to load log:', error);
        showError('加载日志详情失败: ' + (error.message || error));
    }
}



function showLogDetail(log) {
    console.log('[DEBUG] showLogDetail called with:', log);
    currentLogDetail = log;
    setCopyLogButtonState(true);
    setCopyMetadataToggle(false);
    
    // 分离 system prompt 和非 system 消息
    const messages = log.messages || [];
    let systemPromptContent = '';
    
    // 优先使用 log.system_prompt
    if (log.system_prompt) {
        systemPromptContent = log.system_prompt;
    } else {
        // 尝试从消息中提取
        const systemMessages = messages.filter(m => {
            const msgType = (m.type || m.role || '').toLowerCase();
            return msgType === 'system' || msgType === 'systemmessage';
        });
        if (systemMessages.length > 0) {
            systemPromptContent = systemMessages.map(m => m.content).join('\n\n');
        }
    }
    
    const nonSystemMessages = messages.filter(m => {
        const msgType = (m.type || m.role || '').toLowerCase();
        return msgType !== 'system' && msgType !== 'systemmessage';
    });
    
    // 生成 system prompt 卡片（与其他消息类型格式一致）
    const systemPromptHtml = systemPromptContent ? `
        <div class="detail-section">
            <h4>System Prompt</h4>
            <div class="message-list">
                <div class="message-card msg-system">
                    <div class="message-card-header" onclick="toggleMessageCard(this)">
                        <div class="message-meta">
                            <span class="msg-type-badge badge-system">
                                <i class="bi bi-gear"></i> System
                            </span>
                        </div>
                        <i class="bi bi-chevron-down message-toggle-icon"></i>
                    </div>
                    <div class="message-card-body" style="display: none;">
                        ${renderMessageContent(systemPromptContent)}
                    </div>
                </div>
            </div>
        </div>
    ` : '';
    
    try {
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
                            <span class="detail-value">${(log.latency_ms || 0).toFixed(2)}ms</span>
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
                        ${nonSystemMessages.length > 0 ? nonSystemMessages.map((m, idx) => `
                            <div class="message-card ${getMessageTypeClass(m.type || m.role)}">
                                <div class="message-card-header" onclick="toggleMessageCard(this)">
                                    <div class="message-meta">
                                        ${renderMessageTypeBadge(m.type || m.role)}
                                        ${m.name ? `<span class="message-name">${escapeHtml(m.name)}</span>` : ''}
                                    </div>
                                    <i class="bi bi-chevron-down message-toggle-icon"></i>
                                </div>
                                <div class="message-card-body">
                                    ${m.content ? renderMessageContent(m.content) : ''}
                                    ${m.tool_calls && m.tool_calls.length > 0 ? `
                                        <div class="tool-calls-section">
                                            <div class="tool-calls-header">
                                                <i class="bi bi-tools"></i> Tool Calls (${m.tool_calls.length})
                                            </div>
                                            ${m.tool_calls.map(tc => {
                                                const toolName = tc.name || (tc.function && tc.function.name) || 'unknown';
                                                let toolArgs = {};
                                                try {
                                                    const rawArgs = tc.args || tc.arguments || (tc.function && tc.function.arguments) || {};
                                                    toolArgs = (typeof rawArgs === 'string') ? JSON.parse(rawArgs) : rawArgs;
                                                } catch (e) {
                                                    toolArgs = { error: "Failed to parse arguments", raw: tc.arguments };
                                                }
                                                
                                                return `
                                                <div class="tool-call-item">
                                                    <div class="tool-call-name"><i class="bi bi-gear"></i> ${toolName}</div>
                                                    <pre class="tool-call-args">${escapeHtml(JSON.stringify(toolArgs, null, 2))}</pre>
                                                </div>
                                                `;
                                            }).join('')}
                                        </div>
                                    ` : ''}
                                </div>
                            </div>
                        `).join('') : '<p class="empty-hint">无消息</p>'}
                    </div>
                </div>
                
                ${log.output_schema ? `
                <div class="detail-section">
                    <h4>输出模式</h4>
                    <div class="message-list">
                        <div class="message-card msg-output">
                            <div class="message-card-header" onclick="toggleMessageCard(this)">
                                <div class="message-meta">
                                    <span class="msg-type-badge badge-output">
                                        <i class="bi bi-braces"></i> Output Schema
                                    </span>
                                </div>
                                <i class="bi bi-chevron-down message-toggle-icon"></i>
                            </div>
                            <div class="message-card-body" style="display: none;">
                                <div class="code-block">
                                    <pre class="value-content json-value"><code>${escapeHtml(log.output_schema)}</code></pre>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                ` : ''}
                
                ${log.response ? `
                <div class="detail-section">
                    <h4>响应</h4>
                    <div class="message-list">
                        <div class="message-card msg-response">
                            <div class="message-card-header" onclick="toggleMessageCard(this)">
                                <div class="message-meta">
                                    <span class="msg-type-badge badge-response">
                                        <i class="bi bi-arrow-return-left"></i> Response
                                    </span>
                                </div>
                                <i class="bi bi-chevron-down message-toggle-icon"></i>
                            </div>
                            <div class="message-card-body" style="display: none;">
                                <div class="code-block">
                                    <pre class="value-content json-value"><code class="language-json">${escapeHtml(JSON.stringify(log.response, null, 2))}</code></pre>
                                </div>
                            </div>
                        </div>
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
    } catch (e) {
        console.error("Error generating modal content:", e);
        elements.modalBody.innerHTML = `<div class="alert alert-danger">渲染日志详情失败: ${e.message}</div>`;
    }
    
    // 高亮代码
    try {
        elements.modalBody.querySelectorAll('pre code').forEach(block => {
            if (window.hljs) {
                hljs.highlightElement(block);
            }
        });
    } catch (e) {
        console.warn("Highlighting failed:", e);
    }
    
    // 显示弹窗
    if (bsModal) {
        bsModal.show();
    } else {
        console.error("Bootstrap Modal instance (bsModal) is not initialized.");
    }
}

// 获取消息类型的 CSS 类名
function getMessageTypeClass(type) {
    const typeMap = {
        'humanmessage': 'msg-human',
        'human': 'msg-human',
        'aimessage': 'msg-ai',
        'ai': 'msg-ai',
        'toolmessage': 'msg-tool',
        'tool': 'msg-tool',
        'systemmessage': 'msg-system',
        'system': 'msg-system'
    };
    return typeMap[(type || '').toLowerCase()] || 'msg-default';
}

// 渲染消息类型标签
function renderMessageTypeBadge(type) {
    const typeConfig = {
        'humanmessage': { label: 'Human', icon: 'bi-person', class: 'badge-human' },
        'human': { label: 'Human', icon: 'bi-person', class: 'badge-human' },
        'aimessage': { label: 'AI', icon: 'bi-robot', class: 'badge-ai' },
        'ai': { label: 'AI', icon: 'bi-robot', class: 'badge-ai' },
        'toolmessage': { label: 'Tool', icon: 'bi-tools', class: 'badge-tool' },
        'tool': { label: 'Tool', icon: 'bi-tools', class: 'badge-tool' },
        'systemmessage': { label: 'System', icon: 'bi-gear', class: 'badge-system' },
        'system': { label: 'System', icon: 'bi-gear', class: 'badge-system' }
    };
    
    const config = typeConfig[(type || '').toLowerCase()] || { label: type || 'Unknown', icon: 'bi-circle', class: 'badge-default' };
    return `<span class="msg-type-badge ${config.class}"><i class="bi ${config.icon}"></i> ${config.label}</span>`;
}

// 渲染消息内容（支持 Markdown 样式）
function renderMessageContent(content) {
    if (!content) return '';
    
    // 处理代码块
    let formatted = escapeHtml(content);
    
    // 高亮 Markdown 标题
    formatted = formatted.replace(/^(#{1,6}\s+.+)$/gm, '<strong class="md-heading">$1</strong>');
    
    // 高亮列表项
    formatted = formatted.replace(/^(\s*[-*+]\s+.+)$/gm, '<span class="md-list-item">$1</span>');
    
    // 高亮数字列表
    formatted = formatted.replace(/^(\s*\d+\.\s+.+)$/gm, '<span class="md-list-item">$1</span>');
    
    return `<div class="message-text">${formatted}</div>`;
}

// 切换消息卡片折叠状态
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

function closeModal() {
    if (bsModal) {
        bsModal.hide();
    }
}

function setCopyLogButtonState(enabled) {
    if (!elements.copyLogData) return;
    elements.copyLogData.disabled = !enabled;
    elements.copyLogData.classList.remove('copied');
    elements.copyLogData.innerHTML = '<i class="bi bi-copy"></i> 复制交互数据';
    if (copyResetTimer) {
        clearTimeout(copyResetTimer);
        copyResetTimer = null;
    }
}

function setCopyMetadataToggle(checked) {
    if (!elements.copyIncludeMetadata) return;
    elements.copyIncludeMetadata.checked = !!checked;
}

function setCopyLogButtonCopied() {
    if (!elements.copyLogData) return;
    elements.copyLogData.classList.add('copied');
    elements.copyLogData.innerHTML = '<i class="bi bi-check2"></i> 已复制';
    if (copyResetTimer) clearTimeout(copyResetTimer);
    copyResetTimer = setTimeout(() => {
        setCopyLogButtonState(true);
    }, 1500);
}

function buildInteractionPayload(log) {
    return {
        id: log.id,
        timestamp: log.timestamp,
        timestamp_local: log.timestamp ? formatTime(log.timestamp) : null,
        session_id: log.session_id,
        agent_id: log.agent_id || null,
        agent_type: log.agent_type || null,
        target_function: log.target_function || null,
        model: log.model,
        call_type: log.call_type,
        status: log.status,
        success: log.success,
        latency_ms: log.latency_ms,
        retry_count: log.retry_count,
        system_prompt: log.system_prompt || null,
        messages: log.messages || [],
        output_schema: log.output_schema || null,
        response: log.response || null,
        error: log.error || null,
        tools: log.tools || null,
        tool_count: log.tool_count ?? null,
        tool_names: log.tool_names || null,
        tool_calls: log.tool_calls || null,
        metadata: log.metadata || null
    };
}

function formatInteractionData(log) {
    const includeMetadata = elements.copyIncludeMetadata && elements.copyIncludeMetadata.checked;
    return formatInteractionDataMarkdown(log, includeMetadata);
}

function formatInteractionDataMarkdown(log, includeMetadata) {
    const lines = [];
    const payload = buildInteractionPayload(log);
    const allMessages = Array.isArray(payload.messages) ? payload.messages : [];

    // 提取 system prompt（优先使用 log.system_prompt，否则从 messages 中提取）
    let systemPromptContent = payload.system_prompt;
    if (!systemPromptContent) {
        const systemMessages = allMessages.filter(m => {
            const msgType = (m.type || m.role || '').toLowerCase();
            return msgType === 'system' || msgType === 'systemmessage';
        });
        if (systemMessages.length > 0) {
            systemPromptContent = systemMessages.map(m => m.content).join('\n\n');
        }
    }

    // 过滤掉 system 类型的消息（与 UI 渲染保持一致）
    const messages = allMessages.filter(m => {
        const msgType = (m.type || m.role || '').toLowerCase();
        return msgType !== 'system' && msgType !== 'systemmessage';
    });

    lines.push('# 日志交互数据');
    lines.push('');
    lines.push('===== 基本信息 =====');
    lines.push(`- ID: ${formatScalar(payload.id)}`);
    lines.push(`- 时间: ${formatScalar(payload.timestamp)}`);
    lines.push(`- 本地时间: ${formatScalar(payload.timestamp_local)}`);
    lines.push(`- 会话: ${formatScalar(payload.session_id)}`);
    lines.push(`- Agent: ${formatScalar(payload.agent_id)}`);
    lines.push(`- Agent 类型: ${formatScalar(payload.agent_type)}`);
    lines.push(`- 目标函数: ${formatScalar(payload.target_function)}`);
    lines.push(`- 模型: ${formatScalar(payload.model)}`);
    lines.push(`- 类型: ${formatScalar(payload.call_type)}`);
    lines.push(`- 状态: ${formatScalar(payload.status)}`);
    lines.push(`- 成功: ${formatScalar(payload.success)}`);
    lines.push(`- 延迟(ms): ${formatScalar(payload.latency_ms)}`);
    lines.push(`- 重试次数: ${formatScalar(payload.retry_count)}`);
    lines.push('');

    lines.push('===== System Prompt =====');
    lines.push(formatTextBlock(systemPromptContent));
    lines.push('');

    lines.push('===== 消息 =====');
    if (messages.length === 0) {
        lines.push(formatTextBlock(null));
        lines.push('');
    } else {
        messages.forEach((message, index) => {
            const msg = normalizeMessageEntry(message);
            const typeOrRole = (msg.type || msg.role || '').toString();
            const label = getMessageRoleLabel(typeOrRole);
            const headerParts = [label];
            if (typeOrRole && typeOrRole.toLowerCase() !== label.toLowerCase()) {
                headerParts.push(typeOrRole);
            }
            if (msg.name) {
                headerParts.push(msg.name);
            }
            lines.push(`<message index="${index + 1}" type="${headerParts.join(' / ')}">`);
            lines.push(formatContentBlock(msg.content));

            let toolCalls = null;
            if (msg && typeof msg === 'object' && 'tool_calls' in msg) {
                toolCalls = msg.tool_calls;
            }
            if (toolCalls) {
                lines.push('<tool_calls>');
                lines.push(formatJsonBlock(toolCalls));
                lines.push('</tool_calls>');
            }
            lines.push('</message>');
            lines.push('');
        });
    }

    lines.push('===== 输出模式 =====');
    lines.push(formatTextBlock(payload.output_schema));
    lines.push('');

    lines.push('===== 响应 =====');
    lines.push(formatJsonBlock(payload.response));
    lines.push('');

    lines.push('===== 错误 =====');
    lines.push(formatTextBlock(payload.error));
    lines.push('');

    if (includeMetadata) {
        lines.push('===== 元数据 =====');
        lines.push(formatJsonBlock(payload.metadata));
        lines.push('');
    }

    return lines.join('\n');
}

function formatScalar(value) {
    if (value === null || value === undefined || value === '') return '（空）';
    if (typeof value === 'string') return value;
    if (typeof value === 'number' || typeof value === 'boolean') return String(value);
    try {
        return JSON.stringify(value);
    } catch (e) {
        return String(value);
    }
}

function formatTextBlock(value) {
    if (value === null || value === undefined || value === '') {
        return createCodeBlock('text', '（空）');
    }
    if (typeof value === 'string') {
        return createCodeBlock('text', value);
    }
    try {
        return createCodeBlock('json', JSON.stringify(value, null, 2));
    } catch (e) {
        return createCodeBlock('text', String(value));
    }
}

function formatContentBlock(value) {
    if (value === null || value === undefined || value === '') {
        return createCodeBlock('text', '（空）');
    }
    if (typeof value === 'string') {
        return createCodeBlock('text', value);
    }
    try {
        return createCodeBlock('json', JSON.stringify(value, null, 2));
    } catch (e) {
        return createCodeBlock('text', String(value));
    }
}

function formatJsonBlock(value) {
    if (value === null || value === undefined || value === '') {
        return createCodeBlock('json', '（空）');
    }
    if (typeof value === 'string') {
        return createCodeBlock('json', value);
    }
    try {
        return createCodeBlock('json', JSON.stringify(value, null, 2));
    } catch (e) {
        return createCodeBlock('json', String(value));
    }
}

function createCodeBlock(language, content) {
    return `\`\`\`${language}\n${content}\n\`\`\``;
}

function normalizeMessageEntry(message) {
    if (message && typeof message === 'object') return message;
    return { content: message };
}

function getMessageRoleLabel(typeOrRole) {
    const normalized = (typeOrRole || '').toLowerCase();
    if (['aimessage', 'ai', 'assistant'].includes(normalized)) return 'AI';
    if (['humanmessage', 'human', 'user'].includes(normalized)) return 'Human';
    if (['toolmessage', 'tool'].includes(normalized)) return 'Tool';
    if (['systemmessage', 'system'].includes(normalized)) return 'System';
    if (normalized.includes('agent')) return 'Agent';
    return normalized ? normalized : 'Unknown';
}

async function copyInteractionData() {
    if (!currentLogDetail) {
        showError('暂无可复制的日志');
        return;
    }

    let text = '';
    try {
        text = formatInteractionData(currentLogDetail);
    } catch (e) {
        console.error('Format failed:', e);
        showError('格式化失败，请检查日志内容');
        return;
    }
    try {
        await navigator.clipboard.writeText(text);
        setCopyLogButtonCopied();
    } catch (e) {
        const success = fallbackCopyToClipboard(text);
        if (success) {
            setCopyLogButtonCopied();
        } else {
            console.error('Copy failed:', e);
            showError('复制失败，请手动选择复制');
        }
    }
}

function fallbackCopyToClipboard(text) {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    let success = false;
    try {
        success = document.execCommand('copy');
    } catch (e) {
        success = false;
    }
    document.body.removeChild(textarea);
    return success;
}

function viewSession(sessionId) {
    // 切换到日志视图并筛选会话
    switchView('logs');
    if (elements.filterSession) {
        elements.filterSession.value = sessionId;
        applyFilters();
    }
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

// 防抖函数
function debounce(func, wait) {
    let timeout;
    return function(...args) {
        const context = this;
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(context, args), wait);
    };
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
    const container = document.getElementById('toolcalls-list');
    if (!container) return;

    if (logs.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>暂无 Tool Call 日志</p></div>';
        return;
    }

    container.innerHTML = logs.map(log => {
        // 构建工具调用列表
        const toolCallsHtml = log.tool_calls && log.tool_calls.length > 0
            ? log.tool_calls.map(tc => `
                <div class="tc-tool-item">
                    <div class="tc-tool-header">
                        <span class="tc-tool-name">${tc.name || 'unknown'}</span>
                        <span class="tc-tool-status ${tc.success ? 'success' : 'failed'}">${tc.success ? '成功' : '失败'}</span>
                    </div>
                    <div class="tc-tool-args">
                        <pre><code>${escapeHtml(JSON.stringify(tc.args || tc.arguments || {}, null, 2))}</code></pre>
                    </div>
                </div>
            `).join('')
            : '<div class="tc-empty-tools">无工具调用</div>';

        return `
        <div class="tc-card" data-id="${log.id}">
            <div class="tc-header">
                <div class="tc-meta">
                    <span class="tc-time">${formatTime(log.timestamp)}</span>
                    <span class="tc-agent" title="${log.agent_id || '-'}">${log.agent_id ? log.agent_id.substring(0, 12) + '...' : '-'}</span>
                    <span class="tc-status ${log.success ? 'success' : 'failed'}">${renderStatus(log.status, log.success)}</span>
                </div>
                <div class="tc-actions">
                    <span class="tc-latency">${log.latency_ms.toFixed(0)}ms</span>
                    <button class="btn btn-sm btn-secondary" onclick="viewToolCallDetail('${log.id}')">详情</button>
                </div>
            </div>
            <div class="tc-target">${escapeHtml(log.target_function || 'Unknown target')}</div>
            <div class="tc-tools-list">
                ${toolCallsHtml}
            </div>
        </div>
    `}).join('');
}

function updateToolCallPagination() {
    const info = document.getElementById('tc-pagination-info');
    const current = tcState.pagination.page;
    const hasMore = tcState.logs.length >= tcState.pagination.limit;
    
    if (info) {
        info.textContent = `第 ${current} 页 · 每页 ${tcState.pagination.limit} 条`;
    }
    
    // 渲染分页按钮
    const paginationNav = document.querySelector('#view-toolcalls .pagination-nav, #view-toolcalls .btn-group');
    if (paginationNav) {
        // 如果是 btn-group，替换为 pagination-nav
        if (paginationNav.classList.contains('btn-group')) {
            paginationNav.className = 'pagination-nav';
            paginationNav.id = 'tc-pagination-nav';
        }
        paginationNav.innerHTML = renderPaginationButtons(current, null, 'toolcalls', !hasMore);
    }
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

    currentLogDetail = log;
    setCopyLogButtonState(true);
    setCopyMetadataToggle(false);
    
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
                <div class="message-list">
                    <div class="message-card msg-ai">
                        <div class="message-card-header" onclick="toggleMessageCard(this)">
                            <div class="message-meta">
                                <span class="msg-type-badge badge-ai">
                                    <i class="bi bi-chat-text"></i> Content
                                </span>
                            </div>
                            <i class="bi bi-chevron-down message-toggle-icon"></i>
                        </div>
                        <div class="message-card-body">
                            ${renderMessageContent(log.response_content)}
                        </div>
                    </div>
                </div>
            </div>
            ` : ''}
            
            ${log.error ? `
            <div class="detail-section">
                <h4>错误</h4>
                <div class="message-list">
                    <div class="message-card msg-error">
                        <div class="message-card-header" onclick="toggleMessageCard(this)">
                            <div class="message-meta">
                                <span class="msg-type-badge badge-error">
                                    <i class="bi bi-exclamation-triangle"></i> Error
                                </span>
                            </div>
                            <i class="bi bi-chevron-down message-toggle-icon"></i>
                        </div>
                        <div class="message-card-body">
                            <div class="code-block">
                                <pre class="value-content" style="color: var(--danger);">${escapeHtml(log.error)}</pre>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            ` : ''}
            
            ${log.response ? `
            <div class="detail-section">
                <h4>完整响应</h4>
                <div class="message-list">
                    <div class="message-card msg-response">
                        <div class="message-card-header" onclick="toggleMessageCard(this)">
                            <div class="message-meta">
                                <span class="msg-type-badge badge-response">
                                    <i class="bi bi-arrow-return-left"></i> Response
                                </span>
                            </div>
                            <i class="bi bi-chevron-down message-toggle-icon"></i>
                        </div>
                        <div class="message-card-body" style="display: none;">
                            <div class="code-block">
                                <pre class="value-content json-value"><code class="language-json">${escapeHtml(JSON.stringify(log.response, null, 2))}</code></pre>
                            </div>
                        </div>
                    </div>
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
    if (bsModal) {
        bsModal.show();
    }
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
                    '#6366f1', '#8b5cf6', '#ec4899', '#f43f5e', '#f97316',
                    '#f59e0b', '#10b981', '#06b6d4', '#0ea5e9', '#3b82f6'
                ],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            animation: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#64748b' }
                }
            }
        }
    });
}

async function deleteLog(logId) {
    if (!confirm('确定要删除这条日志吗？此操作无法撤销。')) return;
    
    try {
        await apiDelete(`/api/logs/${logId}`);
        
        // 从UI中移除
        const row = document.querySelector(`tr[data-id="${logId}"]`);
        if (row) {
            row.remove();
        }
        
        // 更新状态
        state.logs = state.logs.filter(l => l.id !== logId);
        
        showNotification('成功', '日志已删除');
        
        // Reload current view
        if (state.currentView === 'logs') loadLogs();
        else if (state.currentView === 'dashboard') loadDashboard();
        
    } catch (error) {
        console.error('Failed to delete log:', error);
        showError('删除日志失败');
    }
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

// Expose functions to global scope for inline event handlers
window.viewLog = viewLog;
window.deleteLog = deleteLog;
window.toggleLogStar = toggleLogStar;
window.toggleMessageCard = toggleMessageCard;

// 启动应用
document.addEventListener('DOMContentLoaded', () => {
    init();
    bindToolCallEvents();
});
