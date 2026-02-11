/**
 * IVAgent 漏洞管理平台 JavaScript
 * 现代化、流畅的交互体验
 */

// ============================================
// 全局状态
// ============================================
const state = {
    vulnerabilities: [],
    currentPage: 1,
    totalPages: 1,
    pageSize: 20,
    total: 0,
    filters: {
        severity: [],
        status: '',
        type: '',
        search: ''
    },
    stats: null,
    currentVulnId: null,
    charts: {}
};

// Bootstrap Modal 实例
let bsVulnModal = null;

// ============================================
// API 封装
// ============================================
const api = {
    async getVulnerabilities(params = {}) {
        const query = new URLSearchParams();
        if (params.severity) query.set('severity', params.severity);
        if (params.status) query.set('status', params.status);
        if (params.type) query.set('vuln_type', params.type);
        if (params.search) query.set('search', params.search);
        if (params.limit) query.set('limit', params.limit);
        if (params.offset !== undefined) query.set('offset', params.offset);
        
        const response = await fetch(`/api/vulnerabilities?${query}`);
        if (!response.ok) throw new Error('Failed to fetch vulnerabilities');
        return response.json();
    },
    
    async getVulnerabilityStats() {
        const response = await fetch('/api/vulnerabilities/stats');
        if (!response.ok) throw new Error('Failed to fetch stats');
        return response.json();
    },
    
    async getVulnerabilityTypes() {
        const response = await fetch('/api/vulnerabilities/types/all');
        if (!response.ok) throw new Error('Failed to fetch types');
        return response.json();
    },
    
    async getVulnerabilityDetail(vulnId) {
        const response = await fetch(`/api/vulnerabilities/${vulnId}`);
        if (!response.ok) throw new Error('Failed to fetch vulnerability detail');
        return response.json();
    },
    
    async updateVulnerability(vulnId, data) {
        const response = await fetch(`/api/vulnerabilities/${vulnId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        if (!response.ok) throw new Error('Failed to update vulnerability');
        return response.json();
    },
    
    async deleteVulnerability(vulnId) {
        const response = await fetch(`/api/vulnerabilities/${vulnId}`, {
            method: 'DELETE'
        });
        if (!response.ok) throw new Error('Failed to delete vulnerability');
        return response.json();
    },
    
    async clearAllVulnerabilities() {
        const response = await fetch('/api/vulnerabilities', {
            method: 'DELETE'
        });
        if (!response.ok) throw new Error('Failed to clear all vulnerabilities');
        return response.json();
    }
};

// ============================================
// UI 工具函数
// ============================================
const ui = {
    // 显示 Toast 提示
    toast(message, type = 'info', title = '') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icons = {
            success: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>',
            error: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>',
            info: '<svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>'
        };
        
        toast.innerHTML = `
            ${icons[type]}
            <div class="toast-content">
                ${title ? `<div class="toast-title">${title}</div>` : ''}
                <div class="toast-message">${message}</div>
            </div>
        `;
        
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    },
    
    // 显示加载状态
    showLoading(container) {
        container.innerHTML = `
            <div class="loading-spinner">
                <div class="spinner"></div>
            </div>
        `;
    },
    
    // 显示空状态
    showEmpty(container) {
        container.innerHTML = `
            <div class="empty-state">
                <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    <path d="M9 12l2 2 4-4"></path>
                </svg>
                <div class="empty-title">暂无漏洞数据</div>
                <div class="empty-desc">开始扫描以发现潜在的安全漏洞</div>
            </div>
        `;
    },
    
    // 格式化时间
    formatTime(isoString) {
        if (!isoString) return '-';
        const date = new Date(isoString);
        return date.toLocaleString('zh-CN', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit'
        });
    },
    
    // 获取严重程度颜色
    getSeverityColor(severity) {
        const colors = {
            critical: '#dc2626',
            high: '#ea580c',
            medium: '#d97706',
            low: '#16a34a',
            info: '#6b7280'
        };
        return colors[severity] || colors.info;
    },
    
    // 获取严重程度显示文本
    getSeverityText(severity) {
        const texts = {
            critical: '严重',
            high: '高危',
            medium: '中危',
            low: '低危',
            info: '信息'
        };
        return texts[severity] || severity;
    },
    
    // 获取状态显示文本
    getStatusText(status) {
        const texts = {
            new: '新发现',
            confirmed: '已确认',
            false_positive: '误报',
            fixed: '已修复',
            ignored: '已忽略'
        };
        return texts[status] || status;
    }
};

// ============================================
// 图表渲染
// ============================================
const charts = {
    // 渲染严重程度分布图
    renderSeverityChart(stats) {
        const ctx = document.getElementById('severity-chart');
        if (!ctx) return;
        
        if (state.charts.severity) {
            state.charts.severity.destroy();
        }
        
        const data = stats.by_severity || {};
        const labels = ['严重', '高危', '中危', '低危', '信息'];
        const keys = ['critical', 'high', 'medium', 'low', 'info'];
        const values = keys.map(k => data[k] || 0);
        const colors = ['#ef4444', '#f97316', '#f59e0b', '#10b981', '#94a3b8'];
        
        state.charts.severity = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: colors,
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#64748b',
                            padding: 16,
                            usePointStyle: true,
                            pointStyle: 'circle'
                        }
                    }
                },
                cutout: '70%'
            }
        });
    },
    
    // 渲染趋势图
    renderTrendChart(stats) {
        const ctx = document.getElementById('trend-chart');
        if (!ctx) return;
        
        if (state.charts.trend) {
            state.charts.trend.destroy();
        }
        
        const dailyData = stats.by_day || [];
        const labels = dailyData.map(d => d.date.slice(5)); // 只显示月-日
        const values = dailyData.map(d => d.count);
        
        const context = ctx.getContext('2d');
        const gradient = context.createLinearGradient(0, 0, 0, 300);
        gradient.addColorStop(0, 'rgba(99, 102, 241, 0.25)');
        gradient.addColorStop(1, 'rgba(99, 102, 241, 0)');

        state.charts.trend = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: '漏洞数量',
                    data: values,
                    borderColor: '#6366f1',
                    backgroundColor: gradient,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointBackgroundColor: '#ffffff',
                    pointBorderColor: '#6366f1',
                    pointBorderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    x: {
                        grid: {
                            color: '#e2e8f0',
                            display: false
                        },
                        ticks: {
                            color: '#64748b'
                        }
                    },
                    y: {
                        grid: {
                            color: '#e2e8f0'
                        },
                        ticks: {
                            color: '#64748b'
                        }
                    }
                }
            }
        });
    }
};

// ============================================
// 漏洞列表渲染
// ============================================
const vulnList = {
    // 已查看的漏洞ID集合
    viewedVulns: new Set(),
    
    // 渲染漏洞卡片
    renderCard(vuln) {
        const severityText = ui.getSeverityText(vuln.severity);
        const statusText = ui.getStatusText(vuln.status);
        const createdTime = ui.formatTime(vuln.created_at);
        const isViewed = this.viewedVulns.has(vuln.vuln_id);
        const viewedClass = isViewed ? 'viewed' : '';
        
        return `
            <div class="vuln-card ${viewedClass}" data-id="${vuln.vuln_id}">
                <div class="vuln-severity">
                    <div class="severity-indicator ${vuln.severity}"></div>
                    <span class="severity-text ${vuln.severity}">${severityText}</span>
                </div>
                <div class="vuln-content">
                    <div class="vuln-title">${this.escapeHtml(vuln.name)}</div>
                    <div class="vuln-meta">
                        <span class="vuln-function" title="${this.escapeHtml(vuln.function_identifier)}">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"></path>
                                <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"></path>
                            </svg>
                            ${this.escapeHtml(vuln.function_identifier)}
                        </span>
                        <span class="vuln-location" title="${this.escapeHtml(vuln.location)}">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path>
                                <circle cx="12" cy="10" r="3"></circle>
                            </svg>
                            ${this.escapeHtml(vuln.location)}
                        </span>
                        <span class="vuln-time">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"></circle>
                                <polyline points="12 6 12 12 16 14"></polyline>
                            </svg>
                            ${createdTime}
                        </span>
                    </div>
                    <div class="vuln-description">${this.escapeHtml(vuln.description)}</div>
                    <div class="vuln-tags">
                        <span class="tag type">${this.escapeHtml(vuln.type)}</span>
                        ${vuln.confidence >= 0.8 ? '<span class="tag">高置信度</span>' : ''}
                    </div>
                </div>
                <div class="vuln-status">
                    <span class="status-badge ${vuln.status}">${statusText}</span>
                </div>
            </div>
        `;
    },
    
    // 转义 HTML
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },
    
    // 渲染漏洞列表
    async render() {
        const container = document.getElementById('vuln-list');
        
        try {
            ui.showLoading(container);
            
            const offset = (state.currentPage - 1) * state.pageSize;
            const result = await api.getVulnerabilities({
                ...state.filters,
                limit: state.pageSize,
                offset: offset
            });
            
            state.vulnerabilities = result.items;
            state.total = result.total;
            state.totalPages = Math.ceil(state.total / state.pageSize);
            
            if (state.vulnerabilities.length === 0) {
                ui.showEmpty(container);
                this.updatePagination();
                return;
            }
            
            container.innerHTML = state.vulnerabilities.map(v => this.renderCard(v)).join('');
            
            // 绑定双击事件
            container.querySelectorAll('.vuln-card').forEach(card => {
                card.addEventListener('dblclick', () => {
                    const vulnId = card.dataset.id;
                    // 标记为已查看
                    vulnList.viewedVulns.add(vulnId);
                    card.classList.add('viewed');
                    vulnDetail.show(vulnId);
                });
            });
            
            this.updatePagination();
            document.getElementById('vuln-count').textContent = `共 ${state.total} 个漏洞`;
            
        } catch (error) {
            ui.toast('加载漏洞列表失败: ' + error.message, 'error');
            container.innerHTML = '<div class="empty-state"><div class="empty-title">加载失败</div></div>';
        }
    },
    
    // 更新分页
    updatePagination() {
        document.getElementById('page-info').textContent = `${state.currentPage} / ${Math.max(1, state.totalPages)}`;
        document.getElementById('prev-page').disabled = state.currentPage <= 1;
        document.getElementById('next-page').disabled = state.currentPage >= state.totalPages;
    },
    
    // 刷新列表
    async refresh() {
        state.currentPage = 1;
        await this.render();
    }
};

// ============================================
// 漏洞详情弹窗
// ============================================
const vulnDetail = {
    // 初始化 Bootstrap Modal
    init() {
        const modalEl = document.getElementById('vuln-modal');
        if (modalEl && typeof bootstrap !== 'undefined' && bootstrap.Modal) {
            bsVulnModal = new bootstrap.Modal(modalEl);
        }
    },
    
    // 显示漏洞详情
    async show(vulnId) {
        state.currentVulnId = vulnId;
        
        try {
            const vuln = await api.getVulnerabilityDetail(vulnId);
            this.render(vuln);
            if (bsVulnModal) {
                bsVulnModal.show();
            } else {
                // Fallback: 手动显示
                const modal = document.getElementById('vuln-modal');
                if (modal) modal.classList.add('show');
            }
        } catch (error) {
            ui.toast('加载漏洞详情失败: ' + error.message, 'error');
        }
    },
    
    // 渲染详情
    render(vuln) {
        // 严重程度
        const severityEl = document.getElementById('modal-severity');
        severityEl.className = `severity-badge ${vuln.severity}`;
        severityEl.textContent = ui.getSeverityText(vuln.severity);
        
        // 标题和描述
        document.getElementById('modal-title').textContent = vuln.name;
        document.getElementById('modal-description').textContent = vuln.description;

        // 调用路径
        const callPathEl = document.getElementById('modal-call-path');
        const callPath = vuln.metadata && vuln.metadata.call_path ? vuln.metadata.call_path : null;
        if (callPath) {
            callPathEl.innerHTML = callPath.replace(/\n/g, '<br>');
        } else {
            callPathEl.innerHTML = '<span style="color: var(--text-secondary);">暂无调用路径信息</span>';
        }

        // 数据流
        this.renderDataFlow(vuln.data_flow);
        
        // 代码片段
        const codeSection = document.getElementById('code-section');
        if (vuln.code_snippet) {
            codeSection.style.display = 'block';
            document.getElementById('modal-code').textContent = vuln.code_snippet;
            hljs.highlightElement(document.getElementById('modal-code'));
        } else {
            codeSection.style.display = 'none';
        }
        
        // 修复建议
        document.getElementById('modal-remediation').textContent = vuln.remediation || '暂无修复建议';
        
        // 基本信息
        document.getElementById('modal-type').textContent = vuln.type;
        document.getElementById('modal-confidence-text').textContent = `${Math.round(vuln.confidence * 100)}%`;
        document.getElementById('modal-confidence').style.width = `${vuln.confidence * 100}%`;
        
        // 状态下拉
        document.getElementById('modal-status-select').value = vuln.status;
        
        // 位置信息
        document.getElementById('modal-function').textContent = vuln.function_identifier;
        document.getElementById('modal-location').textContent = vuln.location;
        document.getElementById('modal-file').textContent = vuln.file_path || '-';
        
        // 分析信息
        document.getElementById('modal-agent').textContent = vuln.agent_id ? vuln.agent_id.slice(0, 8) : '-';
        document.getElementById('modal-time').textContent = ui.formatTime(vuln.created_at);
        
        // 调用栈
        const callStackEl = document.getElementById('modal-call-stack');
        if (vuln.call_stack && vuln.call_stack.length > 0) {
            callStackEl.innerHTML = vuln.call_stack.map(fn => 
                `<div class="stack-item">${fn}</div>`
            ).join('');
        } else {
            callStackEl.innerHTML = '<div class="stack-item">-</div>';
        }
        
        // 证据
        const evidenceEl = document.getElementById('modal-evidence');
        if (vuln.evidence && vuln.evidence.length > 0) {
            evidenceEl.innerHTML = vuln.evidence.map(e => `<li>${e}</li>`).join('');
        } else {
            evidenceEl.innerHTML = '<li>暂无证据</li>';
        }
    },
    
    // 渲染数据流
    renderDataFlow(dataFlow) {
        const container = document.getElementById('modal-data-flow');
        
        if (!dataFlow || (!dataFlow.source && !dataFlow.sink)) {
            container.innerHTML = '<p style="color: var(--text-secondary);">暂无数据流信息</p>';
            return;
        }
        
        let html = '';
        
        if (dataFlow.source) {
            html += `
                <div class="flow-node source">
                    <span class="flow-label">污点源</span>
                    <span class="flow-value">${dataFlow.source}</span>
                </div>
            `;
        }
        
        if (dataFlow.intermediate && dataFlow.intermediate.length > 0) {
            html += '<div class="flow-arrow">↓</div>';
            dataFlow.intermediate.forEach((node, i) => {
                html += `
                    <div class="flow-node">
                        <span class="flow-label">中间节点</span>
                        <span class="flow-value">${node}</span>
                    </div>
                `;
                if (i < dataFlow.intermediate.length - 1) {
                    html += '<div class="flow-arrow">↓</div>';
                }
            });
        }
        
        if (dataFlow.sink) {
            html += '<div class="flow-arrow">↓</div>';
            html += `
                <div class="flow-node sink">
                    <span class="flow-label">漏洞点</span>
                    <span class="flow-value">${dataFlow.sink}</span>
                </div>
            `;
        }
        
        container.innerHTML = html;
    },
    
    // 保存状态
    async saveStatus() {
        const newStatus = document.getElementById('modal-status-select').value;
        
        try {
            await api.updateVulnerability(state.currentVulnId, { status: newStatus });
            ui.toast('漏洞状态已更新', 'success');
            vulnList.refresh();
        } catch (error) {
            ui.toast('更新失败: ' + error.message, 'error');
        }
    },
    
    // 删除漏洞
    async delete() {
        if (!confirm('确定要删除这个漏洞吗？此操作不可恢复。')) {
            return;
        }
        
        try {
            await api.deleteVulnerability(state.currentVulnId);
            ui.toast('漏洞已删除', 'success');
            this.close();
            vulnList.refresh();
        } catch (error) {
            ui.toast('删除失败: ' + error.message, 'error');
        }
    },
    
    // 关闭弹窗
    close() {
        if (bsVulnModal) {
            bsVulnModal.hide();
        } else {
            // Fallback: 手动隐藏
            const modal = document.getElementById('vuln-modal');
            if (modal) modal.classList.remove('show');
        }
        state.currentVulnId = null;
    }
};

// ============================================
// 统计信息
// ============================================
const stats = {
    // 加载并显示统计
    async load() {
        try {
            state.stats = await api.getVulnerabilityStats();
            this.render();
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    },
    
    // 渲染统计
    render() {
        const s = state.stats;
        if (!s) return;
        
        // 严重程度统计
        const bySeverity = s.by_severity || {};
        document.getElementById('stat-critical').textContent = bySeverity.critical || 0;
        document.getElementById('stat-high').textContent = bySeverity.high || 0;
        document.getElementById('stat-medium').textContent = bySeverity.medium || 0;
        document.getElementById('stat-low').textContent = bySeverity.low || 0;
        document.getElementById('stat-total').textContent = s.total || 0;
        
        // 图表
        charts.renderSeverityChart(s);
        charts.renderTrendChart(s);
    }
};

// ============================================
// 漏洞类型
// ============================================
const vulnTypes = {
    async load() {
        try {
            const result = await api.getVulnerabilityTypes();
            const select = document.getElementById('filter-type');
            
            // 保留默认选项
            const defaultOption = select.querySelector('option[value=""]');
            select.innerHTML = '';
            select.appendChild(defaultOption);
            
            result.types.forEach(type => {
                const option = document.createElement('option');
                option.value = type;
                option.textContent = type;
                select.appendChild(option);
            });
        } catch (error) {
            console.error('Failed to load types:', error);
        }
    }
};

// ============================================
// 事件绑定
// ============================================
function bindEvents() {
    // 严重程度筛选
    const filterSeverity = document.getElementById('filter-severity');
    if (filterSeverity) {
        filterSeverity.addEventListener('change', (e) => {
            state.filters.severity = e.target.value ? [e.target.value] : [];
            vulnList.refresh();
        });
    }
    
    // 状态筛选
    const filterStatus = document.getElementById('filter-status');
    if (filterStatus) {
        filterStatus.addEventListener('change', (e) => {
            state.filters.status = e.target.value;
            vulnList.refresh();
        });
    }
    
    // 类型筛选
    const filterType = document.getElementById('filter-type');
    if (filterType) {
        filterType.addEventListener('change', (e) => {
            state.filters.type = e.target.value;
            vulnList.refresh();
        });
    }
    
    // 搜索
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                state.filters.search = e.target.value;
                vulnList.refresh();
            }
        });
        // 实时搜索（防抖）
        let searchTimeout;
        searchInput.addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                state.filters.search = e.target.value;
                vulnList.refresh();
            }, 500);
        });
    }
    
    // 分页
    const prevPage = document.getElementById('prev-page');
    const nextPage = document.getElementById('next-page');
    
    if (prevPage) {
        prevPage.addEventListener('click', () => {
            if (state.currentPage > 1) {
                state.currentPage--;
                vulnList.render();
            }
        });
    }
    
    if (nextPage) {
        nextPage.addEventListener('click', () => {
            if (state.currentPage < state.totalPages) {
                state.currentPage++;
                vulnList.render();
            }
        });
    }
    
    // 弹窗关闭 - 使用事件委托
    const modal = document.getElementById('vuln-modal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            // 点击弹窗背景关闭
            if (e.target === modal) {
                vulnDetail.close();
            }
            // 点击关闭按钮
            if (e.target.classList.contains('btn-close') || e.target.closest('.btn-close')) {
                vulnDetail.close();
            }
        });
    }
    
    // ESC 关闭弹窗
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            vulnDetail.close();
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
}

// ============================================
// 导出功能
// ============================================
async function exportData() {
    try {
        const result = await api.getVulnerabilities({
            ...state.filters,
            limit: 1000,
            offset: 0
        });
        
        const data = {
            export_time: new Date().toISOString(),
            total: result.total,
            vulnerabilities: result.items
        };
        
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `vulnerabilities_${new Date().toISOString().slice(0, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        ui.toast('漏洞数据已导出', 'success');
    } catch (error) {
        ui.toast('导出失败: ' + error.message, 'error');
    }
}

// ============================================
// 初始化
// ============================================
async function init() {
    // 初始化 Bootstrap Modal
    vulnDetail.init();
    
    bindEvents();
    
    // 并行加载数据
    await Promise.all([
        stats.load(),
        vulnTypes.load(),
        vulnList.render()
    ]);
    
    ui.toast('漏洞管理平台已加载', 'success');
}

// 页面加载完成后初始化
document.addEventListener('DOMContentLoaded', init);
