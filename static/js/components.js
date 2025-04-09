// static/js/components.js
// 规则管理组件
const RuleManagement = {
    data() {
        return {
            rules: [],
            loading: true,
            dialogVisible: false,
            dialogTitle: '创建规则',
            isEdit: false,
            form: {
                id: null,
                rule_type: 'iptables',
                chain: 'INPUT',
                protocol: 'all',
                source: 'any',
                destination: 'any',
                port: 'any',
                action: 'ACCEPT',
                comment: '',
                priority: 100,
                enabled: true
            },
            formRules: {
                chain: [{ required: true, message: '请输入链名称', trigger: 'blur' }],
                action: [{ required: true, message: '请选择动作', trigger: 'change' }]
            },
            chainOptions: [
                { value: 'INPUT', label: 'INPUT' },
                { value: 'OUTPUT', label: 'OUTPUT' },
                { value: 'FORWARD', label: 'FORWARD' }
            ],
            protocolOptions: [
                { value: 'all', label: '所有协议' },
                { value: 'tcp', label: 'TCP' },
                { value: 'udp', label: 'UDP' },
                { value: 'icmp', label: 'ICMP' }
            ],
            actionOptions: [
                { value: 'ACCEPT', label: '接受' },
                { value: 'DROP', label: '丢弃' },
                { value: 'REJECT', label: '拒绝' },
                { value: 'LOG', label: '记录' }
            ],
            importDialogVisible: false,
            importFile: null,
            syncLoading: false
        };
    },
    created() {
        this.fetchRules();
    },
    methods: {
        fetchRules() {
            this.loading = true;
            axios.get('/api/rules', {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                this.rules = response.data.data;
                this.loading = false;
            })
            .catch(error => {
                this.$message.error('获取规则失败: ' + error.response.data.message);
                this.loading = false;
            });
        },
        openDialog(isEdit, rule) {
            this.isEdit = isEdit;
            this.dialogTitle = isEdit ? '编辑规则' : '创建规则';

            if (isEdit && rule) {
                // 编辑模式，复制规则数据到表单
                this.form = Object.assign({}, rule);
            } else {
                // 创建模式，重置表单
                this.form = {
                    id: null,
                    rule_type: 'iptables',
                    chain: 'INPUT',
                    protocol: 'all',
                    source: 'any',
                    destination: 'any',
                    port: 'any',
                    action: 'ACCEPT',
                    comment: '',
                    priority: 100,
                    enabled: true
                };
            }

            this.dialogVisible = true;
        },
        submitForm() {
            this.$refs.form.validate(valid => {
                if (valid) {
                    if (this.isEdit) {
                        // 更新规则
                        axios.put(`/api/rules/${this.form.id}`, this.form, {
                            headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
                        })
                        .then(response => {
                            this.$message.success('规则更新成功');
                            this.dialogVisible = false;
                            this.fetchRules();
                        })
                        .catch(error => {
                            this.$message.error('规则更新失败: ' + error.response.data.message);
                        });
                    } else {
                        // 创建规则
                        axios.post('/api/rules', this.form, {
                            headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
                        })
                        .then(response => {
                            this.$message.success('规则创建成功');
                            this.dialogVisible = false;
                            this.fetchRules();
                        })
                        .catch(error => {
                            this.$message.error('规则创建失败: ' + error.response.data.message);
                        });
                    }
                }
            });
        },
        deleteRule(rule) {
            this.$confirm('此操作将永久删除该规则, 是否继续?', '提示', {
                confirmButtonText: '确定',
                cancelButtonText: '取消',
                type: 'warning'
            }).then(() => {
                axios.delete(`/api/rules/${rule.id}`, {
                    headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
                })
                .then(response => {
                    this.$message.success('规则删除成功');
                    this.fetchRules();
                })
                .catch(error => {
                    this.$message.error('规则删除失败: ' + error.response.data.message);
                });
            }).catch(() => {
                this.$message.info('已取消删除');
            });
        },
        toggleRuleStatus(rule) {
            const updatedRule = Object.assign({}, rule, { enabled: !rule.enabled });

            axios.put(`/api/rules/${rule.id}`, updatedRule, {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                this.$message.success(`规则已${updatedRule.enabled ? '启用' : '禁用'}`);
                this.fetchRules();
            })
            .catch(error => {
                this.$message.error('操作失败: ' + error.response.data.message);
            });
        },
        verifyRule(rule) {
            axios.post(`/api/status/verify/${rule.id}`, {}, {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                const result = response.data.data;
                if (result.effective) {
                    this.$message.success('规则验证成功: ' + result.message);
                } else {
                    this.$message.warning('规则验证失败: ' + result.message);
                }
            })
            .catch(error => {
                this.$message.error('验证失败: ' + error.response.data.message);
            });
        },
        handleImportSuccess() {
            this.importDialogVisible = false;
            this.fetchRules();
        },
        exportRules() {
            axios.get('/api/rules/export', {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                // 创建下载链接
                const data = JSON.stringify(response.data.data, null, 2);
                const blob = new Blob([data], { type: 'application/json' });
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'firewall_rules_' + new Date().toISOString().slice(0, 10) + '.json';
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            })
            .catch(error => {
                this.$message.error('导出失败: ' + error.response.data.message);
            });
        },
        handleFileChange(file) {
            this.importFile = file.raw;
        },
        submitImport() {
            if (!this.importFile) {
                this.$message.warning('请选择要导入的文件');
                return;
            }

            const formData = new FormData();
            formData.append('file', this.importFile);

            axios.post('/api/rules/import', formData, {
                headers: {
                    'Authorization': 'Bearer ' + localStorage.getItem('token'),
                    'Content-Type': 'multipart/form-data'
                }
            })
            .then(response => {
                this.$message.success('规则导入成功: ' + response.data.message);
                this.importDialogVisible = false;
                this.fetchRules();
            })
            .catch(error => {
                this.$message.error('导入失败: ' + error.response.data.message);
            });
        },
        syncRules() {
            this.syncLoading = true;

            axios.post('/api/rules/sync', {}, {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                this.$message.success('规则同步成功: ' + response.data.message);
                this.fetchRules();
                this.syncLoading = false;
            })
            .catch(error => {
                this.$message.error('同步失败: ' + error.response.data.message);
                this.syncLoading = false;
            });
        }
    },
    template: `
        <div>
            <el-card class="card-container">
                <div slot="header">
                    <span>防火墙规则管理</span>
                </div>
                
                <div class="table-operations">
                    <el-button type="primary" @click="openDialog(false)">创建规则</el-button>
                    <el-button @click="importDialogVisible = true">导入规则</el-button>
                    <el-button @click="exportRules">导出规则</el-button>
                    <el-button :loading="syncLoading" @click="syncRules">同步服务器规则</el-button>
                </div>
                
                <el-table :data="rules" v-loading="loading" border style="width: 100%">
                    <el-table-column prop="id" label="ID" width="60"></el-table-column>
                    <el-table-column prop="rule_type" label="类型" width="100">
                        <template slot-scope="scope">
                            <el-tag size="small" :type="scope.row.rule_type === 'iptables' ? 'primary' : 'success'">
                                {{ scope.row.rule_type }}
                            </el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column prop="chain" label="链" width="100"></el-table-column>
                    <el-table-column prop="protocol" label="协议" width="80"></el-table-column>
                    <el-table-column prop="source" label="源地址"></el-table-column>
                    <el-table-column prop="destination" label="目标地址"></el-table-column>
                    <el-table-column prop="port" label="端口" width="100"></el-table-column>
                    <el-table-column prop="action" label="动作" width="100">
                        <template slot-scope="scope">
                            <el-tag size="small" :type="getActionType(scope.row.action)">
                                {{ scope.row.action }}
                            </el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column prop="enabled" label="状态" width="80">
                        <template slot-scope="scope">
                            <el-switch
                                v-model="scope.row.enabled"
                                @change="toggleRuleStatus(scope.row)"
                                active-color="#13ce66"
                                inactive-color="#ff4949">
                            </el-switch>
                        </template>
                    </el-table-column>
                    <el-table-column label="操作" width="200">
                        <template slot-scope="scope">
                            <el-button size="mini" @click="openDialog(true, scope.row)">编辑</el-button>
                            <el-button size="mini" type="danger" @click="deleteRule(scope.row)">删除</el-button>
                            <el-button size="mini" type="info" @click="verifyRule(scope.row)">验证</el-button>
                        </template>
                    </el-table-column>
                </el-table>
            </el-card>
            
            <!-- 规则表单对话框 -->
            <el-dialog :title="dialogTitle" :visible.sync="dialogVisible" width="600px">
                <el-form :model="form" :rules="formRules" ref="form" label-width="100px" class="rule-form">
                    <el-form-item label="规则类型">
                        <el-radio-group v-model="form.rule_type">
                            <el-radio label="iptables">iptables</el-radio>
                            <el-radio label="nftables">nftables</el-radio>
                        </el-radio-group>
                    </el-form-item>
                    
                    <el-form-item label="链" prop="chain">
                        <el-select v-model="form.chain" placeholder="请选择链">
                            <el-option v-for="item in chainOptions" :key="item.value" :label="item.label" :value="item.value"></el-option>
                            <el-option value="custom" label="自定义"></el-option>
                        </el-select>
                        <el-input v-if="form.chain === 'custom'" v-model="form.customChain" placeholder="请输入自定义链名称" style="margin-top: 10px;"></el-input>
                    </el-form-item>
                    
                    <el-form-item label="协议">
                        <el-select v-model="form.protocol" placeholder="请选择协议">
                            <el-option v-for="item in protocolOptions" :key="item.value" :label="item.label" :value="item.value"></el-option>
                        </el-select>
                    </el-form-item>
                    
                    <el-form-item label="源地址">
                        <el-input v-model="form.source" placeholder="IP地址、网段或'any'"></el-input>
                    </el-form-item>
                    
                    <el-form-item label="目标地址">
                        <el-input v-model="form.destination" placeholder="IP地址、网段或'any'"></el-input>
                    </el-form-item>
                    
                    <el-form-item label="端口">
                        <el-input v-model="form.port" placeholder="端口号、范围或'any'"></el-input>
                    </el-form-item>
                    
                    <el-form-item label="动作" prop="action">
                        <el-select v-model="form.action" placeholder="请选择动作">
                            <el-option v-for="item in actionOptions" :key="item.value" :label="item.label" :value="item.value"></el-option>
                        </el-select>
                    </el-form-item>
                    
                    <el-form-item label="注释">
                        <el-input v-model="form.comment" type="textarea" :rows="2" placeholder="规则说明"></el-input>
                    </el-form-item>
                    
                    <el-form-item label="优先级">
                        <el-input-number v-model="form.priority" :min="1" :max="1000"></el-input-number>
                    </el-form-item>
                    
                    <el-form-item label="启用状态">
                        <el-switch v-model="form.enabled"></el-switch>
                    </el-form-item>
                </el-form>
                <span slot="footer" class="dialog-footer">
                    <el-button @click="dialogVisible = false">取消</el-button>
                    <el-button type="primary" @click="submitForm">确定</el-button>
                </span>
            </el-dialog>
            
            <!-- 导入规则对话框 -->
            <el-dialog title="导入规则" :visible.sync="importDialogVisible" width="400px">
                <el-upload
                    class="upload-demo"
                    drag
                    action="#"
                    :auto-upload="false"
                    :on-change="handleFileChange"
                    :limit="1">
                    <i class="el-icon-upload"></i>
                    <div class="el-upload__text">将文件拖到此处，或<em>点击上传</em></div>
                    <div class="el-upload__tip" slot="tip">只能上传JSON文件</div>
                </el-upload>
                <span slot="footer" class="dialog-footer">
                    <el-button @click="importDialogVisible = false">取消</el-button>
                    <el-button type="primary" @click="submitImport">导入</el-button>
                </span>
            </el-dialog>
        </div>
    `,
    methods: {
        getActionType(action) {
            switch (action) {
                case 'ACCEPT': return 'success';
                case 'DROP': return 'danger';
                case 'REJECT': return 'warning';
                case 'LOG': return 'info';
                default: return '';
            }
        }
    }
};

// 状态监控组件
const StatusMonitor = {
    data() {
        return {
            status: {
                iptables: { status: false, last_checked: null },
                nftables: { status: false, last_checked: null }
            },
            connectionStats: null,
            connectionHistory: [],
            loading: true,
            timeRange: '1h',
            charts: {
                connections: null,
                states: null
            },
            controlDialogVisible: false,
            controlForm: {
                service: 'iptables',
                action: 'restart'
            },
            controlLoading: false
        };
    },
    created() {
        this.fetchStatus();
        this.fetchConnectionStats();
        this.initSocket();
    },
    mounted() {
        this.$nextTick(() => {
            this.initCharts();
        });
    },
    beforeDestroy() {
        // 清理Socket连接
        if (this.socket) {
            this.socket.disconnect();
        }

        // 清理图表实例
        if (this.charts.connections) {
            this.charts.connections.destroy();
        }
        if (this.charts.states) {
            this.charts.states.destroy();
        }
    },
    methods: {
        fetchStatus() {
            axios.get('/api/status', {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                this.status = response.data.data;
                this.loading = false;
            })
            .catch(error => {
                this.$message.error('获取状态失败: ' + error.response.data.message);
                this.loading = false;
            });
        },
        fetchConnectionStats() {
            axios.get(`/api/status/connections?time_range=${this.timeRange}`, {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                this.connectionHistory = response.data.data;
                this.connectionStats = this.connectionHistory.length > 0 ?
                    this.connectionHistory[this.connectionHistory.length - 1] : null;
                this.updateCharts();
            })
            .catch(error => {
                this.$message.error('获取连接统计失败: ' + error.response.data.message);
            });
        },
        initSocket() {
            // 初始化Socket.IO连接
            this.socket = io();

            // 监听状态更新
            this.socket.on('status_update', (data) => {
                if (data.iptables) {
                    this.status.iptables = data.iptables;
                }
                if (data.nftables) {
                    this.status.nftables = data.nftables;
                }
            });

            // 监听连接统计更新
            this.socket.on('connection_update', (data) => {
                this.connectionStats = data;
                this.connectionHistory.push(data);

                // 保持历史记录不超过100条
                if (this.connectionHistory.length > 100) {
                    this.connectionHistory.shift();
                }

                this.updateCharts();
            });
        },
        initCharts() {
            // 初始化连接总数图表
            const connectionsCtx = document.getElementById('connectionsChart');
            if (connectionsCtx) {
                this.charts.connections = new Chart(connectionsCtx, {
                    type: 'line',
                    data: {
                        labels: [],
                        datasets: [{
                            label: '总连接数',
                            data: [],
                            borderColor: '#409EFF',
                            backgroundColor: 'rgba(64, 158, 255, 0.1)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            }

            // 初始化连接状态图表
            const statesCtx = document.getElementById('statesChart');
            if (statesCtx) {
                this.charts.states = new Chart(statesCtx, {
                    type: 'bar',
                    data: {
                        labels: ['已建立', '等待关闭', '关闭等待', 'SYN已发送', 'UDP连接'],
                        datasets: [{
                            label: '连接状态统计',
                            data: [0, 0, 0, 0, 0],
                            backgroundColor: [
                                'rgba(64, 158, 255, 0.6)',
                                'rgba(103, 194, 58, 0.6)',
                                'rgba(230, 162, 60, 0.6)',
                                'rgba(245, 108, 108, 0.6)',
                                'rgba(144, 147, 153, 0.6)'
                            ],
                            borderColor: [
                                '#409EFF',
                                '#67C23A',
                                '#E6A23C',
                                '#F56C6C',
                                '#909399'
                            ],
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            }

            // 初始化后更新图表
            this.updateCharts();
        },
        updateCharts() {
            if (!this.charts.connections || !this.charts.states || !this.connectionHistory.length) {
                return;
            }

            // 更新连接总数图表
            const labels = this.connectionHistory.map(stat => {
                const date = new Date(stat.timestamp);
                return date.toLocaleTimeString();
            });

            const data = this.connectionHistory.map(stat => stat.total_connections);

            this.charts.connections.data.labels = labels;
            this.charts.connections.data.datasets[0].data = data;
            this.charts.connections.update();

            // 更新连接状态图表
            if (this.connectionStats) {
                this.charts.states.data.datasets[0].data = [
                    this.connectionStats.established,
                    this.connectionStats.time_wait,
                    this.connectionStats.close_wait,
                    this.connectionStats.syn_sent,
                    this.connectionStats.udp_connections
                ];
                this.charts.states.update();
            }
        },
        changeTimeRange() {
            this.fetchConnectionStats();
        },
        refreshData() {
            this.fetchStatus();
            this.fetchConnectionStats();
        },
        formatTime(timestamp) {
            if (!timestamp) return '未知';
            const date = new Date(timestamp);
            return date.toLocaleString();
        },
        openControlDialog() {
            this.controlDialogVisible = true;
        },
        submitControl() {
            this.controlLoading = true;

            axios.post('/api/status/control', this.controlForm, {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                this.$message.success(response.data.message);
                this.controlDialogVisible = false;
                this.controlLoading = false;
                this.fetchStatus();
            })
            .catch(error => {
                this.$message.error('操作失败: ' + error.response.data.message);
                this.controlLoading = false;
            });
        }
    },
    template: `
        <div>
            <el-row :gutter="20">
                <el-col :span="12">
                    <el-card class="card-container" v-loading="loading">
                        <div slot="header">
                            <span>防火墙服务状态</span>
                            <el-button style="float: right; padding: 3px 0" type="text" @click="refreshData">刷新</el-button>
                        </div>
                        <div>
                            <el-tag class="status-tag" :type="status.iptables.status ? 'success' : 'danger'">
                                iptables: {{ status.iptables.status ? '运行中' : '已停止' }}
                            </el-tag>
                            <div style="font-size: 12px; color: #909399; margin: 5px 0 15px 0;">
                                最后检查: {{ formatTime(status.iptables.last_checked) }}
                            </div>
                            
                            <el-tag class="status-tag" :type="status.nftables.status ? 'success' : 'danger'">
                                nftables: {{ status.nftables.status ? '运行中' : '已停止' }}
                            </el-tag>
                            <div style="font-size: 12px; color: #909399; margin: 5px 0 15px 0;">
                                最后检查: {{ formatTime(status.nftables.last_checked) }}
                            </div>
                            
                            <el-button type="primary" @click="openControlDialog">防火墙控制</el-button>
                        </div>
                    </el-card>
                </el-col>
                
                <el-col :span="12">
                    <el-card class="card-container">
                        <div slot="header">
                            <span>连接跟踪统计</span>
                        </div>
                        <div v-if="connectionStats">
                            <div style="margin-bottom: 10px;">
                                <span style="font-weight: bold;">总连接数:</span> {{ connectionStats.total_connections }}
                            </div>
                            <el-row :gutter="10">
                                <el-col :span="8">
                                    <div class="stat-item">
                                        <div class="stat-label">已建立连接</div>
                                        <div class="stat-value">{{ connectionStats.established }}</div>
                                    </div>
                                </el-col>
                                <el-col :span="8">
                                    <div class="stat-item">
                                        <div class="stat-label">等待关闭</div>
                                        <div class="stat-value">{{ connectionStats.time_wait }}</div>
                                    </div>
                                </el-col>
                                <el-col :span="8">
                                    <div class="stat-item">
                                        <div class="stat-label">UDP连接</div>
                                        <div class="stat-value">{{ connectionStats.udp_connections }}</div>
                                    </div>
                                </el-col>
                            </el-row>
                            <div style="font-size: 12px; color: #909399; margin-top: 10px;">
                                最后更新: {{ formatTime(connectionStats.timestamp) }}
                            </div>
                        </div>
                        <div v-else>
                            <el-empty description="暂无连接统计数据"></el-empty>
                        </div>
                    </el-card>
                </el-col>
            </el-row>
            
            <el-card class="chart-container">
                <div slot="header">
                    <span>连接历史趋势</span>
                    <el-select v-model="timeRange" size="small" style="float: right; width: 120px;" @change="changeTimeRange">
                        <el-option label="最近1小时" value="1h"></el-option>
                        <el-option label="最近6小时" value="6h"></el-option>
                        <el-option label="最近24小时" value="24h"></el-option>
                        <el-option label="最近7天" value="7d"></el-option>
                    </el-select>
                </div>
                <div style="height: 300px;">
                    <canvas id="connectionsChart"></canvas>
                </div>
            </el-card>
            
            <el-card class="chart-container">
                <div slot="header">
                    <span>连接状态分布</span>
                </div>
                <div style="height: 300px;">
                    <canvas id="statesChart"></canvas>
                </div>
            </el-card>
            
            <!-- 防火墙控制对话框 -->
            <el-dialog title="防火墙服务控制" :visible.sync="controlDialogVisible" width="400px">
                <el-form :model="controlForm" label-width="100px">
                    <el-form-item label="服务">
                        <el-select v-model="controlForm.service" placeholder="请选择服务">
                            <el-option label="iptables" value="iptables"></el-option>
                            <el-option label="nftables" value="nftables"></el-option>
                        </el-select>
                    </el-form-item>
                    <el-form-item label="操作">
                        <el-select v-model="controlForm.action" placeholder="请选择操作">
                            <el-option label="启动" value="start"></el-option>
                            <el-option label="停止" value="stop"></el-option>
                            <el-option label="重启" value="restart"></el-option>
                        </el-select>
                    </el-form-item>
                </el-form>
                <span slot="footer" class="dialog-footer">
                    <el-button @click="controlDialogVisible = false">取消</el-button>
                    <el-button type="primary" @click="submitControl" :loading="controlLoading">确定</el-button>
                </span>
            </el-dialog>
        </div>
    `
};

// 日志分析组件
const LogAnalysis = {
    data() {
        return {
            logs: [],
            loading: true,
            pagination: {
                currentPage: 1,
                pageSize: 50,
                total: 0
            },
            filter: {
                source_ip: '',
                destination_ip: '',
                action: '',
                protocol: '',
                start_date: '',
                end_date: ''
            },
            analysisType: 'traffic',
            timeRange: '24h',
            analysisData: null,
            analysisLoading: false,
            anomalies: [],
            anomalyLoading: false,
            collectLoading: false,
            alertDialogVisible: false,
            alertForm: {
                name: '',
                description: '',
                condition_type: 'rate_limit',
                condition_value: '100',
                action: 'log',
                action_config: '{}',
                enabled: true
            },
            alerts: [],
            alertsLoading: false
        };
    },
    created() {
        this.fetchLogs();
        this.fetchAlerts();
    },
    mounted() {
        this.$nextTick(() => {
            this.loadAnalysisData();
        });
    },
    methods: {
        fetchLogs() {
            this.loading = true;

            // 构建查询参数
            const params = {
                page: this.pagination.currentPage,
                per_page: this.pagination.pageSize,
                ...this.filter
            };

            axios.get('/api/logs', {
                params: params,
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                this.logs = response.data.data;
                this.pagination.total = response.data.pagination.total;
                this.loading = false;
            })
            .catch(error => {
                this.$message.error('获取日志失败: ' + error.response.data.message);
                this.loading = false;
            });
        },
        handlePageChange(page) {
            this.pagination.currentPage = page;
            this.fetchLogs();
        },
        handleFilter() {
            this.pagination.currentPage = 1;
            this.fetchLogs();
        },
        resetFilter() {
            this.filter = {
                source_ip: '',
                destination_ip: '',
                action: '',
                protocol: '',
                start_date: '',
                end_date: ''
            };
            this.handleFilter();
        },
        loadAnalysisData() {
            this.analysisLoading = true;

            axios.get(`/api/logs/analysis?type=${this.analysisType}&time_range=${this.timeRange}`, {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                this.analysisData = response.data.data;
                this.analysisLoading = false;
                this.$nextTick(() => {
                    this.renderAnalysisCharts();
                });
            })
            .catch(error => {
                this.$message.error('获取分析数据失败: ' + error.response.data.message);
                this.analysisLoading = false;
            });
        },
        renderAnalysisCharts() {
            if (!this.analysisData) return;

            // 渲染协议统计图表
            if (this.analysisType === 'traffic' && document.getElementById('protocolChart')) {
                const protocolCtx = document.getElementById('protocolChart');
                const protocolData = this.analysisData.protocol_stats;

                if (this.protocolChart) {
                    this.protocolChart.destroy();
                }

                this.protocolChart = new Chart(protocolCtx, {
                    type: 'pie',
                    data: {
                        labels: Object.keys(protocolData),
                        datasets: [{
                            data: Object.values(protocolData),
                            backgroundColor: [
                                '#409EFF',
                                '#67C23A',
                                '#E6A23C',
                                '#F56C6C',
                                '#909399',
                                '#B9D3EE',
                                '#8FBC8F',
                                '#FFA500'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'right'
                            }
                        }
                    }
                });
            }

            // 渲染时间统计图表
            if (this.analysisType === 'traffic' && document.getElementById('timeChart')) {
                const timeCtx = document.getElementById('timeChart');
                const timeData = this.analysisData.time_stats;

                if (this.timeChart) {
                    this.timeChart.destroy();
                }

                this.timeChart = new Chart(timeCtx, {
                    type: 'line',
                    data: {
                        labels: Object.keys(timeData).map(time => {
                            const date = new Date(time);
                            return date.toLocaleTimeString();
                        }),
                        datasets: [{
                            label: '日志数量',
                            data: Object.values(timeData),
                            borderColor: '#409EFF',
                            backgroundColor: 'rgba(64, 158, 255, 0.1)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true
                            }
                        }
                    }
                });
            }
        },
        loadAnomalies() {
            this.anomalyLoading = true;

            axios.get(`/api/logs/analysis?type=anomalies&time_range=${this.timeRange}`, {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                this.anomalies = response.data.data;
                this.anomalyLoading = false;
            })
            .catch(error => {
                this.$message.error('获取异常数据失败: ' + error.response.data.message);
                this.anomalyLoading = false;
            });
        },
        collectLogs() {
            this.collectLoading = true;

            axios.post('/api/logs/collect', {}, {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                this.$message.success(response.data.message);
                this.collectLoading = false;
                this.fetchLogs();
            })
            .catch(error => {
                this.$message.error('收集日志失败: ' + error.response.data.message);
                this.collectLoading = false;
            });
        },
        formatTime(timestamp) {
            if (!timestamp) return '未知';
            const date = new Date(timestamp);
            return date.toLocaleString();
        },
        changeAnalysisType() {
            this.loadAnalysisData();
        },
        changeTimeRange() {
            this.loadAnalysisData();
            if (this.analysisType === 'anomalies') {
                this.loadAnomalies();
            }
        },
        fetchAlerts() {
            this.alertsLoading = true;

            axios.get('/api/logs/alerts', {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                this.alerts = response.data.data;
                this.alertsLoading = false;
            })
            .catch(error => {
                this.$message.error('获取告警配置失败: ' + error.response.data.message);
                this.alertsLoading = false;
            });
        },
        openAlertDialog(isEdit, alert) {
            this.isEdit = isEdit;

            if (isEdit && alert) {
                this.alertForm = Object.assign({}, alert);
            } else {
                this.alertForm = {
                    name: '',
                    description: '',
                    condition_type: 'rate_limit',
                    condition_value: '100',
                    action: 'log',
                    action_config: '{}',
                    enabled: true
                };
            }

            this.alertDialogVisible = true;
        },
        submitAlertForm() {
            if (!this.alertForm.name) {
                this.$message.warning('请输入告警名称');
                return;
            }

            if (this.isEdit) {
                // 更新告警
                axios.put(`/api/logs/alerts/${this.alertForm.id}`, this.alertForm, {
                    headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
                })
                .then(response => {
                    this.$message.success('告警配置更新成功');
                    this.alertDialogVisible = false;
                    this.fetchAlerts();
                })
                .catch(error => {
                    this.$message.error('更新告警配置失败: ' + error.response.data.message);
                });
            } else {
                // 创建告警
                axios.post('/api/logs/alerts', this.alertForm, {
                    headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
                })
                .then(response => {
                    this.$message.success('告警配置创建成功');
                    this.alertDialogVisible = false;
                    this.fetchAlerts();
                })
                .catch(error => {
                    this.$message.error('创建告警配置失败: ' + error.response.data.message);
                });
            }
        },
        deleteAlert(alert) {
            this.$confirm('此操作将永久删除该告警配置, 是否继续?', '提示', {
                confirmButtonText: '确定',
                cancelButtonText: '取消',
                type: 'warning'
            }).then(() => {
                axios.delete(`/api/logs/alerts/${alert.id}`, {
                    headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
                })
                .then(response => {
                    this.$message.success('告警配置删除成功');
                    this.fetchAlerts();
                })
                .catch(error => {
                    this.$message.error('删除告警配置失败: ' + error.response.data.message);
                });
            }).catch(() => {
                this.$message.info('已取消删除');
            });
        },
        toggleAlertStatus(alert) {
            const updatedAlert = Object.assign({}, alert, { enabled: !alert.enabled });

            axios.put(`/api/logs/alerts/${alert.id}`, updatedAlert, {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                this.$message.success(`告警配置已${updatedAlert.enabled ? '启用' : '禁用'}`);
                this.fetchAlerts();
            })
            .catch(error => {
                this.$message.error('操作失败: ' + error.response.data.message);
            });
        }
    },
    template: `
        <div>
            <el-tabs v-model="activeTab">
                <el-tab-pane label="日志查询" name="logs">
                    <el-card class="card-container">
                        <div slot="header">
                            <span>防火墙日志查询</span>
                            <el-button style="float: right; padding: 3px 0" type="text" :loading="collectLoading" @click="collectLogs">收集最新日志</el-button>
                        </div>
                        
                        <div class="log-filter">
                            <el-form :inline="true" :model="filter" size="small">
                                <el-form-item label="源IP">
                                    <el-input v-model="filter.source_ip" placeholder="源IP地址"></el-input>
                                </el-form-item>
                                <el-form-item label="目标IP">
                                    <el-input v-model="filter.destination_ip" placeholder="目标IP地址"></el-input>
                                </el-form-item>
                                <el-form-item label="动作">
                                    <el-select v-model="filter.action" placeholder="动作" clearable>
                                        <el-option label="ACCEPT" value="ACCEPT"></el-option>
                                        <el-option label="DROP" value="DROP"></el-option>
                                        <el-option label="REJECT" value="REJECT"></el-option>
                                        <el-option label="LOG" value="LOG"></el-option>
                                    </el-select>
                                </el-form-item>
                                <el-form-item label="协议">
                                    <el-select v-model="filter.protocol" placeholder="协议" clearable>
                                        <el-option label="TCP" value="TCP"></el-option>
                                        <el-option label="UDP" value="UDP"></el-option>
                                        <el-option label="ICMP" value="ICMP"></el-option>
                                    </el-select>
                                </el-form-item>
                                <el-form-item label="开始时间">
                                    <el-date-picker v-model="filter.start_date" type="datetime" placeholder="开始时间"></el-date-picker>
                                </el-form-item>
                                <el-form-item label="结束时间">
                                    <el-date-picker v-model="filter.end_date" type="datetime" placeholder="结束时间"></el-date-picker>
                                </el-form-item>
                                <el-form-item>
                                    <el-button type="primary" @click="handleFilter">查询</el-button>
                                    <el-button @click="resetFilter">重置</el-button>
                                </el-form-item>
                            </el-form>
                        </div>
                        
                        <el-table :data="logs" v-loading="loading" border style="width: 100%">
                            <el-table-column prop="timestamp" label="时间" width="180">
                                <template slot-scope="scope">
                                    {{ formatTime(scope.row.timestamp) }}
                                </template>
                            </el-table-column>
                            <el-table-column prop="source_ip" label="源IP" width="140"></el-table-column>
                            <el-table-column prop="destination_ip" label="目标IP" width="140"></el-table-column>
                            <el-table-column prop="protocol" label="协议" width="80"></el-table-column>
                            <el-table-column prop="action" label="动作" width="100">
                                <template slot-scope="scope">
                                    <el-tag size="small" :type="getActionType(scope.row.action)">
                                        {{ scope.row.action }}
                                    </el-tag>
                                </template>
                            </el-table-column>
                            <el-table-column prop="chain" label="链" width="100"></el-table-column>
                            <el-table-column prop="interface" label="接口" width="100"></el-table-column>
                            <el-table-column prop="raw_log" label="原始日志">
                                <template slot-scope="scope">
                                    <el-tooltip :content="scope.row.raw_log" placement="top" effect="light">
                                        <div class="truncate-text">{{ scope.row.raw_log }}</div>
                                    </el-tooltip>
                                </template>
                            </el-table-column>
                        </el-table>
                        
                        <div style="margin-top: 20px; text-align: right;">
                            <el-pagination
                                @current-change="handlePageChange"
                                :current-page="pagination.currentPage"
                                :page-size="pagination.pageSize"
                                layout="total, prev, pager, next"
                                :total="pagination.total">
                            </el-pagination>
                        </div>
                    </el-card>
                </el-tab-pane>
                
                <el-tab-pane label="流量分析" name="analysis">
                    <el-card class="card-container">
                        <div slot="header">
                            <span>流量分析</span>
                            <div style="float: right;">
                                <el-select v-model="analysisType" size="small" style="width: 120px; margin-right: 10px;" @change="changeAnalysisType">
                                    <el-option label="流量模式" value="traffic"></el-option>
                                    <el-option label="热门源IP" value="top_sources"></el-option>
                                    <el-option label="热门目标IP" value="top_destinations"></el-option>
                                </el-select>
                                <el-select v-model="timeRange" size="small" style="width: 120px;" @change="changeTimeRange">
                                    <el-option label="最近1小时" value="1h"></el-option>
                                    <el-option label="最近6小时" value="6h"></el-option>
                                    <el-option label="最近24小时" value="24h"></el-option>
                                    <el-option label="最近7天" value="7d"></el-option>
                                </el-select>
                            </div>
                        </div>
                        
                        <div v-loading="analysisLoading">
                            <!-- 流量模式分析 -->
                            <div v-if="analysisType === 'traffic' && analysisData">
                                <el-row :gutter="20">
                                    <el-col :span="12">
                                        <div class="chart-container" style="height: 300px;">
                                            <h4>协议分布</h4>
                                            <canvas id="protocolChart"></canvas>
                                        </div>
                                    </el-col>
                                    <el-col :span="12">
                                        <div class="chart-container" style="height: 300px;">
                                            <h4>时间分布</h4>
                                            <canvas id="timeChart"></canvas>
                                        </div>
                                    </el-col>
                                </el-row>
                                
                                <el-row :gutter="20" style="margin-top: 20px;">
                                    <el-col :span="12">
                                        <h4>热门源IP</h4>
                                        <el-table :data="Object.entries(analysisData.source_stats).map(([ip, count]) => ({ ip, count }))" border>
                                            <el-table-column prop="ip" label="源IP"></el-table-column>
                                            <el-table-column prop="count" label="数量"></el-table-column>
                                        </el-table>
                                    </el-col>
                                    <el-col :span="12">
                                        <h4>热门目标IP</h4>
                                        <el-table :data="Object.entries(analysisData.destination_stats).map(([ip, count]) => ({ ip, count }))" border>
                                            <el-table-column prop="ip" label="目标IP"></el-table-column>
                                            <el-table-column prop="count" label="数量"></el-table-column>
                                        </el-table>
                                    </el-col>
                                </el-row>
                            </div>
                            
                            <!-- 热门源IP分析 -->
                            <div v-if="analysisType === 'top_sources' && analysisData">
                                <h4>访问量最大的源IP</h4>
                                <el-table :data="analysisData" border>
                                    <el-table-column prop="source_ip" label="源IP"></el-table-column>
                                    <el-table-column prop="count" label="访问次数"></el-table-column>
                                </el-table>
                            </div>
                            
                            <!-- 热门目标IP分析 -->
                            <div v-if="analysisType === 'top_destinations' && analysisData">
                                <h4>访问量最大的目标IP</h4>
                                <el-table :data="analysisData" border>
                                    <el-table-column prop="destination_ip" label="目标IP"></el-table-column>
                                    <el-table-column prop="count" label="访问次数"></el-table-column>
                                </el-table>
                            </div>
                            
                            <div v-if="!analysisData" class="empty-data">
                                <el-empty description="暂无分析数据"></el-empty>
                            </div>
                        </div>
                    </el-card>
                </el-tab-pane>
                
                <el-tab-pane label="异常检测" name="anomalies">
                    <el-card class="card-container">
                        <div slot="header">
                            <span>异常检测</span>
                            <div style="float: right;">
                                <el-select v-model="timeRange" size="small" style="width: 120px; margin-right: 10px;" @change="loadAnomalies">
                                    <el-option label="最近1小时" value="1h"></el-option>
                                    <el-option label="最近6小时" value="6h"></el-option>
                                    <el-option label="最近24小时" value="24h"></el-option>
                                    <el-option label="最近7天" value="7d"></el-option>
                                </el-select>
                                <el-button size="small" type="primary" @click="loadAnomalies" :loading="anomalyLoading">检测异常</el-button>
                            </div>
                        </div>
                        
                        <div v-loading="anomalyLoading">
                            <div v-if="anomalies && anomalies.length > 0">
                                <el-table :data="anomalies" border>
                                    <el-table-column prop="type" label="类型" width="120">
                                        <template slot-scope="scope">
                                            <el-tag :type="getAnomalyType(scope.row.type)">{{ getAnomalyName(scope.row.type) }}</el-tag>
                                        </template>
                                    </el-table-column>
                                    <el-table-column prop="description" label="描述"></el-table-column>
                                    <el-table-column prop="source_ip" label="源IP" width="140"></el-table-column>
                                    <el-table-column prop="count" label="次数" width="80"></el-table-column>
                                    <el-table-column label="操作" width="200">
                                        <template slot-scope="scope">
                                            <el-button size="mini" type="danger" @click="createBlockRule(scope.row)">阻止</el-button>
                                            <el-button size="mini" type="info" @click="createAlertRule(scope.row)">设置告警</el-button>
                                        </template>
                                    </el-table-column>
                                </el-table>
                            </div>
                            <div v-else>
                                <el-empty description="未检测到异常"></el-empty>
                            </div>
                        </div>
                    </el-card>
                </el-tab-pane>
                
                <el-tab-pane label="告警配置" name="alerts">
                    <el-card class="card-container">
                        <div slot="header">
                            <span>告警配置</span>
                            <el-button style="float: right; padding: 3px 0" type="text" @click="openAlertDialog(false)">添加告警</el-button>
                        </div>
                        
                        <div v-loading="alertsLoading">
                            <el-table :data="alerts" border>
                                <el-table-column prop="name" label="名称" width="150"></el-table-column>
                                <el-table-column prop="description" label="描述"></el-table-column>
                                <el-table-column prop="condition_type" label="条件类型" width="120">
                                    <template slot-scope="scope">
                                        <el-tag>{{ getConditionTypeName(scope.row.condition_type) }}</el-tag>
                                    </template>
                                </el-table-column>
                                <el-table-column prop="condition_value" label="条件值" width="100"></el-table-column>
                                <el-table-column prop="action" label="动作" width="100">
                                    <template slot-scope="scope">
                                        <el-tag type="success">{{ getActionName(scope.row.action) }}</el-tag>
                                    </template>
                                </el-table-column>
                                <el-table-column prop="enabled" label="状态" width="80">
                                    <template slot-scope="scope">
                                        <el-switch
                                            v-model="scope.row.enabled"
                                            @change="toggleAlertStatus(scope.row)"
                                            active-color="#13ce66"
                                            inactive-color="#ff4949">
                                        </el-switch>
                                    </template>
                                </el-table-column>
                                <el-table-column label="操作" width="150">
                                    <template slot-scope="scope">
                                        <el-button size="mini" @click="openAlertDialog(true, scope.row)">编辑</el-button>
                                        <el-button size="mini" type="danger" @click="deleteAlert(scope.row)">删除</el-button>
                                    </template>
                                </el-table-column>
                            </el-table>
                            
                            <div v-if="alerts.length === 0" class="empty-data">
                                <el-empty description="暂无告警配置"></el-empty>
                            </div>
                        </div>
                    </el-card>
                </el-tab-pane>
            </el-tabs>
            
            <!-- 告警配置对话框 -->
            <el-dialog :title="isEdit ? '编辑告警配置' : '添加告警配置'" :visible.sync="alertDialogVisible" width="500px">
                <el-form :model="alertForm" label-width="100px">
                    <el-form-item label="名称">
                        <el-input v-model="alertForm.name" placeholder="告警名称"></el-input>
                    </el-form-item>
                    <el-form-item label="描述">
                        <el-input v-model="alertForm.description" placeholder="告警描述"></el-input>
                    </el-form-item>
                    <el-form-item label="条件类型">
                        <el-select v-model="alertForm.condition_type" placeholder="请选择条件类型">
                            <el-option label="速率限制" value="rate_limit"></el-option>
                            <el-option label="模式匹配" value="pattern_match"></el-option>
                            <el-option label="任意异常" value="any"></el-option>
                        </el-select>
                    </el-form-item>
                    <el-form-item label="条件值">
                        <el-input v-model="alertForm.condition_value" placeholder="条件值"></el-input>
                        <div class="form-tip" v-if="alertForm.condition_type === 'rate_limit'">
                            输入一个数字，表示触发告警的请求次数阈值
                        </div>
                        <div class="form-tip" v-if="alertForm.condition_type === 'pattern_match'">
                            输入一个字符串，用于在日志中匹配
                        </div>
                    </el-form-item>
                    <el-form-item label="告警动作">
                        <el-select v-model="alertForm.action" placeholder="请选择告警动作">
                            <el-option label="记录日志" value="log"></el-option>
                            <el-option label="发送邮件" value="email"></el-option>
                            <el-option label="Webhook通知" value="webhook"></el-option>
                        </el-select>
                    </el-form-item>
                    <el-form-item label="动作配置" v-if="alertForm.action !== 'log'">
                        <el-input v-model="alertForm.action_config" type="textarea" :rows="3" placeholder="JSON格式配置"></el-input>
                        <div class="form-tip" v-if="alertForm.action === 'email'">
                            格式: {"recipient": "user@example.com"}
                        </div>
                        <div class="form-tip" v-if="alertForm.action === 'webhook'">
                            格式: {"url": "https://example.com/webhook"}
                        </div>
                    </el-form-item>
                    <el-form-item label="启用状态">
                        <el-switch v-model="alertForm.enabled"></el-switch>
                    </el-form-item>
                </el-form>
                <span slot="footer" class="dialog-footer">
                    <el-button @click="alertDialogVisible = false">取消</el-button>
                    <el-button type="primary" @click="submitAlertForm">确定</el-button>
                </span>
            </el-dialog>
        </div>
    `,
    methods: {
        getActionType(action) {
            switch (action) {
                case 'ACCEPT': return 'success';
                case 'DROP': return 'danger';
                case 'REJECT': return 'warning';
                case 'LOG': return 'info';
                default: return '';
            }
        },
        getAnomalyType(type) {
            switch (type) {
                case 'rate_limit': return 'danger';
                case 'pattern_match': return 'warning';
                case 'port_scan': return 'danger';
                default: return 'info';
            }
        },
        getAnomalyName(type) {
            switch (type) {
                case 'rate_limit': return '速率超限';
                case 'pattern_match': return '模式匹配';
                case 'port_scan': return '端口扫描';
                default: return type;
            }
        },
        getConditionTypeName(type) {
            switch (type) {
                case 'rate_limit': return '速率限制';
                case 'pattern_match': return '模式匹配';
                case 'any': return '任意异常';
                default: return type;
            }
        },
        getActionName(action) {
            switch (action) {
                case 'log': return '记录日志';
                case 'email': return '发送邮件';
                case 'webhook': return 'Webhook';
                default: return action;
            }
        },
        createBlockRule(anomaly) {
            // 根据异常创建阻止规则
            if (!anomaly.source_ip) {
                this.$message.warning('无法创建规则：缺少源IP地址');
                return;
            }

            // 创建一个新规则对象
            const rule = {
                rule_type: 'iptables',
                chain: 'INPUT',
                protocol: 'all',
                source: anomaly.source_ip,
                destination: 'any',
                port: 'any',
                action: 'DROP',
                comment: `自动创建: 阻止异常流量 (${anomaly.type})`,
                priority: 50,  // 高优先级
                enabled: true
            };

            // 发送请求创建规则
            axios.post('/api/rules', rule, {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                this.$message.success('已创建阻止规则');
            })
            .catch(error => {
                this.$message.error('创建规则失败: ' + error.response.data.message);
            });
        },
        createAlertRule(anomaly) {
            // 根据异常创建告警规则
            let conditionType, conditionValue;

            if (anomaly.type === 'rate_limit') {
                conditionType = 'rate_limit';
                conditionValue = anomaly.threshold ? String(anomaly.threshold) : '100';
            } else if (anomaly.type === 'pattern_match') {
                conditionType = 'pattern_match';
                conditionValue = anomaly.pattern || '';
            } else {
                conditionType = 'any';
                conditionValue = '';
            }

            // 设置告警表单
            this.alertForm = {
                name: `告警: ${this.getAnomalyName(anomaly.type)}`,
                description: anomaly.description || `检测${this.getAnomalyName(anomaly.type)}类型的异常流量`,
                condition_type: conditionType,
                condition_value: conditionValue,
                action: 'log',
                action_config: '{}',
                enabled: true
            };

            // 打开告警对话框
            this.alertDialogVisible = true;
        }
    }
};

// 系统设置组件
const SystemSettings = {
    data() {
        return {
            settings: {},
            loading: true,
            backups: [],
            backupsLoading: false,
            createBackupLoading: false,
            restoreLoading: false,
            backupDescription: '',
            backupDialogVisible: false
        };
    },
    created() {
        this.fetchSettings();
        this.fetchBackups();
    },
    methods: {
        fetchSettings() {
            this.loading = true;

            axios.get('/api/settings', {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                // 将设置数组转换为对象
                const settingsObj = {};
                response.data.data.forEach(setting => {
                    settingsObj[setting.key] = setting.value;
                });

                this.settings = settingsObj;
                this.loading = false;
            })
            .catch(error => {
                this.$message.error('获取设置失败: ' + error.response.data.message);
                this.loading = false;
            });
        },
        saveSettings() {
            axios.post('/api/settings', this.settings, {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                this.$message.success('设置保存成功');
            })
            .catch(error => {
                this.$message.error('保存设置失败: ' + error.response.data.message);
            });
        },
        fetchBackups() {
            this.backupsLoading = true;

            axios.get('/api/settings/backups', {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                this.backups = response.data.data;
                this.backupsLoading = false;
            })
            .catch(error => {
                this.$message.error('获取备份列表失败: ' + error.response.data.message);
                this.backupsLoading = false;
            });
        },
        openBackupDialog() {
            this.backupDescription = `手动备份 - ${new Date().toLocaleString()}`;
            this.backupDialogVisible = true;
        },
        createBackup() {
            this.createBackupLoading = true;

            axios.post('/api/settings/backups', {
                description: this.backupDescription
            }, {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                this.$message.success('备份创建成功');
                this.backupDialogVisible = false;
                this.fetchBackups();
                this.createBackupLoading = false;
            })
            .catch(error => {
                this.$message.error('创建备份失败: ' + error.response.data.message);
                this.createBackupLoading = false;
            });
        },
        restoreBackup(backup) {
            this.$confirm(`此操作将从备份"${backup.description}"恢复系统, 是否继续?`, '提示', {
                confirmButtonText: '确定',
                cancelButtonText: '取消',
                type: 'warning'
            }).then(() => {
                this.restoreLoading = true;

                axios.post(`/api/settings/backups/${backup.id}`, {}, {
                    headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
                })
                .then(response => {
                    this.$message.success('系统恢复成功');
                    this.restoreLoading = false;
                    // 刷新页面以应用恢复的设置
                    setTimeout(() => {
                        window.location.reload();
                    }, 1500);
                })
                .catch(error => {
                    this.$message.error('恢复系统失败: ' + error.response.data.message);
                    this.restoreLoading = false;
                });
            }).catch(() => {
                this.$message.info('已取消恢复操作');
            });
        },
        deleteBackup(backup) {
            this.$confirm(`此操作将永久删除备份"${backup.description}", 是否继续?`, '提示', {
                confirmButtonText: '确定',
                cancelButtonText: '取消',
                type: 'warning'
            }).then(() => {
                axios.delete(`/api/settings/backups/${backup.id}`, {
                    headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
                })
                .then(response => {
                    this.$message.success('备份删除成功');
                    this.fetchBackups();
                })
                .catch(error => {
                    this.$message.error('删除备份失败: ' + error.response.data.message);
                });
            }).catch(() => {
                this.$message.info('已取消删除');
            });
        },
        formatTime(timestamp) {
            if (!timestamp) return '未知';
            const date = new Date(timestamp);
            return date.toLocaleString();
        },
        formatSize(size) {
            if (size < 1024) {
                return size + ' B';
            } else if (size < 1024 * 1024) {
                return (size / 1024).toFixed(2) + ' KB';
            } else {
                return (size / (1024 * 1024)).toFixed(2) + ' MB';
            }
        }
    },
    template: `
        <div>
            <el-card class="card-container" v-loading="loading">
                <div slot="header">
                    <span>系统设置</span>
                    <el-button style="float: right; padding: 3px 0" type="text" @click="saveSettings">保存设置</el-button>
                </div>
                
                <el-form label-width="200px">
                    <el-form-item label="监控间隔 (秒)">
                        <el-input-number v-model="settings.monitor_interval" :min="5" :max="3600"></el-input-number>
                        <div class="form-tip">系统自动检查防火墙状态的时间间隔</div>
                    </el-form-item>
                    
                    <el-form-item label="日志保留天数">
                        <el-input-number v-model="settings.log_retention_days" :min="1" :max="365"></el-input-number>
                        <div class="form-tip">系统自动清理超过保留天数的日志</div>
                    </el-form-item>
                    
                    <el-form-item label="自动备份">
                        <el-switch v-model="settings.auto_backup_enabled" active-text="启用" inactive-text="禁用"></el-switch>
                        <div class="form-tip">是否启用系统自动备份</div>
                    </el-form-item>
                    
                    <el-form-item label="自动备份间隔 (天)" v-if="settings.auto_backup_enabled">
                        <el-input-number v-model="settings.auto_backup_interval" :min="1" :max="30"></el-input-number>
                        <div class="form-tip">系统自动创建备份的时间间隔</div>
                    </el-form-item>
                    
                    <el-form-item label="备份保留数量">
                        <el-input-number v-model="settings.backup_retention_count" :min="1" :max="100"></el-input-number>
                        <div class="form-tip">系统保留的最大备份数量，超过将自动删除最旧的备份</div>
                    </el-form-item>
                </el-form>
            </el-card>
            
            <el-card class="card-container">
                <div slot="header">
                    <span>系统备份与恢复</span>
                    <el-button style="float: right; padding: 3px 0" type="text" @click="openBackupDialog">创建备份</el-button>
                </div>
                
                <div v-loading="backupsLoading">
                    <div v-if="backups.length > 0" class="backup-list">
                        <div v-for="backup in backups" :key="backup.id" class="backup-item">
                            <div class="backup-info">
                                <div><strong>{{ backup.description }}</strong></div>
                                <div style="font-size: 12px; color: #909399;">
                                    创建时间: {{ formatTime(backup.created_at) }} | 
                                    大小: {{ formatSize(backup.size) }}
                                </div>
                            </div>
                            <div class="backup-actions">
                                <el-button size="mini" type="primary" @click="restoreBackup(backup)" :loading="restoreLoading">恢复</el-button>
                                <el-button size="mini" type="danger" @click="deleteBackup(backup)">删除</el-button>
                            </div>
                        </div>
                    </div>
                    <div v-else>
                        <el-empty description="暂无备份记录"></el-empty>
                    </div>
                </div>
            </el-card>
            
            <!-- 创建备份对话框 -->
            <el-dialog title="创建系统备份" :visible.sync="backupDialogVisible" width="400px">
                <el-form>
                    <el-form-item label="备份描述">
                        <el-input v-model="backupDescription" placeholder="输入备份描述信息"></el-input>
                    </el-form-item>
                </el-form>
                <span slot="footer" class="dialog-footer">
                    <el-button @click="backupDialogVisible = false">取消</el-button>
                    <el-button type="primary" @click="createBackup" :loading="createBackupLoading">创建</el-button>
                </span>
            </el-dialog>
        </div>
    `
};
