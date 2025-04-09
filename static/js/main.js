// static/js/main.js
// 定义路由
const routes = [
    { path: '/rules', component: RuleManagement },
    { path: '/status', component: StatusMonitor },
    { path: '/logs', component: LogAnalysis },
    { path: '/settings', component: SystemSettings },
    { path: '*', redirect: '/rules' }
];

const router = new VueRouter({
    routes
});

// 创建Vue实例
new Vue({
    el: '#app',
    router,
    data: {
        isLoggedIn: false,
        username: '',
        firewallEnabled: false,
        loginForm: {
            username: '',
            password: ''
        },
        loginRules: {
            username: [
                { required: true, message: '请输入用户名', trigger: 'blur' }
            ],
            password: [
                { required: true, message: '请输入密码', trigger: 'blur' }
            ]
        },
        loginLoading: false,
        profileDialogVisible: false,
        profileForm: {
            username: '',
            password: '',
            confirmPassword: '',
            regenerateApiKey: false
        },
        profileRules: {
            password: [
                { validator: this.validatePassword, trigger: 'blur' }
            ],
            confirmPassword: [
                { validator: this.validateConfirmPassword, trigger: 'blur' }
            ]
        }
    },
    created() {
        // 检查是否已登录
        const token = localStorage.getItem('token');
        if (token) {
            this.checkAuth();
        }

        // 检查防火墙状态
        this.checkFirewallStatus();
    },
    methods: {
        login() {
            this.$refs.loginForm.validate(valid => {
                if (valid) {
                    this.loginLoading = true;

                    axios.post('/api/users/login', this.loginForm)
                        .then(response => {
                            if (response.data.success) {
                                localStorage.setItem('token', response.data.data.token);
                                this.username = response.data.data.user.username;
                                this.isLoggedIn = true;
                                this.loginLoading = false;

                                // 检查防火墙状态
                                this.checkFirewallStatus();
                            }
                        })
                        .catch(error => {
                            this.$message.error('登录失败: ' + (error.response ? error.response.data.message : '未知错误'));
                            this.loginLoading = false;
                        });
                }
            });
        },
        checkAuth() {
            axios.get('/api/users/profile', {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                if (response.data.success) {
                    this.isLoggedIn = true;
                    this.username = response.data.data.username;
                }
            })
            .catch(error => {
                // 认证失败，清除token
                localStorage.removeItem('token');
                this.isLoggedIn = false;
            });
        },
        checkFirewallStatus() {
            if (!this.isLoggedIn) return;

            axios.get('/api/status', {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                if (response.data.success) {
                    // 如果iptables或nftables任一启用，则认为防火墙已启用
                    this.firewallEnabled = response.data.data.iptables.status || response.data.data.nftables.status;
                }
            })
            .catch(error => {
                console.error('获取防火墙状态失败:', error);
            });
        },
        toggleFirewall() {
            const action = this.firewallEnabled ? 'start' : 'stop';
            const service = 'iptables';  // 默认使用iptables

            axios.post('/api/status/control', {
                service: service,
                action: action
            }, {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                if (response.data.success) {
                    this.$message.success(`防火墙已${this.firewallEnabled ? '启用' : '禁用'}`);
                }
            })
            .catch(error => {
                this.$message.error('操作失败: ' + error.response.data.message);
                // 恢复原状态
                this.firewallEnabled = !this.firewallEnabled;
            });
        },
        handleCommand(command) {
            if (command === 'logout') {
                this.logout();
            } else if (command === 'profile') {
                this.openProfileDialog();
            }
        },
        logout() {
            localStorage.removeItem('token');
            this.isLoggedIn = false;
            this.username = '';
            this.$router.push('/');
            this.$message.success('已退出登录');
        },
        openProfileDialog() {
            // 获取当前用户信息
            axios.get('/api/users/profile', {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                if (response.data.success) {
                    this.profileForm = {
                        username: response.data.data.username,
                        password: '',
                        confirmPassword: '',
                        regenerateApiKey: false
                    };
                    this.profileDialogVisible = true;
                }
            })
            .catch(error => {
                this.$message.error('获取用户信息失败: ' + error.response.data.message);
            });
        },
        updateProfile() {
            // 验证密码
            if (this.profileForm.password && this.profileForm.password !== this.profileForm.confirmPassword) {
                this.$message.error('两次输入的密码不一致');
                return;
            }

            // 构建更新数据
            const updateData = {
                regenerate_api_key: this.profileForm.regenerateApiKey
            };

            if (this.profileForm.password) {
                updateData.password = this.profileForm.password;
            }

            // 发送更新请求
            axios.put('/api/users/profile', updateData, {
                headers: { 'Authorization': 'Bearer ' + localStorage.getItem('token') }
            })
            .then(response => {
                if (response.data.success) {
                    this.$message.success('个人设置更新成功');
                    this.profileDialogVisible = false;

                    // 如果更新了密码，需要重新登录
                    if (this.profileForm.password) {
                        this.$confirm('密码已更新，需要重新登录', '提示', {
                            confirmButtonText: '确定',
                            type: 'warning',
                            showCancelButton: false
                        }).then(() => {
                            this.logout();
                        });
                    }
                }
            })
            .catch(error => {
                this.$message.error('更新失败: ' + error.response.data.message);
            });
        },
        validatePassword(rule, value, callback) {
            if (value && value.length < 6) {
                callback(new Error('密码长度不能少于6个字符'));
            } else {
                callback();
            }
        },
        validateConfirmPassword(rule, value, callback) {
            if (value !== this.profileForm.password) {
                callback(new Error('两次输入的密码不一致'));
            } else {
                callback();
            }
        }
    }
});
