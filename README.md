# 防火墙管理系统

## 使用指南

### 系统架构
- 基于 Docker 容器化部署
- 使用 PostgreSQL 作为数据库后端
- Python Flask 作为 Web 框架
- 支持 iptables 和 nftables 防火墙

### 安装和启动

**系统要求**：
- 已安装 Docker 和 Docker Compose 的 VPS 服务器
- 建议配置：至少 1GB 内存，10GB 存储空间

**安装步骤**：
1. 克隆代码库到您的服务器：
   ```bash
   git clone https://github.com/likesrt/firewall-manager
   ```
2. 进入项目目录：
   ```bash
   cd firewall-manager
   ```
3. 修改环境配置（可选）：
   - 编辑 `docker-compose.yml` 文件中的环境变量
   - 特别是修改 `SECRET_KEY`、`DEFAULT_ADMIN_PASSWORD` 和数据库连接信息
4. 启动应用：
   ```bash
   docker-compose up -d
   ```

**访问系统**：
- 访问地址：`http://your-server-ip:5000`
- 默认登录凭证：
  - 用户名：`admin`
  - 密码：`admin123`（首次登录后请立即修改）

### 配置说明

#### 环境变量
| 变量名 | 描述 | 默认值 |
|--------|------|--------|
| `SECRET_KEY` | Flask 应用密钥 | your-secret-key-here |
| `DEBUG` | 调试模式 | true |
| `DEFAULT_ADMIN_PASSWORD` | 默认管理员密码 | admin123 |
| `SQLALCHEMY_DATABASE_URI` | 数据库连接字符串 | postgresql://user:password@host:port/db |
| `MAIL_*` 系列 | 邮件通知配置 | 需用户自定义 |

#### 挂载卷
- `/var/log/iptables`: 用于读取 iptables 日志
- `/var/log/nftables`: 用于读取 nftables 日志
- 本地目录挂载: 用于持久化应用代码

### 基本使用流程

#### 规则管理
- 创建、编辑和删除防火墙规则
- 支持批量导入/导出规则配置 (JSON/CSV 格式)
- 自动同步服务器现有规则
- 支持规则测试和模拟应用

#### 状态监控
- 实时查看防火墙服务状态
- 监控网络连接统计和流量图表
- 控制防火墙服务（启动/停止/重启）
- 服务健康检查和告警

#### 日志分析
- 查询和筛选防火墙日志
- 可视化流量模式和趋势
- 异常流量检测和安全威胁分析
- 可配置的自动告警规则

#### 系统设置
- 调整系统配置参数
- 创建和恢复系统备份
- 多用户账号管理和权限控制
- 审计日志和操作历史

### 数据库配置
系统默认使用外部 PostgreSQL 数据库，配置示例：
```yaml
SQLALCHEMY_DATABASE_URI=postgresql://username:password@host:port/database
```

如需使用内置数据库，取消注释 `docker-compose.yml` 中的 db 服务部分，并注释掉外部数据库配置。

### 安全注意事项

1. **初始安全设置**：
   - 首次登录后立即修改默认密码
   - 禁用 DEBUG 模式（设置 `DEBUG=false`）
   - 修改默认的 `SECRET_KEY`

2. **连接安全**：
   - 强烈建议通过反向代理（如 Nginx）启用 HTTPS 加密
   - 使用防火墙限制管理界面的访问 IP
   - 考虑修改默认端口（5000）

3. **数据安全**：
   - 定期备份系统配置和规则
   - 将备份文件存储在加密的安全位置
   - 数据库密码等敏感信息不要硬编码在配置文件中

4. **系统维护**：
   - 定期检查系统日志和安全审计日志
   - 保持 Docker 镜像和系统组件更新到最新版本
   - 监控容器资源使用情况

5. **网络安全**：
   - 仅开放必要的端口
   - 实施最小权限原则
   - 定期审查防火墙规则的有效性

### 故障排除

1. **容器启动失败**：
   - 检查日志：`docker-compose logs web`
   - 确保数据库连接信息正确
   - 验证端口 5000 未被占用

2. **权限问题**：
   - 确保挂载的日志目录有正确权限
   - 可能需要 `chmod 644` 日志文件

3. **邮件配置**：
   - 测试邮件发送功能
   - 对于 Gmail，可能需要启用"不太安全的应用"选项

4. **数据库连接**：
   - 验证数据库服务是否运行
   - 检查网络连接和防火墙规则



   ```

