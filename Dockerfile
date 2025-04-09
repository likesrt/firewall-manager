# Dockerfile
# 多阶段构建
FROM python:3.9-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --user -r requirements.txt

FROM python:3.9-slim
WORKDIR /app

# 安装iptables和nftables
RUN apt-get update && apt-get install -y iptables nftables conntrack && apt-get clean

# 复制Python依赖
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# 复制应用代码
COPY . .

# 创建备份目录
RUN mkdir -p /app/backups

EXPOSE 5000
CMD ["python", "app.py"]
