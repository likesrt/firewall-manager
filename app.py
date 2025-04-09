#!/usr/bin/env python3
# app.py - 应用程序入口点

import os
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
from flask_migrate import Migrate
from models import db, User
from routes import register_routes
from services.status_monitor import FirewallMonitor
from config import Config
import threading
import time

# 创建Flask应用
app = Flask(__name__)
app.config.from_object(Config)

# 初始化数据库
db.init_app(app)
migrate = Migrate(app, db)

# 初始化SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# 注册所有路由
register_routes(app)


# 主页路由
@app.route('/')
def index():
	return render_template('index.html')


# 健康检查API
@app.route('/api/health')
def health_check():
	return jsonify({"status": "ok", "version": "1.0.0"})


# 启动状态监控
def start_monitor():
	with app.app_context():
		monitor = FirewallMonitor(socketio)
		monitor.start_monitoring()


# 创建初始用户
def create_default_user():
	with app.app_context():
		# 确保表已创建
		db.create_all()
		
		# 检查是否有用户，如果没有则创建默认用户
		if User.query.count() == 0:
			default_user = User(username='admin')
			default_password = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'admin123')
			default_user.set_password(default_password)
			db.session.add(default_user)
			db.session.commit()
			print(f"Created default admin user with password: {default_password}")


if __name__ == '__main__':
	# 创建默认用户
	create_default_user()
	
	# 在后台线程启动监控服务
	monitor_thread = threading.Thread(target=start_monitor)
	monitor_thread.daemon = True
	monitor_thread.start()
	
	# 启动Flask应用
	socketio.run(app, host='0.0.0.0', port=5000, debug=Config.DEBUG)
