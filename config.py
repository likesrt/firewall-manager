# config.py - 应用配置

import os


class Config:
	# Flask配置
	SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard-to-guess-string'
	DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
	
	# 数据库配置
	SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
	                          'postgresql://firewall:securepassword@db/firewall_manager'
	SQLALCHEMY_TRACK_MODIFICATIONS = False
	
	# 防火墙配置
	IPTABLES_PATH = os.environ.get('IPTABLES_PATH') or '/sbin/iptables'
	NFTABLES_PATH = os.environ.get('NFTABLES_PATH') or '/sbin/nft'
	
	# 日志配置
	IPTABLES_LOG_PATH = os.environ.get('IPTABLES_LOG_PATH') or '/var/log/iptables.log'
	NFTABLES_LOG_PATH = os.environ.get('NFTABLES_LOG_PATH') or '/var/log/nftables.log'
	
	# 监控配置
	MONITOR_INTERVAL = int(os.environ.get('MONITOR_INTERVAL') or 30)  # 秒
	
	# 备份配置
	BACKUP_DIR = os.environ.get('BACKUP_DIR') or '/app/backups'

	# 邮件配置
	MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
	MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
	MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
	MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'False').lower() == 'true'
	MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
	MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')
	MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', '')
