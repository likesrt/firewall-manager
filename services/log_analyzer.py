# services/log_analyzer.py
import re
import os
import subprocess
from datetime import datetime, timedelta
from models import db, FirewallLog, AlertConfig
from flask import current_app
from collections import Counter
import json


class LogCollector:
	def __init__(self):
		self.iptables_log_path = current_app.config.get('IPTABLES_LOG_PATH')
		self.nftables_log_path = current_app.config.get('NFTABLES_LOG_PATH')
	
	def collect_logs(self):
		"""收集防火墙日志"""
		count = 0
		
		# 收集iptables日志
		if os.path.exists(self.iptables_log_path):
			count += self._collect_iptables_logs()
		
		# 收集nftables日志
		if os.path.exists(self.nftables_log_path):
			count += self._collect_nftables_logs()
		
		return count
	
	def _collect_iptables_logs(self):
		"""收集iptables日志"""
		count = 0
		
		try:
			# 获取上次处理的位置
			last_position = self._get_last_position('iptables')
			
			with open(self.iptables_log_path, 'r') as f:
				# 如果有上次位置，则跳转到该位置
				if last_position > 0:
					f.seek(last_position)
				
				# 读取并解析新日志
				for line in f:
					log_entry = self.parse_iptables_log(line)
					if log_entry:
						db.session.add(log_entry)
						count += 1
				
				# 保存当前位置
				self._save_last_position('iptables', f.tell())
			
			# 提交所有更改
			if count > 0:
				db.session.commit()
		
		except Exception as e:
			current_app.logger.error(f"Error collecting iptables logs: {e}")
			db.session.rollback()
		
		return count
	
	def _collect_nftables_logs(self):
		"""收集nftables日志"""
		count = 0
		
		try:
			# 获取上次处理的位置
			last_position = self._get_last_position('nftables')
			
			with open(self.nftables_log_path, 'r') as f:
				# 如果有上次位置，则跳转到该位置
				if last_position > 0:
					f.seek(last_position)
				
				# 读取并解析新日志
				for line in f:
					log_entry = self.parse_nftables_log(line)
					if log_entry:
						db.session.add(log_entry)
						count += 1
				
				# 保存当前位置
				self._save_last_position('nftables', f.tell())
			
			# 提交所有更改
			if count > 0:
				db.session.commit()
		
		except Exception as e:
			current_app.logger.error(f"Error collecting nftables logs: {e}")
			db.session.rollback()
		
		return count
	
	def _get_last_position(self, log_type):
		"""获取上次处理的日志位置"""
		setting_key = f'last_log_position_{log_type}'
		setting = db.session.query(SystemSetting).filter_by(key=setting_key).first()
		
		if setting:
			try:
				return int(setting.value)
			except (ValueError, TypeError):
				return 0
		
		return 0
	
	def _save_last_position(self, log_type, position):
		"""保存当前处理的日志位置"""
		setting_key = f'last_log_position_{log_type}'
		setting = db.session.query(SystemSetting).filter_by(key=setting_key).first()
		
		if setting:
			setting.value = str(position)
		else:
			from models.setting import SystemSetting
			setting = SystemSetting(
				key=setting_key,
				value=str(position),
				description=f'Last processed position in {log_type} log file'
			)
			db.session.add(setting)
		
		db.session.commit()
	
	def parse_iptables_log(self, log_line):
		"""解析iptables日志条目"""
		# 示例iptables日志格式
		# Jan 1 12:34:56 hostname kernel: [123456.789012] [IPTABLES] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=192.168.1.2 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=12345 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0
		
		try:
			# 提取时间戳
			timestamp_match = re.search(r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)', log_line)
			if not timestamp_match:
				return None
			
			timestamp_str = timestamp_match.group(1)
			# 添加年份，因为日志中通常没有年份
			current_year = datetime.utcnow().year
			timestamp_str = f"{timestamp_str} {current_year}"
			timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
			
			# 提取源IP
			src_match = re.search(r'SRC=(\S+)', log_line)
			source_ip = src_match.group(1) if src_match else None
			
			# 提取目标IP
			dst_match = re.search(r'DST=(\S+)', log_line)
			destination_ip = dst_match.group(1) if dst_match else None
			
			# 提取协议
			proto_match = re.search(r'PROTO=(\S+)', log_line)
			protocol = proto_match.group(1) if proto_match else None
			
			# 提取接口
			in_match = re.search(r'IN=(\S+)', log_line)
			interface = in_match.group(1) if in_match else None
			
			# 提取动作和链（通常需要在日志前缀中配置）
			action_match = re.search(r'\[IPTABLES\]\s+(\S+)', log_line)
			action = action_match.group(1) if action_match else "UNKNOWN"
			
			chain_match = re.search(r'CHAIN=(\S+)', log_line)
			chain = chain_match.group(1) if chain_match else "UNKNOWN"
			
			# 创建日志条目
			log_entry = FirewallLog(
				timestamp=timestamp,
				source_ip=source_ip,
				destination_ip=destination_ip,
				protocol=protocol,
				action=action,
				chain=chain,
				interface=interface,
				raw_log=log_line
			)
			
			return log_entry
		
		except Exception as e:
			current_app.logger.error(f"Error parsing iptables log: {e}, line: {log_line}")
			return None
	
	def parse_nftables_log(self, log_line):
		"""解析nftables日志条目"""
		# 示例nftables日志格式
		# Jan 1 12:34:56 hostname kernel: [123456.789012] nft#12345: [chain-name] [table-name] IN=eth0 OUT= MAC=00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd SRC=192.168.1.2 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=12345 DPT=80 WINDOW=65535 RES=0x00 SYN URGP=0
		
		try:
			# 提取时间戳
			timestamp_match = re.search(r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)', log_line)
			if not timestamp_match:
				return None
			
			timestamp_str = timestamp_match.group(1)
			# 添加年份，因为日志中通常没有年份
			current_year = datetime.utcnow().year
			timestamp_str = f"{timestamp_str} {current_year}"
			timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
			
			# 提取链和表
			chain_table_match = re.search(r'nft#\d+: \[([^\]]+)\] \[([^\]]+)\]', log_line)
			chain = chain_table_match.group(1) if chain_table_match else "UNKNOWN"
			table = chain_table_match.group(2) if chain_table_match else "UNKNOWN"
			
			# 提取源IP
			src_match = re.search(r'SRC=(\S+)', log_line)
			source_ip = src_match.group(1) if src_match else None
			
			# 提取目标IP
			dst_match = re.search(r'DST=(\S+)', log_line)
			destination_ip = dst_match.group(1) if dst_match else None
			
			# 提取协议
			proto_match = re.search(r'PROTO=(\S+)', log_line)
			protocol = proto_match.group(1) if proto_match else None
			
			# 提取接口
			in_match = re.search(r'IN=(\S+)', log_line)
			interface = in_match.group(1) if in_match else None
			
			# 动作通常需要从日志配置中推断
			action = "LOG"  # 默认动作
			
			# 创建日志条目
			log_entry = FirewallLog(
				timestamp=timestamp,
				source_ip=source_ip,
				destination_ip=destination_ip,
				protocol=protocol,
				action=action,
				chain=chain,
				interface=interface,
				raw_log=log_line
			)
			
			return log_entry
		
		except Exception as e:
			current_app.logger.error(f"Error parsing nftables log: {e}, line: {log_line}")
			return None


class LogAnalyzer:
	def analyze_traffic_patterns(self, start_time, end_time):
		"""分析流量模式"""
		# 查询指定时间范围内的日志
		logs = FirewallLog.query.filter(
			FirewallLog.timestamp.between(start_time, end_time)
		).all()
		
		# 按协议统计
		protocol_stats = Counter()
		for log in logs:
			if log.protocol:
				protocol_stats[log.protocol] += 1
		
		# 按源IP统计
		source_stats = Counter()
		for log in logs:
			if log.source_ip:
				source_stats[log.source_ip] += 1
		
		# 按目标IP统计
		destination_stats = Counter()
		for log in logs:
			if log.destination_ip:
				destination_stats[log.destination_ip] += 1
		
		# 按时间段统计
		time_stats = {}
		# 将时间范围分为24个时间段
		time_range = (end_time - start_time).total_seconds()
		interval = time_range / 24
		
		for i in range(24):
			interval_start = start_time + timedelta(seconds=i * interval)
			interval_end = start_time + timedelta(seconds=(i + 1) * interval)
			
			count = FirewallLog.query.filter(
				FirewallLog.timestamp.between(interval_start, interval_end)
			).count()
			
			time_stats[interval_start.isoformat()] = count
		
		return {
			'protocol_stats': dict(protocol_stats.most_common(10)),
			'source_stats': dict(source_stats.most_common(10)),
			'destination_stats': dict(destination_stats.most_common(10)),
			'time_stats': time_stats
		}
	
	def detect_anomalies(self, start_time, end_time):
		"""检测异常"""
		anomalies = []
		
		# 获取告警配置
		alert_configs = AlertConfig.query.filter_by(enabled=True).all()
		
		for config in alert_configs:
			if config.condition_type == 'rate_limit':
				# 速率限制检测
				try:
					threshold = int(config.condition_value)
					
					# 按源IP统计
					source_counts = db.session.query(
						FirewallLog.source_ip,
						db.func.count(FirewallLog.id).label('count')
					).filter(
						FirewallLog.timestamp.between(start_time, end_time)
					).group_by(FirewallLog.source_ip).all()
					
					for source_ip, count in source_counts:
						if count > threshold:
							anomalies.append({
								'type': 'rate_limit',
								'source_ip': source_ip,
								'count': count,
								'threshold': threshold,
								'description': f'Source IP {source_ip} exceeded rate limit with {count} requests (threshold: {threshold})'
							})
				except ValueError:
					current_app.logger.error(f"Invalid rate limit threshold: {config.condition_value}")
			
			elif config.condition_type == 'pattern_match':
				# 模式匹配检测
				pattern = config.condition_value
				
				try:
					matching_logs = FirewallLog.query.filter(
						FirewallLog.timestamp.between(start_time, end_time),
						FirewallLog.raw_log.like(f'%{pattern}%')
					).all()
					
					if matching_logs:
						anomalies.append({
							'type': 'pattern_match',
							'pattern': pattern,
							'count': len(matching_logs),
							'description': f'Found {len(matching_logs)} logs matching pattern "{pattern}"',
							'sample': matching_logs[0].raw_log if matching_logs else None
						})
				except Exception as e:
					current_app.logger.error(f"Error in pattern matching: {e}")
		
		# 检测端口扫描
		# 查找短时间内访问多个不同端口的源IP
		try:
			# 获取所有包含端口信息的日志
			port_logs = FirewallLog.query.filter(
				FirewallLog.timestamp.between(start_time, end_time),
				FirewallLog.raw_log.like('%DPT=%')
			).all()
			
			# 按源IP分组，统计不同目标端口的数量
			port_scan_data = {}
			for log in port_logs:
				if not log.source_ip:
					continue
				
				port_match = re.search(r'DPT=(\d+)', log.raw_log)
				if not port_match:
					continue
				
				port = port_match.group(1)
				
				if log.source_ip not in port_scan_data:
					port_scan_data[log.source_ip] = set()
				
				port_scan_data[log.source_ip].add(port)
			
			# 检测端口扫描（访问超过10个不同端口）
			for source_ip, ports in port_scan_data.items():
				if len(ports) > 10:
					anomalies.append({
						'type': 'port_scan',
						'source_ip': source_ip,
						'port_count': len(ports),
						'description': f'Possible port scan from {source_ip} targeting {len(ports)} different ports'
					})
		except Exception as e:
			current_app.logger.error(f"Error detecting port scans: {e}")
		
		return anomalies
	
	def get_top_sources(self, start_time, end_time):
		"""获取访问量最大的源IP"""
		try:
			# 按源IP统计
			source_counts = db.session.query(
				FirewallLog.source_ip,
				db.func.count(FirewallLog.id).label('count')
			).filter(
				FirewallLog.timestamp.between(start_time, end_time),
				FirewallLog.source_ip != None
			).group_by(FirewallLog.source_ip).order_by(
				db.func.count(FirewallLog.id).desc()
			).limit(20).all()
			
			return [{'source_ip': source_ip, 'count': count} for source_ip, count in source_counts]
		except Exception as e:
			current_app.logger.error(f"Error getting top sources: {e}")
			return []
	
	def get_top_destinations(self, start_time, end_time):
		"""获取访问量最大的目标IP"""
		try:
			# 按目标IP统计
			destination_counts = db.session.query(
				FirewallLog.destination_ip,
				db.func.count(FirewallLog.id).label('count')
			).filter(
				FirewallLog.timestamp.between(start_time, end_time),
				FirewallLog.destination_ip != None
			).group_by(FirewallLog.destination_ip).order_by(
				db.func.count(FirewallLog.id).desc()
			).limit(20).all()
			
			return [{'destination_ip': destination_ip, 'count': count} for destination_ip, count in destination_counts]
		except Exception as e:
			current_app.logger.error(f"Error getting top destinations: {e}")
			return []
	
	def generate_alerts(self):
		"""生成告警"""
		# 检查最近1小时的异常
		end_time = datetime.utcnow()
		start_time = end_time - timedelta(hours=1)
		
		anomalies = self.detect_anomalies(start_time, end_time)
		
		# 处理告警
		for anomaly in anomalies:
			# 查找匹配的告警配置
			alert_configs = AlertConfig.query.filter_by(enabled=True).all()
			
			for config in alert_configs:
				if config.condition_type == 'rate_limit' and anomaly['type'] == 'rate_limit':
					self._process_alert(config, anomaly)
				elif config.condition_type == 'pattern_match' and anomaly['type'] == 'pattern_match':
					self._process_alert(config, anomaly)
				elif config.condition_type == 'any' and anomaly['type'] == 'port_scan':
					self._process_alert(config, anomaly)
		
		return len(anomalies)
	
	def _process_alert(self, config, anomaly):
		"""处理告警"""
		try:
			if config.action == 'email':
				# 发送邮件告警
				action_config = json.loads(config.action_config)
				recipient = action_config.get('recipient')
				
				if recipient:
					self._send_email_alert(recipient, anomaly)
			
			elif config.action == 'webhook':
				# 发送webhook告警
				action_config = json.loads(config.action_config)
				webhook_url = action_config.get('url')
				
				if webhook_url:
					self._send_webhook_alert(webhook_url, anomaly)
			
			elif config.action == 'log':
				# 仅记录日志
				current_app.logger.warning(f"Alert generated: {anomaly['description']}")
		
		except Exception as e:
			current_app.logger.error(f"Error processing alert: {e}")
	
	def _send_email_alert(self, recipient, anomaly):
		"""发送邮件告警"""
		try:
			from flask_mail import Mail, Message
			
			# 获取邮件配置
			mail_settings = {
				'MAIL_SERVER': current_app.config.get('MAIL_SERVER', 'smtp.gmail.com'),
				'MAIL_PORT': current_app.config.get('MAIL_PORT', 587),
				'MAIL_USE_TLS': current_app.config.get('MAIL_USE_TLS', True),
				'MAIL_USE_SSL': current_app.config.get('MAIL_USE_SSL', False),
				'MAIL_USERNAME': current_app.config.get('MAIL_USERNAME', ''),
				'MAIL_PASSWORD': current_app.config.get('MAIL_PASSWORD', ''),
				'MAIL_DEFAULT_SENDER': current_app.config.get('MAIL_DEFAULT_SENDER', '')
			}
			
			# 检查邮件配置是否完整
			if not mail_settings['MAIL_USERNAME'] or not mail_settings['MAIL_PASSWORD']:
				current_app.logger.warning(f"邮件配置不完整，无法发送告警邮件到 {recipient}")
				return False
			
			# 应用邮件配置
			for key, value in mail_settings.items():
				current_app.config[key] = value
			
			# 初始化Mail对象
			mail = Mail(current_app)
			
			# 构建邮件内容
			subject = f"防火墙告警: {anomaly.get('type', '未知类型')}"
			
			# 构建HTML邮件正文
			html_body = f"""
	        <html>
	        <head>
	            <style>
	                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
	                .container {{ padding: 20px; }}
	                .header {{ background-color: #f44336; color: white; padding: 10px; }}
	                .content {{ padding: 15px; border: 1px solid #ddd; }}
	                .footer {{ font-size: 12px; color: #777; margin-top: 20px; }}
	                table {{ border-collapse: collapse; width: 100%; }}
	                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
	                th {{ background-color: #f2f2f2; }}
	            </style>
	        </head>
	        <body>
	            <div class="container">
	                <div class="header">
	                    <h2>防火墙安全告警</h2>
	                </div>
	                <div class="content">
	                    <p><strong>告警时间:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
	                    <p><strong>告警类型:</strong> {anomaly.get('type', '未知类型')}</p>
	                    <p><strong>告警描述:</strong> {anomaly.get('description', '无描述')}</p>

	                    <h3>详细信息:</h3>
	                    <table>
	                        <tr>
	                            <th>属性</th>
	                            <th>值</th>
	                        </tr>
	        """
			
			# 添加所有异常详情到表格
			for key, value in anomaly.items():
				if key not in ['type', 'description']:
					html_body += f"""
	                        <tr>
	                            <td>{key}</td>
	                            <td>{value}</td>
	                        </tr>
	                """
			
			# 完成HTML邮件
			html_body += """
	                    </table>

	                    <p>请登录防火墙管理系统查看更多详情并采取必要的安全措施。</p>
	                </div>
	                <div class="footer">
	                    <p>此邮件由防火墙管理系统自动发送，请勿直接回复。</p>
	                </div>
	            </div>
	        </body>
	        </html>
	        """
			
			# 创建邮件消息
			msg = Message(
				subject=subject,
				recipients=[recipient],
				html=html_body
			)
			
			# 发送邮件
			mail.send(msg)
			
			current_app.logger.info(f"成功发送告警邮件到 {recipient}")
			return True
		
		except ImportError:
			current_app.logger.error("未安装Flask-Mail，无法发送邮件")
			return False
		except Exception as e:
			current_app.logger.error(f"发送邮件告警失败: {str(e)}")
			return False
	
	def _send_webhook_alert(self, webhook_url, anomaly):
		"""发送webhook告警"""
		try:
			import requests
			
			payload = {
				'alert_type': anomaly['type'],
				'description': anomaly['description'],
				'details': anomaly,
				'timestamp': datetime.utcnow().isoformat()
			}
			
			response = requests.post(webhook_url, json=payload, timeout=5)
			
			if response.status_code >= 200 and response.status_code < 300:
				current_app.logger.info(f"Successfully sent webhook alert to {webhook_url}")
			else:
				current_app.logger.warning(f"Failed to send webhook alert: {response.status_code} {response.text}")
		
		except Exception as e:
			current_app.logger.error(f"Error sending webhook alert: {e}")
