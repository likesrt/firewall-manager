# services/status_monitor.py
import subprocess
import re
import time
import threading
from datetime import datetime
from models import db, FirewallStatus, ConnectionStat, FirewallRule
from flask import current_app


class FirewallMonitor:
	def __init__(self, socketio=None):
		self.socketio = socketio
		self.iptables_path = current_app.config.get('IPTABLES_PATH', '/sbin/iptables')
		self.nftables_path = current_app.config.get('NFTABLES_PATH', '/sbin/nft')
		self.monitor_interval = current_app.config.get('MONITOR_INTERVAL', 30)
		self.running = False
	
	def check_status(self):
		"""检查防火墙服务状态"""
		# 检查iptables状态
		iptables_status = self._check_iptables_status()
		
		# 检查nftables状态
		nftables_status = self._check_nftables_status()
		
		# 保存状态到数据库
		now = datetime.utcnow()
		
		iptables_record = FirewallStatus(
			service_name='iptables',
			status=iptables_status,
			last_checked=now
		)
		
		nftables_record = FirewallStatus(
			service_name='nftables',
			status=nftables_status,
			last_checked=now
		)
		
		db.session.add(iptables_record)
		db.session.add(nftables_record)
		db.session.commit()
		
		# 如果有socketio，广播状态更新
		if self.socketio:
			self.broadcast_status_update({
				'iptables': iptables_record.to_dict(),
				'nftables': nftables_record.to_dict()
			})
		
		return {
			'iptables': iptables_status,
			'nftables': nftables_status
		}
	
	def _check_iptables_status(self):
		"""检查iptables状态"""
		try:
			# 尝试列出iptables规则
			result = subprocess.run([self.iptables_path, '-L'], check=False, capture_output=True, text=True)
			
			# 如果命令成功执行并且输出中包含规则链，则认为服务正常
			return result.returncode == 0 and 'Chain' in result.stdout
		except Exception as e:
			current_app.logger.error(f"Error checking iptables status: {e}")
			return False
	
	def _check_nftables_status(self):
		"""检查nftables状态"""
		try:
			# 尝试列出nftables规则
			result = subprocess.run([self.nftables_path, 'list', 'ruleset'], check=False, capture_output=True,
			                        text=True)
			
			# 如果命令成功执行，则认为服务正常
			return result.returncode == 0
		except Exception as e:
			current_app.logger.error(f"Error checking nftables status: {e}")
			return False
	
	def get_connection_stats(self):
		"""获取连接跟踪统计"""
		try:
			# 使用conntrack工具获取连接跟踪统计
			result = subprocess.run(['conntrack', '-S'], check=False, capture_output=True, text=True)
			
			if result.returncode != 0:
				current_app.logger.warning(f"conntrack command failed: {result.stderr}")
				return None
			
			# 解析输出
			stats = {
				'total_connections': 0,
				'established': 0,
				'time_wait': 0,
				'close_wait': 0,
				'syn_sent': 0,
				'udp_connections': 0
			}
			
			# 获取总连接数
			total_match = re.search(r'entries=(\d+)', result.stdout)
			if total_match:
				stats['total_connections'] = int(total_match.group(1))
			
			# 获取TCP连接状态统计
			# 使用ss命令获取更详细的连接状态
			ss_result = subprocess.run(['ss', '-tan', 'state', 'all'], check=False, capture_output=True, text=True)
			
			if ss_result.returncode == 0:
				stats['established'] = ss_result.stdout.count('ESTAB')
				stats['time_wait'] = ss_result.stdout.count('TIME-WAIT')
				stats['close_wait'] = ss_result.stdout.count('CLOSE-WAIT')
				stats['syn_sent'] = ss_result.stdout.count('SYN-SENT')
			
			# 获取UDP连接数
			udp_result = subprocess.run(['ss', '-uan'], check=False, capture_output=True, text=True)
			if udp_result.returncode == 0:
				# 计算UDP连接数（减去标题行）
				udp_lines = udp_result.stdout.strip().split('\n')
				stats['udp_connections'] = max(0, len(udp_lines) - 1)
			
			# 保存到数据库
			conn_stat = ConnectionStat(
				timestamp=datetime.utcnow(),
				total_connections=stats['total_connections'],
				established=stats['established'],
				time_wait=stats['time_wait'],
				close_wait=stats['close_wait'],
				syn_sent=stats['syn_sent'],
				udp_connections=stats['udp_connections']
			)
			
			db.session.add(conn_stat)
			db.session.commit()
			
			# 如果有socketio，广播连接统计更新
			if self.socketio:
				self.broadcast_connection_update(conn_stat.to_dict())
			
			return conn_stat
		
		except Exception as e:
			current_app.logger.error(f"Error getting connection stats: {e}")
			return None
	
	def verify_rule_effectiveness(self, rule_id):
		"""验证规则是否生效"""
		rule = FirewallRule.query.get_or_404(rule_id)
		
		try:
			if rule.rule_type == 'iptables':
				return self._verify_iptables_rule(rule)
			else:
				return self._verify_nftables_rule(rule)
		except Exception as e:
			current_app.logger.error(f"Error verifying rule effectiveness: {e}")
			raise
	
	def _verify_iptables_rule(self, rule):
		"""验证iptables规则是否生效"""
		# 构建查询命令
		cmd = [self.iptables_path, '-C']
		cmd.extend(rule.to_iptables_command())
		
		try:
			# 尝试检查规则是否存在
			result = subprocess.run(cmd, check=False, capture_output=True, text=True)
			
			# 返回验证结果
			return {
				'rule_id': rule.id,
				'effective': result.returncode == 0,
				'message': 'Rule is active' if result.returncode == 0 else 'Rule is not active',
				'details': result.stderr if result.returncode != 0 else None
			}
		except Exception as e:
			return {
				'rule_id': rule.id,
				'effective': False,
				'message': f'Error verifying rule: {str(e)}',
				'details': None
			}
	
	def _verify_nftables_rule(self, rule):
		"""验证nftables规则是否生效"""
		# 对于nftables，我们需要列出所有规则并检查是否有匹配的
		try:
			# 获取规则列表
			result = subprocess.run([self.nftables_path, '-j', 'list', 'ruleset'], check=True, capture_output=True,
			                        text=True)
			
			# 解析JSON输出
			import json
			rules_json = json.loads(result.stdout)
			
			# 检查是否有匹配的规则
			# 这是一个简化的匹配逻辑，实际情况可能需要更复杂的比较
			found = False
			if 'nftables' in rules_json:
				for item in rules_json['nftables']:
					if 'rule' in item and item['rule'].get('chain') == rule.chain:
						# 简单匹配：检查协议、源IP和目标IP
						expr = item['rule'].get('expr', [])
						matches = 0
						needed_matches = 0
						
						if rule.protocol and rule.protocol != 'all':
							needed_matches += 1
							for e in expr:
								if e.get('match', {}).get('left', {}).get('payload', {}).get(
										'protocol') == rule.protocol:
									matches += 1
									break
						
						if rule.source and rule.source != 'any':
							needed_matches += 1
							for e in expr:
								if e.get('match', {}).get('left', {}).get('payload', {}).get('field') == 'saddr' and \
										e.get('match', {}).get('right') == rule.source:
									matches += 1
									break
						
						if rule.destination and rule.destination != 'any':
							needed_matches += 1
							for e in expr:
								if e.get('match', {}).get('left', {}).get('payload', {}).get('field') == 'daddr' and \
										e.get('match', {}).get('right') == rule.destination:
									matches += 1
									break
						
						if matches == needed_matches:
							found = True
							break
			
			# 返回验证结果
			return {
				'rule_id': rule.id,
				'effective': found,
				'message': 'Rule is active' if found else 'Rule is not active',
				'details': None
			}
		except Exception as e:
			return {
				'rule_id': rule.id,
				'effective': False,
				'message': f'Error verifying rule: {str(e)}',
				'details': None
			}
	
	def control_firewall(self, service, action):
		"""控制防火墙服务"""
		if service == 'iptables':
			return self._control_iptables(action)
		else:
			return self._control_nftables(action)
	
	def _control_iptables(self, action):
		"""控制iptables服务"""
		try:
			if action == 'start':
				# 启动iptables
				result = subprocess.run(['systemctl', 'start', 'iptables'], check=True, capture_output=True, text=True)
			elif action == 'stop':
				# 停止iptables
				result = subprocess.run(['systemctl', 'stop', 'iptables'], check=True, capture_output=True, text=True)
			elif action == 'restart':
				# 重启iptables
				result = subprocess.run(['systemctl', 'restart', 'iptables'], check=True, capture_output=True,
				                        text=True)
			else:
				raise ValueError(f"Invalid action: {action}")
			
			# 检查新状态
			new_status = self._check_iptables_status()
			
			# 保存状态到数据库
			status_record = FirewallStatus(
				service_name='iptables',
				status=new_status,
				last_checked=datetime.utcnow()
			)
			
			db.session.add(status_record)
			db.session.commit()
			
			# 如果有socketio，广播状态更新
			if self.socketio:
				self.broadcast_status_update({
					'iptables': status_record.to_dict()
				})
			
			return {
				'success': True,
				'status': new_status
			}
		except Exception as e:
			current_app.logger.error(f"Error controlling iptables: {e}")
			raise
	
	def _control_nftables(self, action):
		"""控制nftables服务"""
		try:
			if action == 'start':
				# 启动nftables
				result = subprocess.run(['systemctl', 'start', 'nftables'], check=True, capture_output=True, text=True)
			elif action == 'stop':
				# 停止nftables
				result = subprocess.run(['systemctl', 'stop', 'nftables'], check=True, capture_output=True, text=True)
			elif action == 'restart':
				# 重启nftables
				result = subprocess.run(['systemctl', 'restart', 'nftables'], check=True, capture_output=True,
				                        text=True)
			else:
				raise ValueError(f"Invalid action: {action}")
			
			# 检查新状态
			new_status = self._check_nftables_status()
			
			# 保存状态到数据库
			status_record = FirewallStatus(
				service_name='nftables',
				status=new_status,
				last_checked=datetime.utcnow()
			)
			
			db.session.add(status_record)
			db.session.commit()
			
			# 如果有socketio，广播状态更新
			if self.socketio:
				self.broadcast_status_update({
					'nftables': status_record.to_dict()
				})
			
			return {
				'success': True,
				'status': new_status
			}
		except Exception as e:
			current_app.logger.error(f"Error controlling nftables: {e}")
			raise
	
	def start_monitoring(self):
		"""启动定期监控"""
		self.running = True
		
		while self.running:
			try:
				# 检查防火墙状态
				self.check_status()
				
				# 获取连接统计
				self.get_connection_stats()
				
				# 等待下一次检查
				time.sleep(self.monitor_interval)
			except Exception as e:
				current_app.logger.error(f"Error in monitoring loop: {e}")
				time.sleep(self.monitor_interval)
	
	def stop_monitoring(self):
		"""停止监控"""
		self.running = False
	
	def broadcast_status_update(self, status_data):
		"""通过WebSocket广播状态更新"""
		if self.socketio:
			self.socketio.emit('status_update', status_data)
	
	def broadcast_connection_update(self, connection_data):
		"""通过WebSocket广播连接统计更新"""
		if self.socketio:
			self.socketio.emit('connection_update', connection_data)
