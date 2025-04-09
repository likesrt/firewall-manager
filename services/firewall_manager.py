# services/firewall_manager.py
import subprocess
import re
import json
from models import db, FirewallRule
from flask import current_app
import tempfile
import os


class FirewallManager:
	def __init__(self):
		self.iptables_path = current_app.config.get('IPTABLES_PATH', '/sbin/iptables')
		self.nftables_path = current_app.config.get('NFTABLES_PATH', '/sbin/nft')
	
	def apply_iptables_rule(self, rule):
		"""应用iptables规则"""
		if not rule.enabled:
			return True
		
		# 生成iptables命令
		cmd = [self.iptables_path]
		cmd.extend(rule.to_iptables_command())
		
		# 执行命令
		try:
			result = subprocess.run(cmd, check=True, capture_output=True, text=True)
			return True
		except subprocess.CalledProcessError as e:
			current_app.logger.error(f"Error applying iptables rule: {e.stderr}")
			raise Exception(f"Failed to apply iptables rule: {e.stderr}")
	
	def apply_nftables_rule(self, rule):
		"""应用nftables规则"""
		if not rule.enabled:
			return True
		
		# 生成nftables命令
		cmd_str = rule.to_nftables_command()
		
		# 执行命令
		try:
			result = subprocess.run([self.nftables_path, '-c', cmd_str], check=True, capture_output=True, text=True)
			return True
		except subprocess.CalledProcessError as e:
			current_app.logger.error(f"Error applying nftables rule: {e.stderr}")
			raise Exception(f"Failed to apply nftables rule: {e.stderr}")
	
	def remove_iptables_rule(self, rule):
		"""从iptables移除规则"""
		# 复制规则命令，但将-A替换为-D
		cmd = [self.iptables_path]
		iptables_cmd = rule.to_iptables_command()
		if iptables_cmd[0] == '-A':
			iptables_cmd[0] = '-D'
		cmd.extend(iptables_cmd)
		
		try:
			result = subprocess.run(cmd, check=True, capture_output=True, text=True)
			return True
		except subprocess.CalledProcessError as e:
			current_app.logger.error(f"Error removing iptables rule: {e.stderr}")
			raise Exception(f"Failed to remove iptables rule: {e.stderr}")
	
	def remove_nftables_rule(self, rule):
		"""从nftables移除规则"""
		# 为了移除nftables规则，我们需要找到规则的句柄
		table = 'filter'
		
		# 获取规则列表
		try:
			# 获取规则句柄
			list_cmd = f"list table {table}"
			result = subprocess.run([self.nftables_path, '-j', list_cmd], check=True, capture_output=True, text=True)
			rules_json = json.loads(result.stdout)
			
			# 查找匹配的规则并删除
			# 这里需要根据实际情况进行匹配，这只是一个简化的示例
			rule_handle = self._find_nftables_rule_handle(rules_json, rule)
			
			if rule_handle:
				delete_cmd = f"delete rule {table} {rule.chain} handle {rule_handle}"
				result = subprocess.run([self.nftables_path, delete_cmd], check=True, capture_output=True, text=True)
				return True
			else:
				current_app.logger.warning(f"Rule not found in nftables: {rule.id}")
				return False
		
		except subprocess.CalledProcessError as e:
			current_app.logger.error(f"Error removing nftables rule: {e.stderr}")
			raise Exception(f"Failed to remove nftables rule: {e.stderr}")
	
	def _find_nftables_rule_handle(self, rules_json, rule):
		"""在nftables JSON输出中查找匹配规则的句柄"""
		# 这是一个简化的实现，实际情况可能需要更复杂的匹配逻辑
		if 'nftables' not in rules_json:
			return None
		
		for item in rules_json['nftables']:
			if 'rule' in item:
				rule_data = item['rule']
				if rule_data.get('chain') == rule.chain:
					# 这里需要根据规则的具体内容进行匹配
					# 简化示例：仅检查协议、源IP和目标IP
					expr = rule_data.get('expr', [])
					matches = 0
					needed_matches = 0
					
					if rule.protocol and rule.protocol != 'all':
						needed_matches += 1
						for e in expr:
							if e.get('match', {}).get('left', {}).get('payload', {}).get('protocol') == rule.protocol:
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
						return rule_data.get('handle')
		
		return None
	
	def sync_from_server(self):
		"""从服务器同步现有规则"""
		synced_rules = []
		
		# 同步iptables规则
		iptables_rules = self._get_iptables_rules()
		for rule_data in iptables_rules:
			rule = self._create_or_update_rule('iptables', rule_data)
			if rule:
				synced_rules.append(rule)
		
		# 同步nftables规则
		nftables_rules = self._get_nftables_rules()
		for rule_data in nftables_rules:
			rule = self._create_or_update_rule('nftables', rule_data)
			if rule:
				synced_rules.append(rule)
		
		return synced_rules
	
	def _get_iptables_rules(self):
		"""获取服务器上的iptables规则"""
		rules = []
		
		try:
			# 获取iptables规则列表
			result = subprocess.run([self.iptables_path, '-S'], check=True, capture_output=True, text=True)
			lines = result.stdout.strip().split('\n')
			
			for line in lines:
				if line.startswith('-A'):  # 只处理添加规则的命令
					parts = line.split()
					rule_data = {
						'chain': parts[1] if len(parts) > 1 else None,
						'protocol': None,
						'source': None,
						'destination': None,
						'port': None,
						'action': None,
						'comment': None
					}
					
					# 解析规则参数
					i = 2
					while i < len(parts):
						if parts[i] == '-p' and i + 1 < len(parts):
							rule_data['protocol'] = parts[i + 1]
							i += 2
						elif parts[i] == '-s' and i + 1 < len(parts):
							rule_data['source'] = parts[i + 1]
							i += 2
						elif parts[i] == '-d' and i + 1 < len(parts):
							rule_data['destination'] = parts[i + 1]
							i += 2
						elif parts[i] == '--dport' and i + 1 < len(parts):
							rule_data['port'] = parts[i + 1]
							i += 2
						elif parts[i] == '-j' and i + 1 < len(parts):
							rule_data['action'] = parts[i + 1]
							i += 2
						elif parts[i] == '-m' and i + 1 < len(parts) and parts[i + 1] == 'comment' and i + 3 < len(
								parts) and parts[i + 2] == '--comment':
							rule_data['comment'] = parts[i + 3].strip('"\'')
							i += 4
						else:
							i += 1
					
					rules.append(rule_data)
			
			return rules
		except subprocess.CalledProcessError as e:
			current_app.logger.error(f"Error getting iptables rules: {e.stderr}")
			return []
	
	def _get_nftables_rules(self):
		"""获取服务器上的nftables规则"""
		rules = []
		
		try:
			# 获取nftables规则列表
			result = subprocess.run([self.nftables_path, '-j', 'list', 'ruleset'], check=True, capture_output=True,
			                        text=True)
			rules_json = json.loads(result.stdout)
			
			if 'nftables' in rules_json:
				for item in rules_json['nftables']:
					if 'rule' in item:
						rule_data = {
							'chain': item['rule'].get('chain'),
							'protocol': None,
							'source': None,
							'destination': None,
							'port': None,
							'action': None,
							'comment': None
						}
						
						# 解析表达式
						for expr in item['rule'].get('expr', []):
							# 解析协议
							if 'match' in expr and 'left' in expr['match'] and 'payload' in expr['match']['left']:
								payload = expr['match']['left']['payload']
								if payload.get('protocol') in ['tcp', 'udp', 'icmp']:
									rule_data['protocol'] = payload.get('protocol')
							
							# 解析源IP
							if 'match' in expr and 'left' in expr['match'] and 'payload' in expr['match']['left']:
								payload = expr['match']['left']['payload']
								if payload.get('field') == 'saddr' and 'right' in expr['match']:
									rule_data['source'] = expr['match']['right']
							
							# 解析目标IP
							if 'match' in expr and 'left' in expr['match'] and 'payload' in expr['match']['left']:
								payload = expr['match']['left']['payload']
								if payload.get('field') == 'daddr' and 'right' in expr['match']:
									rule_data['destination'] = expr['match']['right']
							
							# 解析端口
							if 'match' in expr and 'left' in expr['match'] and 'payload' in expr['match']['left']:
								payload = expr['match']['left']['payload']
								if payload.get('field') == 'dport' and 'right' in expr['match']:
									rule_data['port'] = str(expr['match']['right'])
							
							# 解析动作
							if expr.get('accept') is not None:
								rule_data['action'] = 'ACCEPT'
							elif expr.get('drop') is not None:
								rule_data['action'] = 'DROP'
							elif expr.get('reject') is not None:
								rule_data['action'] = 'REJECT'
							elif expr.get('log') is not None:
								rule_data['action'] = 'LOG'
							
							# 解析注释
							if expr.get('comment') is not None:
								rule_data['comment'] = expr['comment']
						
						rules.append(rule_data)
			
			return rules
		except subprocess.CalledProcessError as e:
			current_app.logger.error(f"Error getting nftables rules: {e.stderr}")
			return []
		except json.JSONDecodeError as e:
			current_app.logger.error(f"Error parsing nftables JSON: {e}")
			return []
	
	def _create_or_update_rule(self, rule_type, rule_data):
		"""创建或更新规则"""
		# 尝试查找匹配的现有规则
		existing_rule = FirewallRule.query.filter_by(
			rule_type=rule_type,
			chain=rule_data['chain'],
			protocol=rule_data['protocol'],
			source=rule_data['source'],
			destination=rule_data['destination'],
			port=rule_data['port'],
			action=rule_data['action']
		).first()
		
		if existing_rule:
			# 更新现有规则
			if rule_data['comment']:
				existing_rule.comment = rule_data['comment']
			db.session.commit()
			return existing_rule
		else:
			# 创建新规则
			new_rule = FirewallRule(
				rule_type=rule_type,
				chain=rule_data['chain'],
				protocol=rule_data['protocol'] or 'all',
				source=rule_data['source'] or 'any',
				destination=rule_data['destination'] or 'any',
				port=rule_data['port'] or 'any',
				action=rule_data['action'],
				comment=rule_data['comment'] or '',
				priority=100,  # 默认优先级
				enabled=True
			)
			db.session.add(new_rule)
			db.session.commit()
			return new_rule
	
	def import_rules_from_data(self, rules_data):
		"""从数据导入规则"""
		imported_rules = []
		
		for rule_data in rules_data:
			# 检查必填字段
			required_fields = ['rule_type', 'chain', 'action']
			if all(field in rule_data for field in required_fields):
				# 创建规则对象
				rule = FirewallRule(
					rule_type=rule_data['rule_type'],
					chain=rule_data['chain'],
					protocol=rule_data.get('protocol', 'all'),
					source=rule_data.get('source', 'any'),
					destination=rule_data.get('destination', 'any'),
					port=rule_data.get('port', 'any'),
					action=rule_data['action'],
					comment=rule_data.get('comment', ''),
					priority=rule_data.get('priority', 100),
					enabled=rule_data.get('enabled', True)
				)
				
				# 保存到数据库
				db.session.add(rule)
				db.session.commit()
				
				# 应用规则
				try:
					if rule.rule_type == 'iptables':
						self.apply_iptables_rule(rule)
					else:
						self.apply_nftables_rule(rule)
					
					imported_rules.append(rule)
				except Exception as e:
					current_app.logger.error(f"Error applying imported rule: {e}")
					db.session.delete(rule)
					db.session.commit()
		
		return imported_rules
	
	def import_rules_from_file(self, file_path):
		"""从文件导入规则"""
		try:
			with open(file_path, 'r') as f:
				rules_data = json.load(f)
			
			return self.import_rules_from_data(rules_data)
		except Exception as e:
			current_app.logger.error(f"Error importing rules from file: {e}")
			raise
	
	def export_rules_to_file(self, file_path, rule_type='all'):
		"""导出规则到文件"""
		try:
			# 根据类型筛选规则
			if rule_type != 'all':
				rules = FirewallRule.query.filter_by(rule_type=rule_type).all()
			else:
				rules = FirewallRule.query.all()
			
			# 导出为JSON
			rules_data = [rule.to_dict() for rule in rules]
			
			with open(file_path, 'w') as f:
				json.dump(rules_data, f, indent=2)
			
			return len(rules_data)
		except Exception as e:
			current_app.logger.error(f"Error exporting rules to file: {e}")
			raise
