# services/system_manager.py
import os
import shutil
import json
import subprocess
import tempfile
from datetime import datetime
from models import db, SystemSetting, SystemBackup, FirewallRule
from flask import current_app


class SystemManager:
	def backup_system(self, description=None):
		"""创建系统备份"""
		try:
			# 创建备份目录（如果不存在）
			backup_dir = current_app.config.get('BACKUP_DIR')
			os.makedirs(backup_dir, exist_ok=True)
			
			# 创建备份文件名
			timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
			backup_filename = f'firewall_backup_{timestamp}.json'
			backup_path = os.path.join(backup_dir, backup_filename)
			
			# 导出规则
			rules = FirewallRule.query.all()
			rules_data = [rule.to_dict() for rule in rules]
			
			# 导出系统设置
			settings = SystemSetting.query.all()
			settings_data = [setting.to_dict() for setting in settings]
			
			# 创建备份数据
			backup_data = {
				'timestamp': datetime.utcnow().isoformat(),
				'rules': rules_data,
				'settings': settings_data
			}
			
			# 写入备份文件
			with open(backup_path, 'w') as f:
				json.dump(backup_data, f, indent=2)
			
			# 获取文件大小
			file_size = os.path.getsize(backup_path)
			
			# 创建备份记录
			backup = SystemBackup(
				filename=backup_filename,
				description=description or f'Backup created at {datetime.utcnow().isoformat()}',
				size=file_size,
				created_at=datetime.utcnow()
			)
			
			db.session.add(backup)
			db.session.commit()
			
			return backup
		
		except Exception as e:
			current_app.logger.error(f"Error creating backup: {e}")
			raise
	
	def restore_system(self, backup_id):
		"""从备份恢复系统"""
		backup = SystemBackup.query.get_or_404(backup_id)
		
		try:
			# 构建备份文件路径
			backup_path = os.path.join(current_app.config.get('BACKUP_DIR'), backup.filename)
			
			# 检查文件是否存在
			if not os.path.exists(backup_path):
				raise FileNotFoundError(f"Backup file not found: {backup_path}")
			
			# 读取备份数据
			with open(backup_path, 'r') as f:
				backup_data = json.load(f)
			
			# 开始事务
			db.session.begin_nested()
			
			try:
				# 恢复规则前先清除现有规则
				# 1. 从防火墙中移除规则
				firewall_manager = FirewallManager()
				existing_rules = FirewallRule.query.all()
				
				for rule in existing_rules:
					try:
						if rule.rule_type == 'iptables':
							firewall_manager.remove_iptables_rule(rule)
						else:
							firewall_manager.remove_nftables_rule(rule)
					except Exception as e:
						current_app.logger.warning(f"Error removing rule {rule.id}: {e}")
				
				# 2. 从数据库中删除规则
				FirewallRule.query.delete()
				
				# 恢复规则
				restored_rules = []
				for rule_data in backup_data.get('rules', []):
					# 创建规则对象
					rule = FirewallRule(
						rule_type=rule_data.get('rule_type'),
						chain=rule_data.get('chain'),
						protocol=rule_data.get('protocol', 'all'),
						source=rule_data.get('source', 'any'),
						destination=rule_data.get('destination', 'any'),
						port=rule_data.get('port', 'any'),
						action=rule_data.get('action'),
						comment=rule_data.get('comment', ''),
						priority=rule_data.get('priority', 100),
						enabled=rule_data.get('enabled', True)
					)
					
					# 保存到数据库
					db.session.add(rule)
					restored_rules.append(rule)
				
				# 恢复设置
				for setting_data in backup_data.get('settings', []):
					# 查找现有设置
					setting = SystemSetting.query.filter_by(key=setting_data.get('key')).first()
					
					if setting:
						# 更新现有设置
						setting.value = setting_data.get('value')
						setting.description = setting_data.get('description', '')
					else:
						# 创建新设置
						setting = SystemSetting(
							key=setting_data.get('key'),
							value=setting_data.get('value'),
							description=setting_data.get('description', '')
						)
						db.session.add(setting)
				
				# 提交事务
				db.session.commit()
				
				# 应用恢复的规则
				for rule in restored_rules:
					try:
						if rule.enabled:
							if rule.rule_type == 'iptables':
								firewall_manager.apply_iptables_rule(rule)
							else:
								firewall_manager.apply_nftables_rule(rule)
					except Exception as e:
						current_app.logger.warning(f"Error applying restored rule {rule.id}: {e}")
				
				return {
					'success': True,
					'rules_restored': len(restored_rules),
					'settings_restored': len(backup_data.get('settings', []))
				}
			
			except Exception as e:
				# 回滚事务
				db.session.rollback()
				raise
		
		except Exception as e:
			current_app.logger.error(f"Error restoring from backup: {e}")
			raise
	
	def get_system_settings(self):
		"""获取系统设置"""
		settings = SystemSetting.query.all()
		return settings
	
	def update_system_settings(self, settings_data):
		"""更新系统设置"""
		updated_settings = []
		
		for key, value in settings_data.items():
			# 查找现有设置
			setting = SystemSetting.query.filter_by(key=key).first()
			
			if setting:
				# 更新现有设置
				setting.value = value
				updated_settings.append(setting)
			else:
				# 创建新设置
				setting = SystemSetting(
					key=key,
					value=value,
					description=f'Setting for {key}'
				)
				db.session.add(setting)
				updated_settings.append(setting)
		
		db.session.commit()
		return updated_settings
