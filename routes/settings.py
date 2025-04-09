# routes/settings.py
from flask import Blueprint, request, jsonify, current_app
from flask_restful import Api, Resource
from models import db, SystemSetting, SystemBackup
from services.system_manager import SystemManager
from utils.security import require_api_key
import os

settings_bp = Blueprint('settings', __name__)
api = Api(settings_bp)


class SettingsList(Resource):
	@require_api_key
	def get(self):
		"""获取所有系统设置"""
		settings = SystemSetting.query.all()
		return jsonify({
			'success': True,
			'data': [setting.to_dict() for setting in settings]
		})
	
	@require_api_key
	def post(self):
		"""更新系统设置"""
		data = request.get_json()
		
		if not data or not isinstance(data, dict):
			return jsonify({
				'success': False,
				'message': 'Invalid settings data'
			}), 400
		
		system_manager = SystemManager()
		updated_settings = system_manager.update_system_settings(data)
		
		return jsonify({
			'success': True,
			'message': 'Settings updated successfully',
			'data': [setting.to_dict() for setting in updated_settings]
		})


class BackupList(Resource):
	@require_api_key
	def get(self):
		"""获取所有系统备份"""
		backups = SystemBackup.query.order_by(SystemBackup.created_at.desc()).all()
		return jsonify({
			'success': True,
			'data': [backup.to_dict() for backup in backups]
		})
	
	@require_api_key
	def post(self):
		"""创建新备份"""
		data = request.get_json() or {}
		description = data.get('description', f'Backup created at {datetime.utcnow().isoformat()}')
		
		try:
			system_manager = SystemManager()
			backup = system_manager.backup_system(description)
			
			return jsonify({
				'success': True,
				'message': 'Backup created successfully',
				'data': backup.to_dict()
			})
		except Exception as e:
			return jsonify({
				'success': False,
				'message': f'Failed to create backup: {str(e)}'
			}), 500


class BackupDetail(Resource):
	@require_api_key
	def get(self, backup_id):
		"""获取单个备份详情"""
		backup = SystemBackup.query.get_or_404(backup_id)
		return jsonify({
			'success': True,
			'data': backup.to_dict()
		})
	
	@require_api_key
	def post(self, backup_id):
		"""从备份恢复系统"""
		backup = SystemBackup.query.get_or_404(backup_id)
		
		try:
			system_manager = SystemManager()
			result = system_manager.restore_system(backup_id)
			
			return jsonify({
				'success': True,
				'message': 'System restored successfully',
				'data': result
			})
		except Exception as e:
			return jsonify({
				'success': False,
				'message': f'Failed to restore system: {str(e)}'
			}), 500
	
	@require_api_key
	def delete(self, backup_id):
		"""删除备份"""
		backup = SystemBackup.query.get_or_404(backup_id)
		
		try:
			# 删除备份文件
			backup_path = os.path.join(current_app.config['BACKUP_DIR'], backup.filename)
			if os.path.exists(backup_path):
				os.remove(backup_path)
			
			# 从数据库删除记录
			db.session.delete(backup)
			db.session.commit()
			
			return jsonify({
				'success': True,
				'message': 'Backup deleted successfully'
			})
		except Exception as e:
			return jsonify({
				'success': False,
				'message': f'Failed to delete backup: {str(e)}'
			}), 500


# 注册API资源
api.add_resource(SettingsList, '')
api.add_resource(BackupList, '/backups')
api.add_resource(BackupDetail, '/backups/<int:backup_id>')
