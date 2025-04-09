# routes/rules.py
from flask import Blueprint, request, jsonify, current_app
from flask_restful import Api, Resource
from models import db, FirewallRule, RuleTemplate
from services.firewall_manager import FirewallManager
from utils.security import require_api_key
import json

rules_bp = Blueprint('rules', __name__)
api = Api(rules_bp)


class RuleList(Resource):
	@require_api_key
	def get(self):
		"""获取所有防火墙规则"""
		rules = FirewallRule.query.order_by(FirewallRule.priority).all()
		return jsonify({
			'success': True,
			'data': [rule.to_dict() for rule in rules]
		})
	
	@require_api_key
	def post(self):
		"""创建新规则"""
		data = request.get_json()
		
		# 验证必填字段
		required_fields = ['rule_type', 'chain', 'action']
		for field in required_fields:
			if field not in data:
				return jsonify({
					'success': False,
					'message': f'Missing required field: {field}'
				}), 400
		
		# 创建规则对象
		rule = FirewallRule(
			rule_type=data.get('rule_type'),
			chain=data.get('chain'),
			protocol=data.get('protocol', 'all'),
			source=data.get('source', 'any'),
			destination=data.get('destination', 'any'),
			port=data.get('port', 'any'),
			action=data.get('action'),
			comment=data.get('comment', ''),
			priority=data.get('priority', 100),
			enabled=data.get('enabled', True)
		)
		
		# 保存到数据库
		db.session.add(rule)
		db.session.commit()
		
		# 应用规则
		try:
			firewall_manager = FirewallManager()
			if rule.rule_type == 'iptables':
				firewall_manager.apply_iptables_rule(rule)
			else:
				firewall_manager.apply_nftables_rule(rule)
			
			return jsonify({
				'success': True,
				'message': 'Rule created successfully',
				'data': rule.to_dict()
			})
		except Exception as e:
			# 如果应用规则失败，回滚数据库
			db.session.delete(rule)
			db.session.commit()
			
			return jsonify({
				'success': False,
				'message': f'Failed to apply rule: {str(e)}'
			}), 500


class RuleDetail(Resource):
	@require_api_key
	def get(self, rule_id):
		"""获取单个规则详情"""
		rule = FirewallRule.query.get_or_404(rule_id)
		return jsonify({
			'success': True,
			'data': rule.to_dict()
		})
	
	@require_api_key
	def put(self, rule_id):
		"""更新规则"""
		rule = FirewallRule.query.get_or_404(rule_id)
		data = request.get_json()
		
		# 更新规则字段
		for field in ['rule_type', 'chain', 'protocol', 'source',
		              'destination', 'port', 'action', 'comment',
		              'priority', 'enabled']:
			if field in data:
				setattr(rule, field, data[field])
		
		# 保存更新
		db.session.commit()
		
		# 应用更新后的规则
		try:
			firewall_manager = FirewallManager()
			if rule.rule_type == 'iptables':
				firewall_manager.apply_iptables_rule(rule)
			else:
				firewall_manager.apply_nftables_rule(rule)
			
			return jsonify({
				'success': True,
				'message': 'Rule updated successfully',
				'data': rule.to_dict()
			})
		except Exception as e:
			return jsonify({
				'success': False,
				'message': f'Failed to apply updated rule: {str(e)}'
			}), 500
	
	@require_api_key
	def delete(self, rule_id):
		"""删除规则"""
		rule = FirewallRule.query.get_or_404(rule_id)
		
		# 删除规则前先从防火墙中移除
		try:
			firewall_manager = FirewallManager()
			if rule.rule_type == 'iptables':
				firewall_manager.remove_iptables_rule(rule)
			else:
				firewall_manager.remove_nftables_rule(rule)
			
			# 从数据库删除
			db.session.delete(rule)
			db.session.commit()
			
			return jsonify({
				'success': True,
				'message': 'Rule deleted successfully'
			})
		except Exception as e:
			return jsonify({
				'success': False,
				'message': f'Failed to delete rule: {str(e)}'
			}), 500


class RuleImport(Resource):
	@require_api_key
	def post(self):
		"""导入规则"""
		if 'file' not in request.files:
			return jsonify({
				'success': False,
				'message': 'No file part'
			}), 400
		
		file = request.files['file']
		if file.filename == '':
			return jsonify({
				'success': False,
				'message': 'No selected file'
			}), 400
		
		try:
			# 读取文件内容
			content = file.read().decode('utf-8')
			rules_data = json.loads(content)
			
			# 导入规则
			firewall_manager = FirewallManager()
			imported_rules = firewall_manager.import_rules_from_data(rules_data)
			
			return jsonify({
				'success': True,
				'message': f'Successfully imported {len(imported_rules)} rules',
				'data': [rule.to_dict() for rule in imported_rules]
			})
		except Exception as e:
			return jsonify({
				'success': False,
				'message': f'Failed to import rules: {str(e)}'
			}), 500


class RuleExport(Resource):
	@require_api_key
	def get(self):
		"""导出规则"""
		rule_type = request.args.get('type', 'all')
		
		# 根据类型筛选规则
		if rule_type != 'all':
			rules = FirewallRule.query.filter_by(rule_type=rule_type).all()
		else:
			rules = FirewallRule.query.all()
		
		# 导出为JSON
		rules_data = [rule.to_dict() for rule in rules]
		
		return jsonify({
			'success': True,
			'data': rules_data
		})


class RuleSync(Resource):
	@require_api_key
	def post(self):
		"""同步服务器现有规则"""
		try:
			firewall_manager = FirewallManager()
			synced_rules = firewall_manager.sync_from_server()
			
			return jsonify({
				'success': True,
				'message': f'Successfully synced {len(synced_rules)} rules',
				'data': [rule.to_dict() for rule in synced_rules]
			})
		except Exception as e:
			return jsonify({
				'success': False,
				'message': f'Failed to sync rules: {str(e)}'
			}), 500


class RuleTemplateList(Resource):
	@require_api_key
	def get(self):
		"""获取所有规则模板"""
		templates = RuleTemplate.query.all()
		return jsonify({
			'success': True,
			'data': [template.to_dict() for template in templates]
		})
	
	@require_api_key
	def post(self):
		"""创建新规则模板"""
		data = request.get_json()
		
		# 验证必填字段
		if 'name' not in data or 'rule_json' not in data:
			return jsonify({
				'success': False,
				'message': 'Missing required fields: name or rule_json'
			}), 400
		
		# 检查名称是否已存在
		if RuleTemplate.query.filter_by(name=data['name']).first():
			return jsonify({
				'success': False,
				'message': 'Template name already exists'
			}), 400
		
		# 创建模板
		template = RuleTemplate(
			name=data['name'],
			description=data.get('description', ''),
			rule_json=data['rule_json']
		)
		
		db.session.add(template)
		db.session.commit()
		
		return jsonify({
			'success': True,
			'message': 'Template created successfully',
			'data': template.to_dict()
		})


class RuleTemplateDetail(Resource):
	@require_api_key
	def get(self, template_id):
		"""获取单个模板详情"""
		template = RuleTemplate.query.get_or_404(template_id)
		return jsonify({
			'success': True,
			'data': template.to_dict()
		})
	
	@require_api_key
	def put(self, template_id):
		"""更新模板"""
		template = RuleTemplate.query.get_or_404(template_id)
		data = request.get_json()
		
		# 更新字段
		if 'name' in data:
			template.name = data['name']
		if 'description' in data:
			template.description = data['description']
		if 'rule_json' in data:
			template.rule_json = data['rule_json']
		
		db.session.commit()
		
		return jsonify({
			'success': True,
			'message': 'Template updated successfully',
			'data': template.to_dict()
		})
	
	@require_api_key
	def delete(self, template_id):
		"""删除模板"""
		template = RuleTemplate.query.get_or_404(template_id)
		db.session.delete(template)
		db.session.commit()
		
		return jsonify({
			'success': True,
			'message': 'Template deleted successfully'
		})


# 注册API资源
api.add_resource(RuleList, '')
api.add_resource(RuleDetail, '/<int:rule_id>')
api.add_resource(RuleImport, '/import')
api.add_resource(RuleExport, '/export')
api.add_resource(RuleSync, '/sync')
api.add_resource(RuleTemplateList, '/templates')
api.add_resource(RuleTemplateDetail, '/templates/<int:template_id>')
