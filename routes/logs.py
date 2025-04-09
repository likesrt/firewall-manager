# routes/logs.py
from flask import Blueprint, request, jsonify
from flask_restful import Api, Resource
from models import db, FirewallLog, AlertConfig
from services.log_analyzer import LogCollector, LogAnalyzer
from utils.security import require_api_key
from datetime import datetime, timedelta

logs_bp = Blueprint('logs', __name__)
api = Api(logs_bp)


class LogList(Resource):
	@require_api_key
	def get(self):
		"""获取防火墙日志列表"""
		# 分页参数
		page = request.args.get('page', 1, type=int)
		per_page = request.args.get('per_page', 50, type=int)
		
		# 筛选参数
		source_ip = request.args.get('source_ip')
		destination_ip = request.args.get('destination_ip')
		action = request.args.get('action')
		protocol = request.args.get('protocol')
		start_date = request.args.get('start_date')
		end_date = request.args.get('end_date')
		
		# 构建查询
		query = FirewallLog.query
		
		if source_ip:
			query = query.filter(FirewallLog.source_ip.like(f'%{source_ip}%'))
		if destination_ip:
			query = query.filter(FirewallLog.destination_ip.like(f'%{destination_ip}%'))
		if action:
			query = query.filter(FirewallLog.action == action)
		if protocol:
			query = query.filter(FirewallLog.protocol == protocol)
		
		if start_date:
			try:
				start_datetime = datetime.fromisoformat(start_date)
				query = query.filter(FirewallLog.timestamp >= start_datetime)
			except ValueError:
				pass
		
		if end_date:
			try:
				end_datetime = datetime.fromisoformat(end_date)
				query = query.filter(FirewallLog.timestamp <= end_datetime)
			except ValueError:
				pass
		
		# 排序和分页
		paginated_logs = query.order_by(FirewallLog.timestamp.desc()).paginate(page=page, per_page=per_page)
		
		return jsonify({
			'success': True,
			'data': [log.to_dict() for log in paginated_logs.items],
			'pagination': {
				'total': paginated_logs.total,
				'pages': paginated_logs.pages,
				'current_page': page,
				'per_page': per_page
			}
		})


class LogAnalysis(Resource):
	@require_api_key
	def get(self):
		"""获取日志分析结果"""
		analysis_type = request.args.get('type', 'traffic')
		time_range = request.args.get('time_range', '24h')
		
		# 解析时间范围
		end_time = datetime.utcnow()
		if time_range == '1h':
			start_time = end_time - timedelta(hours=1)
		elif time_range == '6h':
			start_time = end_time - timedelta(hours=6)
		elif time_range == '24h':
			start_time = end_time - timedelta(hours=24)
		elif time_range == '7d':
			start_time = end_time - timedelta(days=7)
		elif time_range == '30d':
			start_time = end_time - timedelta(days=30)
		else:
			start_time = end_time - timedelta(hours=24)  # 默认24小时
		
		# 创建分析器并获取结果
		analyzer = LogAnalyzer()
		
		if analysis_type == 'traffic':
			result = analyzer.analyze_traffic_patterns(start_time, end_time)
		elif analysis_type == 'anomalies':
			result = analyzer.detect_anomalies(start_time, end_time)
		elif analysis_type == 'top_sources':
			result = analyzer.get_top_sources(start_time, end_time)
		elif analysis_type == 'top_destinations':
			result = analyzer.get_top_destinations(start_time, end_time)
		else:
			return jsonify({
				'success': False,
				'message': f'Unknown analysis type: {analysis_type}'
			}), 400
		
		return jsonify({
			'success': True,
			'data': result
		})


class LogCollectorResource(Resource):
	@require_api_key
	def post(self):
		"""手动触发日志收集"""
		try:
			collector = LogCollector()
			count = collector.collect_logs()
			
			return jsonify({
				'success': True,
				'message': f'Successfully collected {count} log entries'
			})
		except Exception as e:
			return jsonify({
				'success': False,
				'message': f'Failed to collect logs: {str(e)}'
			}), 500


class AlertConfigList(Resource):
	@require_api_key
	def get(self):
		"""获取告警配置列表"""
		alerts = AlertConfig.query.all()
		return jsonify({
			'success': True,
			'data': [alert.to_dict() for alert in alerts]
		})
	
	@require_api_key
	def post(self):
		"""创建新告警配置"""
		data = request.get_json()
		
		# 验证必填字段
		required_fields = ['name', 'condition_type', 'condition_value', 'action']
		for field in required_fields:
			if field not in data:
				return jsonify({
					'success': False,
					'message': f'Missing required field: {field}'
				}), 400
		
		# 创建告警配置
		alert = AlertConfig(
			name=data['name'],
			description=data.get('description', ''),
			condition_type=data['condition_type'],
			condition_value=data['condition_value'],
			action=data['action'],
			action_config=data.get('action_config', '{}'),
			enabled=data.get('enabled', True)
		)
		
		db.session.add(alert)
		db.session.commit()
		
		return jsonify({
			'success': True,
			'message': 'Alert configuration created successfully',
			'data': alert.to_dict()
		})


class AlertConfigDetail(Resource):
	@require_api_key
	def get(self, alert_id):
		"""获取单个告警配置详情"""
		alert = AlertConfig.query.get_or_404(alert_id)
		return jsonify({
			'success': True,
			'data': alert.to_dict()
		})
	
	@require_api_key
	def put(self, alert_id):
		"""更新告警配置"""
		alert = AlertConfig.query.get_or_404(alert_id)
		data = request.get_json()
		
		# 更新字段
		for field in ['name', 'description', 'condition_type', 'condition_value',
		              'action', 'action_config', 'enabled']:
			if field in data:
				setattr(alert, field, data[field])
		
		db.session.commit()
		
		return jsonify({
			'success': True,
			'message': 'Alert configuration updated successfully',
			'data': alert.to_dict()
		})
	
	@require_api_key
	def delete(self, alert_id):
		"""删除告警配置"""
		alert = AlertConfig.query.get_or_404(alert_id)
		db.session.delete(alert)
		db.session.commit()
		
		return jsonify({
			'success': True,
			'message': 'Alert configuration deleted successfully'
		})


# 注册API资源
api.add_resource(LogList, '')
api.add_resource(LogAnalysis, '/analysis')
api.add_resource(LogCollectorResource, '/collect')
api.add_resource(AlertConfigList, '/alerts')
api.add_resource(AlertConfigDetail, '/alerts/<int:alert_id>')
