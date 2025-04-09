# routes/status.py
from flask import Blueprint, request, jsonify
from flask_restful import Api, Resource
from models import db, FirewallStatus, ConnectionStat
from services.status_monitor import FirewallMonitor
from utils.security import require_api_key
from datetime import datetime, timedelta

status_bp = Blueprint('status', __name__)
api = Api(status_bp)


class StatusCheck(Resource):
	@require_api_key
	def get(self):
		"""获取防火墙服务状态"""
		# 获取最新状态
		iptables_status = FirewallStatus.query.filter_by(service_name='iptables').order_by(
			FirewallStatus.last_checked.desc()).first()
		nftables_status = FirewallStatus.query.filter_by(service_name='nftables').order_by(
			FirewallStatus.last_checked.desc()).first()
		
		# 如果没有状态记录或状态过旧，则重新检查
		now = datetime.utcnow()
		threshold = now - timedelta(minutes=5)  # 5分钟阈值
		
		if not iptables_status or iptables_status.last_checked < threshold or not nftables_status or nftables_status.last_checked < threshold:
			monitor = FirewallMonitor()
			monitor.check_status()
			
			# 重新查询最新状态
			iptables_status = FirewallStatus.query.filter_by(service_name='iptables').order_by(
				FirewallStatus.last_checked.desc()).first()
			nftables_status = FirewallStatus.query.filter_by(service_name='nftables').order_by(
				FirewallStatus.last_checked.desc()).first()
		
		return jsonify({
			'success': True,
			'data': {
				'iptables': iptables_status.to_dict() if iptables_status else {'status': False, 'last_checked': None},
				'nftables': nftables_status.to_dict() if nftables_status else {'status': False, 'last_checked': None}
			}
		})


class ConnectionStats(Resource):
	@require_api_key
	def get(self):
		"""获取连接统计数据"""
		# 获取时间范围
		time_range = request.args.get('time_range', '1h')
		
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
		else:
			start_time = end_time - timedelta(hours=1)  # 默认1小时
		
		# 查询连接统计数据
		stats = ConnectionStat.query.filter(
			ConnectionStat.timestamp.between(start_time, end_time)
		).order_by(ConnectionStat.timestamp).all()
		
		# 如果没有数据，则立即收集
		if not stats:
			monitor = FirewallMonitor()
			stat = monitor.get_connection_stats()
			if stat:
				stats = [stat]
		
		return jsonify({
			'success': True,
			'data': [stat.to_dict() for stat in stats]
		})


class RuleVerification(Resource):
	@require_api_key
	def post(self, rule_id):
		"""验证规则是否生效"""
		try:
			monitor = FirewallMonitor()
			result = monitor.verify_rule_effectiveness(rule_id)
			
			return jsonify({
				'success': True,
				'data': result
			})
		except Exception as e:
			return jsonify({
				'success': False,
				'message': f'Failed to verify rule: {str(e)}'
			}), 500


class FirewallControl(Resource):
	@require_api_key
	def post(self):
		"""控制防火墙服务"""
		data = request.get_json()
		
		if 'action' not in data or 'service' not in data:
			return jsonify({
				'success': False,
				'message': 'Missing required fields: action or service'
			}), 400
		
		action = data['action']
		service = data['service']
		
		if action not in ['start', 'stop', 'restart']:
			return jsonify({
				'success': False,
				'message': f'Invalid action: {action}'
			}), 400
		
		if service not in ['iptables', 'nftables']:
			return jsonify({
				'success': False,
				'message': f'Invalid service: {service}'
			}), 400
		
		try:
			monitor = FirewallMonitor()
			result = monitor.control_firewall(service, action)
			
			return jsonify({
				'success': True,
				'message': f'Successfully {action}ed {service}',
				'data': result
			})
		except Exception as e:
			return jsonify({
				'success': False,
				'message': f'Failed to {action} {service}: {str(e)}'
			}), 500


# 注册API资源
api.add_resource(StatusCheck, '')
api.add_resource(ConnectionStats, '/connections')
api.add_resource(RuleVerification, '/verify/<int:rule_id>')
api.add_resource(FirewallControl, '/control')
