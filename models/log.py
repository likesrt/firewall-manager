# models/log.py
from datetime import datetime
from models import db


class FirewallLog(db.Model):
	__tablename__ = 'firewall_logs'
	
	id = db.Column(db.Integer, primary_key=True)
	timestamp = db.Column(db.DateTime)
	source_ip = db.Column(db.String(50))
	destination_ip = db.Column(db.String(50))
	protocol = db.Column(db.String(10))
	action = db.Column(db.String(20))
	chain = db.Column(db.String(50))
	interface = db.Column(db.String(20))
	raw_log = db.Column(db.Text)
	processed_at = db.Column(db.DateTime, default=datetime.utcnow)
	
	def to_dict(self):
		return {
			'id': self.id,
			'timestamp': self.timestamp.isoformat() if self.timestamp else None,
			'source_ip': self.source_ip,
			'destination_ip': self.destination_ip,
			'protocol': self.protocol,
			'action': self.action,
			'chain': self.chain,
			'interface': self.interface,
			'raw_log': self.raw_log,
			'processed_at': self.processed_at.isoformat() if self.processed_at else None
		}


class AlertConfig(db.Model):
	__tablename__ = 'alert_configs'
	
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(100))
	description = db.Column(db.String(255))
	condition_type = db.Column(db.String(50))  # 如：rate_limit, pattern_match
	condition_value = db.Column(db.String(255))  # 条件值，如阈值或正则表达式
	action = db.Column(db.String(50))  # 如：email, webhook
	action_config = db.Column(db.Text)  # JSON配置
	enabled = db.Column(db.Boolean, default=True)
	created_at = db.Column(db.DateTime, default=datetime.utcnow)
	updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
	
	def to_dict(self):
		return {
			'id': self.id,
			'name': self.name,
			'description': self.description,
			'condition_type': self.condition_type,
			'condition_value': self.condition_value,
			'action': self.action,
			'action_config': self.action_config,
			'enabled': self.enabled,
			'created_at': self.created_at.isoformat() if self.created_at else None,
			'updated_at': self.updated_at.isoformat() if self.updated_at else None
		}
