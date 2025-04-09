# models/status.py
from datetime import datetime
from models import db


class FirewallStatus(db.Model):
	__tablename__ = 'firewall_status'
	
	id = db.Column(db.Integer, primary_key=True)
	service_name = db.Column(db.String(50))  # iptables 或 nftables
	status = db.Column(db.Boolean)
	last_checked = db.Column(db.DateTime, default=datetime.utcnow)
	
	def to_dict(self):
		return {
			'id': self.id,
			'service_name': self.service_name,
			'status': self.status,
			'last_checked': self.last_checked.isoformat() if self.last_checked else None
		}


class ConnectionStat(db.Model):
	__tablename__ = 'connection_stats'
	
	id = db.Column(db.Integer, primary_key=True)
	timestamp = db.Column(db.DateTime, default=datetime.utcnow)
	total_connections = db.Column(db.Integer)
	established = db.Column(db.Integer)
	time_wait = db.Column(db.Integer)
	close_wait = db.Column(db.Integer)
	syn_sent = db.Column(db.Integer)
	udp_connections = db.Column(db.Integer)
	
	def to_dict(self):
		return {
			'id': self.id,
			'timestamp': self.timestamp.isoformat() if self.timestamp else None,
			'total_connections': self.total_connections,
			'established': self.established,
			'time_wait': self.time_wait,
			'close_wait': self.close_wait,
			'syn_sent': self.syn_sent,
			'udp_connections': self.udp_connections
		}
