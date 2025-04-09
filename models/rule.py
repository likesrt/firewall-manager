# models/rule.py
from datetime import datetime
from models import db


class FirewallRule(db.Model):
	__tablename__ = 'firewall_rules'
	
	id = db.Column(db.Integer, primary_key=True)
	rule_type = db.Column(db.String(10))  # iptables 或 nftables
	chain = db.Column(db.String(50))
	protocol = db.Column(db.String(10))
	source = db.Column(db.String(50))
	destination = db.Column(db.String(50))
	port = db.Column(db.String(50))
	action = db.Column(db.String(20))
	comment = db.Column(db.String(200))
	priority = db.Column(db.Integer)
	enabled = db.Column(db.Boolean, default=True)
	created_at = db.Column(db.DateTime, default=datetime.utcnow)
	updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
	
	def to_dict(self):
		return {
			'id': self.id,
			'rule_type': self.rule_type,
			'chain': self.chain,
			'protocol': self.protocol,
			'source': self.source,
			'destination': self.destination,
			'port': self.port,
			'action': self.action,
			'comment': self.comment,
			'priority': self.priority,
			'enabled': self.enabled,
			'created_at': self.created_at.isoformat() if self.created_at else None,
			'updated_at': self.updated_at.isoformat() if self.updated_at else None
		}
	
	def to_iptables_command(self):
		cmd = ['-A', self.chain]
		
		if self.protocol and self.protocol != 'all':
			cmd.extend(['-p', self.protocol])
		
		if self.source and self.source != 'any':
			cmd.extend(['-s', self.source])
		
		if self.destination and self.destination != 'any':
			cmd.extend(['-d', self.destination])
		
		if self.port and self.port != 'any':
			if '-' in self.port:  # 端口范围
				cmd.extend(['--dport', self.port])
			else:
				cmd.extend(['--dport', self.port])
		
		if self.action:
			cmd.extend(['-j', self.action])
		
		if self.comment:
			cmd.extend(['-m', 'comment', '--comment', f'"{self.comment}"'])
		
		return cmd
	
	def to_nftables_command(self):
		table = 'filter'
		
		# 构建nftables命令
		cmd = f'add rule {table} {self.chain}'
		
		conditions = []
		
		if self.protocol and self.protocol != 'all':
			conditions.append(f'ip protocol {self.protocol}')
		
		if self.source and self.source != 'any':
			conditions.append(f'ip saddr {self.source}')
		
		if self.destination and self.destination != 'any':
			conditions.append(f'ip daddr {self.destination}')
		
		if self.port and self.port != 'any':
			if self.protocol in ['tcp', 'udp']:
				if '-' in self.port:  # 端口范围
					start, end = self.port.split('-')
					conditions.append(f'{self.protocol} dport {{{start}-{end}}}')
				else:
					conditions.append(f'{self.protocol} dport {self.port}')
		
		if conditions:
			cmd += ' ' + ' '.join(conditions)
		
		if self.action:
			action_map = {
				'ACCEPT': 'accept',
				'DROP': 'drop',
				'REJECT': 'reject',
				'LOG': 'log'
			}
			action = action_map.get(self.action, self.action.lower())
			cmd += f' {action}'
		
		if self.comment:
			cmd += f' comment "{self.comment}"'
		
		return cmd


class RuleTemplate(db.Model):
	__tablename__ = 'rule_templates'
	
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(100), unique=True)
	description = db.Column(db.String(255))
	rule_json = db.Column(db.Text)  # 存储规则模板的JSON
	created_at = db.Column(db.DateTime, default=datetime.utcnow)
	
	def to_dict(self):
		return {
			'id': self.id,
			'name': self.name,
			'description': self.description,
			'rule_json': self.rule_json,
			'created_at': self.created_at.isoformat() if self.created_at else None
		}
