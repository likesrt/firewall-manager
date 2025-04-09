# models/setting.py
from datetime import datetime
from models import db


class SystemSetting(db.Model):
	__tablename__ = 'system_settings'
	
	id = db.Column(db.Integer, primary_key=True)
	key = db.Column(db.String(50), unique=True)
	value = db.Column(db.String(255))
	description = db.Column(db.String(255))
	updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
	
	def to_dict(self):
		return {
			'id': self.id,
			'key': self.key,
			'value': self.value,
			'description': self.description,
			'updated_at': self.updated_at.isoformat() if self.updated_at else None
		}


class SystemBackup(db.Model):
	__tablename__ = 'system_backups'
	
	id = db.Column(db.Integer, primary_key=True)
	filename = db.Column(db.String(255))
	description = db.Column(db.String(255))
	size = db.Column(db.Integer)  # 文件大小（字节）
	created_at = db.Column(db.DateTime, default=datetime.utcnow)
	
	def to_dict(self):
		return {
			'id': self.id,
			'filename': self.filename,
			'description': self.description,
			'size': self.size,
			'created_at': self.created_at.isoformat() if self.created_at else None
		}
