# models/user.py
from datetime import datetime
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from models import db


class User(db.Model):
	__tablename__ = 'users'
	
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(80), unique=True)
	password_hash = db.Column(db.String(128))
	api_key = db.Column(db.String(64), unique=True, default=lambda: str(uuid.uuid4()))
	last_login = db.Column(db.DateTime)
	created_at = db.Column(db.DateTime, default=datetime.utcnow)
	
	def set_password(self, password):
		self.password_hash = generate_password_hash(password)
	
	def check_password(self, password):
		return check_password_hash(self.password_hash, password)
	
	def to_dict(self):
		return {
			'id': self.id,
			'username': self.username,
			'api_key': self.api_key,
			'last_login': self.last_login.isoformat() if self.last_login else None,
			'created_at': self.created_at.isoformat() if self.created_at else None
		}
