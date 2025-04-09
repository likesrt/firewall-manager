# utils/security.py
from functools import wraps
from flask import request, jsonify, current_app
import jwt
from datetime import datetime, timedelta
import time


def generate_token(user_id):
	"""生成JWT令牌"""
	payload = {
		'user_id': user_id,
		'exp': datetime.utcnow() + timedelta(days=1),
		'iat': datetime.utcnow()
	}
	
	return jwt.encode(
		payload,
		current_app.config.get('SECRET_KEY'),
		algorithm='HS256'
	)


def verify_token(token):
	"""验证JWT令牌"""
	try:
		payload = jwt.decode(
			token,
			current_app.config.get('SECRET_KEY'),
			algorithms=['HS256']
		)
		return payload
	except jwt.ExpiredSignatureError:
		return None
	except jwt.InvalidTokenError:
		return None


def require_api_key(f):
	"""API密钥验证装饰器"""
	
	@wraps(f)
	def decorated(*args, **kwargs):
		# 获取认证头
		auth_header = request.headers.get('Authorization')
		
		if not auth_header:
			return jsonify({
				'success': False,
				'message': 'Missing Authorization header'
			}), 401
		
		# 检查认证类型
		parts = auth_header.split()
		
		if parts[0].lower() != 'bearer':
			return jsonify({
				'success': False,
				'message': 'Authorization header must start with Bearer'
			}), 401
		
		if len(parts) == 1:
			return jsonify({
				'success': False,
				'message': 'Token not found'
			}), 401
		
		token = parts[1]
		
		# 验证令牌
		payload = verify_token(token)
		
		if not payload:
			return jsonify({
				'success': False,
				'message': 'Invalid or expired token'
			}), 401
		
		# 将用户ID添加到请求对象
		request.user_id = payload['user_id']
		
		return f(*args, **kwargs)
	
	return decorated
