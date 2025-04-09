# routes/users.py
from flask import Blueprint, request, jsonify, current_app
from flask_restful import Api, Resource
from models import db, User
from utils.security import require_api_key, generate_token
from datetime import datetime

users_bp = Blueprint('users', __name__)
api = Api(users_bp)


class UserLogin(Resource):
	def post(self):
		"""用户登录"""
		data = request.get_json()
		
		if 'username' not in data or 'password' not in data:
			return jsonify({
				'success': False,
				'message': 'Missing username or password'
			}), 400
		
		# 查找用户
		user = User.query.filter_by(username=data['username']).first()
		
		# 验证密码
		if not user or not user.check_password(data['password']):
			return jsonify({
				'success': False,
				'message': 'Invalid username or password'
			}), 401
		
		# 更新最后登录时间
		user.last_login = datetime.utcnow()
		db.session.commit()
		
		# 生成JWT令牌
		token = generate_token(user.id)
		
		return jsonify({
			'success': True,
			'message': 'Login successful',
			'data': {
				'token': token,
				'user': user.to_dict()
			}
		})


class UserProfile(Resource):
	@require_api_key
	def get(self):
		"""获取当前用户信息"""
		user_id = request.user_id
		user = User.query.get_or_404(user_id)
		
		return jsonify({
			'success': True,
			'data': user.to_dict()
		})
	
	@require_api_key
	def put(self):
		"""更新用户信息"""
		user_id = request.user_id
		user = User.query.get_or_404(user_id)
		data = request.get_json()
		
		# 更新密码
		if 'password' in data and data['password']:
			user.set_password(data['password'])
		
		# 重新生成API密钥
		if data.get('regenerate_api_key'):
			import uuid
			user.api_key = str(uuid.uuid4())
		
		db.session.commit()
		
		return jsonify({
			'success': True,
			'message': 'Profile updated successfully',
			'data': user.to_dict()
		})


# 注册API资源
api.add_resource(UserLogin, '/login')
api.add_resource(UserProfile, '/profile')
