# routes/__init__.py
from routes.rules import rules_bp
from routes.logs import logs_bp
from routes.status import status_bp
from routes.users import users_bp
from routes.settings import settings_bp

def register_routes(app):
    """注册所有路由蓝图"""
    app.register_blueprint(rules_bp, url_prefix='/api/rules')
    app.register_blueprint(logs_bp, url_prefix='/api/logs')
    app.register_blueprint(status_bp, url_prefix='/api/status')
    app.register_blueprint(users_bp, url_prefix='/api/users')
    app.register_blueprint(settings_bp, url_prefix='/api/settings')
