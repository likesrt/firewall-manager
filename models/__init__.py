# models/__init__.py
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from models.rule import FirewallRule, RuleTemplate
from models.log import FirewallLog, AlertConfig
from models.status import FirewallStatus, ConnectionStat
from models.user import User
from models.setting import SystemSetting, SystemBackup
