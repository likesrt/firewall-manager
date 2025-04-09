# utils/validators.py
import re
import ipaddress


def validate_ip_address(ip):
	"""验证IP地址格式"""
	try:
		ipaddress.ip_address(ip)
		return True
	except ValueError:
		return False


def validate_ip_network(network):
	"""验证IP网络格式"""
	try:
		ipaddress.ip_network(network, strict=False)
		return True
	except ValueError:
		return False


def validate_port(port):
	"""验证端口格式"""
	# 单个端口
	if port.isdigit():
		port_num = int(port)
		return 0 <= port_num <= 65535
	
	# 端口范围
	if '-' in port:
		parts = port.split('-')
		if len(parts) != 2:
			return False
		
		if not parts[0].isdigit() or not parts[1].isdigit():
			return False
		
		start = int(parts[0])
		end = int(parts[1])
		
		return 0 <= start <= end <= 65535
	
	return False


def validate_protocol(protocol):
	"""验证协议格式"""
	valid_protocols = ['tcp', 'udp', 'icmp', 'all']
	return protocol.lower() in valid_protocols


def validate_chain(chain):
	"""验证链名称格式"""
	# 链名称只能包含字母、数字和下划线
	return bool(re.match(r'^[a-zA-Z0-9_]+$', chain))


def validate_action(action):
	"""验证动作格式"""
	valid_actions = ['ACCEPT', 'DROP', 'REJECT', 'LOG']
	return action in valid_actions
