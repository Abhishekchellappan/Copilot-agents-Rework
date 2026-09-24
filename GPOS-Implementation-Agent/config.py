import os

WORKSPACE_ROOT = os.environ.get('WORKSPACE_ROOT', '/app/workspace')
TEMPLATES_DIR = os.environ.get('TEMPLATES_DIR', '/app/templates')
SERVER_PORT = int(os.environ.get('SERVER_PORT', '8000'))
SUPPORTED_LANGUAGES = ['c', 'cpp', 'java', 'dart']
SUPPORTED_EXTENSIONS = ['.c', '.cpp', '.cc', '.h', '.hpp', '.java', '.dart']
