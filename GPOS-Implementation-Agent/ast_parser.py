import os
import re
from typing import Dict, List, Any

try:
    from tree_sitter import Language, Parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

SUPPORTED_EXTENSIONS = ['.c', '.cpp', '.cc', '.h', '.hpp', '.java', '.dart']

def _ext_to_lang(ext: str) -> str:
    ext = ext.lower()
    if ext in ['.c', '.h']:
        return 'c'
    if ext in ['.cpp', '.cc', '.hpp']:
        return 'cpp'
    if ext == '.java':
        return 'java'
    if ext == '.dart':
        return 'dart'
    return 'unknown'

def _regex_parse(content: str, lang: str) -> Dict[str, Any]:
    functions = []
    classes = []
    includes = []
    
    if lang in ['c', 'cpp']:
        includes = re.findall(r'#include\s+["<]([^">]+)[">]', content)
        classes = re.findall(r'\b(?:class|struct)\s+(\w+)', content)
        functions = re.findall(r'\b[\w:*&<>]+\s+(\w+)\s*\([^)]*\)\s*(?:const)?\s*(?:\{|;)', content)
    elif lang == 'java':
        includes = re.findall(r'import\s+([^;]+);', content)
        classes = re.findall(r'(?:public|private|protected)?\s*(?:static)?\s*class\s+(\w+)', content)
        functions = re.findall(r'\b[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w\s,]+)?(?:\{|;)', content)
    elif lang == 'dart':
        includes = re.findall(r'import\s+[\'"]([^\'"]+)[\'"]', content)
        classes = re.findall(r'class\s+(\w+)(?:\s+(?:extends|implements|with)\s+[\w\s,<>]+)*', content)
        functions = re.findall(r'(?:[\w<>_]+\s+)?(\w+)\s*\([^)]*\)\s*(?:async\s*)?(?:\{|=>|;)', content)
        method_channels = re.findall(r'MethodChannel\([\'"]([^\'"]+)[\'"]\)', content)
        functions.extend(method_channels) 
        
    keywords = {'if', 'while', 'for', 'switch', 'catch', 'main', 'return', 'new'}
    functions = list(set([f for f in functions if f not in keywords]))
    classes = list(set(classes))
    includes = list(set(includes))
    
    return {'functions': functions, 'classes': classes, 'includes': includes}

def parse_file(file_path: str) -> Dict[str, Any]:
    _, ext = os.path.splitext(file_path)
    lang = _ext_to_lang(ext)
    
    result = {
        'file_path': file_path,
        'language': lang,
        'functions': [],
        'classes': [],
        'includes': []
    }
    
    if not os.path.exists(file_path):
        return result
        
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception:
        return result
        
    parsed = _regex_parse(content, lang)
    result.update(parsed)
    return result

def find_symbol(file_path: str, symbol_name: str) -> Dict[str, Any]:
    result = {
        'name': symbol_name,
        'type': 'unknown',
        'definition': '',
        'line_range': [],
        'dependencies': []
    }
    
    _, ext = os.path.splitext(file_path)
    lang = _ext_to_lang(ext)
    
    if not os.path.exists(file_path):
        return result
        
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception:
        return result
        
    class_pattern = r''
    if lang in ['c', 'cpp']:
        class_pattern = rf'\b(?:class|struct)\s+{symbol_name}\b'
    elif lang in ['java', 'dart']:
        class_pattern = rf'\bclass\s+{symbol_name}\b'
        
    if class_pattern:
        for i, line in enumerate(lines):
            if re.search(class_pattern, line):
                result['type'] = 'class'
                result['definition'] = line.strip()
                result['line_range'] = [i + 1, i + 1]
                return result
            
    func_pattern = rf'\b{symbol_name}\s*\('
    for i, line in enumerate(lines):
        if re.search(func_pattern, line):
            result['type'] = 'function'
            result['definition'] = line.strip()
            result['line_range'] = [i + 1, i + 1]
            return result
            
    return result

def scan_directory(directory_path: str, extensions: List[str] = None, symbol_name: str = '') -> List[Dict[str, Any]]:
    if extensions is None:
        extensions = SUPPORTED_EXTENSIONS
    
    results = []
    for root, _, files in os.walk(directory_path):
        for file in files:
            _, ext = os.path.splitext(file)
            if ext in extensions:
                file_path = os.path.join(root, file)
                if symbol_name:
                    sym_info = find_symbol(file_path, symbol_name)
                    if sym_info['type'] != 'unknown':
                        results.append(sym_info)
                else:
                    results.append(parse_file(file_path))
    return results
