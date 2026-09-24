import os
import re
from typing import Dict, List, Any
import networkx as nx

def parse_recipe(recipe_path: str) -> Dict[str, Any]:
    variables = {}
    if not os.path.exists(recipe_path):
        return variables
        
    try:
        with open(recipe_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception:
        return variables
        
    var_pattern = re.compile(r'^([a-zA-Z0-9_:{}\-]+)\s*([?+:]?=)\s*"(.*)"\s*$')
    task_pattern = re.compile(r'^(do_[a-zA-Z0-9_]+)\s*\(\)\s*\{')
    inherit_pattern = re.compile(r'^inherit\s+(.+)$')
    
    for line in lines:
        line = line.strip()
        m = var_pattern.match(line)
        if m:
            var_name = m.group(1)
            op = m.group(2)
            val = m.group(3)
            
            if var_name in variables and ('+=' in op or '_append' in var_name):
                variables[var_name] += ' ' + val
            else:
                variables[var_name] = val
            continue
            
        m2 = task_pattern.match(line)
        if m2:
            task_name = m2.group(1)
            variables[task_name] = "defined"
            continue
            
        m3 = inherit_pattern.match(line)
        if m3:
            variables['inherit'] = m3.group(1)
            
    return variables

def parse_layer_conf(layer_conf_path: str) -> Dict[str, Any]:
    variables = {}
    if not os.path.exists(layer_conf_path):
        return variables
        
    var_pattern = re.compile(r'^([a-zA-Z0-9_]+)\s*([?+:]?=)\s*"(.*)"\s*$')
    try:
        with open(layer_conf_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                m = var_pattern.match(line)
                if m:
                    var_name = m.group(1)
                    val = m.group(3)
                    variables[var_name] = val
    except Exception:
        pass
    return variables

def validate_recipe(recipe_path: str, layer_conf_path: str = '') -> Dict[str, Any]:
    recipe_vars = parse_recipe(recipe_path)
    
    errors = []
    warnings = []
    
    if 'LICENSE' not in recipe_vars:
        errors.append("Missing LICENSE")
    if 'LIC_FILES_CHKSUM' not in recipe_vars:
        errors.append("Missing LIC_FILES_CHKSUM")
        
    if 'SUMMARY' not in recipe_vars:
        warnings.append("Missing SUMMARY")
    if 'SRC_URI' not in recipe_vars:
        warnings.append("Missing SRC_URI")
    else:
        src_uri = recipe_vars['SRC_URI']
        if not re.search(r'(git|http|https|file|ftp)://', src_uri):
             warnings.append("Invalid SRC_URI schemes")
             
    if 'inherit' not in recipe_vars:
        warnings.append("Missing inherit class")
        
    return {
        'valid': len(errors) == 0,
        'errors': errors,
        'warnings': warnings
    }

def build_dependency_graph(recipes_dir: str) -> Dict[str, Any]:
    graph = nx.DiGraph()
    
    if not os.path.exists(recipes_dir):
        return {
            'num_recipes': 0,
            'num_dependencies': 0,
            'cycles_detected': False,
            'cycles': []
        }
        
    for root, _, files in os.walk(recipes_dir):
        for file in files:
            if file.endswith('.bb') or file.endswith('.bbappend'):
                recipe_path = os.path.join(root, file)
                pn = file.split('_')[0] if '_' in file else file.replace('.bb', '').replace('.bbappend', '')
                
                if pn not in graph:
                    graph.add_node(pn)
                    
                recipe_vars = parse_recipe(recipe_path)
                
                depends_str = recipe_vars.get('DEPENDS', '')
                for dep in depends_str.split():
                    if dep:
                        graph.add_edge(pn, dep)
                    
                rdepends = []
                for k, v in recipe_vars.items():
                    if k.startswith('RDEPENDS'):
                        rdepends.extend(v.split())
                        
                for dep in rdepends:
                    if dep:
                        graph.add_edge(pn, dep)
                    
    try:
        cycles = list(nx.simple_cycles(graph))
    except Exception:
        cycles = []
        
    return {
        'num_recipes': graph.number_of_nodes(),
        'num_dependencies': graph.number_of_edges(),
        'cycles_detected': len(cycles) > 0,
        'cycles': cycles
    }
