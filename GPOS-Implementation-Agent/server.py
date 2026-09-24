import os
import re
import glob
import json
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

try:
    from mcp.server.fastmcp import FastMCP, Context
except ImportError:
    try:
        from fastmcp import FastMCP, Context
    except ImportError:
        raise ImportError('Failed to import FastMCP.')

from config import WORKSPACE_ROOT, SERVER_PORT, SUPPORTED_EXTENSIONS
from ast_parser import parse_file, find_symbol, scan_directory
from bitbake_parser import parse_recipe, parse_layer_conf, validate_recipe, build_dependency_graph


def _load_markdown_knowledge() -> str:
    sections = []
    base_dir = os.path.dirname(os.path.abspath(__file__))
    for folder, tag in [('.github', 'CORE INSTRUCTIONS'), ('rules', 'GOVERNANCE RULE'), ('skills', 'WORKFLOW SKILL')]:
        for filepath in sorted(glob.glob(os.path.join(base_dir, folder, '*.md'))):
            name = os.path.basename(filepath)
            if name.startswith('_'):
                continue
            with open(filepath, 'r', encoding='utf-8') as f:
                sections.append(f'### [{tag}: {name}]\n{f.read().strip()}')
    return '\n\n---\n\n'.join(sections) if sections else ''

AGENT_KNOWLEDGE = _load_markdown_knowledge()
_knowledge_file_count = AGENT_KNOWLEDGE.count('### [')
print(f'📚 Loaded {_knowledge_file_count} markdown knowledge files into agent context.')

mcp = FastMCP('Code Implementation Agent', instructions=AGENT_KNOWLEDGE if AGENT_KNOWLEDGE else None)

@mcp.tool()
def get_agent_instructions() -> str:
    """
    IMPORTANT: You MUST call this tool ONCE at the start of every new conversation before calling any other tool.
    Returns the core rules, guidelines, and skills the agent must follow.
    """
    return AGENT_KNOWLEDGE

@mcp.tool()
def workspace_code_analyzer(file_path: str = '', symbol_name: str = '', directory_path: str = '', extensions: str = '.c,.cpp,.h,.hpp,.java,.dart') -> str:
    """
    Analyzes source code in the workspace.
    Can parse a specific file, search for a symbol, or scan a directory for specific extensions.
    """
    ext_list = extensions.split(',')
    results = {}
    
    try:
        if file_path:
            results['file_analysis'] = parse_file(file_path)
        if symbol_name:
            # Assumes directory_path is set, fallback to WORKSPACE_ROOT
            search_dir = directory_path or WORKSPACE_ROOT
            results['symbol_search'] = find_symbol(symbol_name, search_dir, ext_list)
        if directory_path and not symbol_name:
            results['directory_scan'] = scan_directory(directory_path, ext_list)
            
        return json.dumps(results, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})

@mcp.tool()
def find_reference_components(query: str, search_dir: str = '', component_type: str = 'any') -> str:
    """
    Scans workspace to find existing implementations matching a query.
    component_type can be: 'flutter_plugin', 'luna_service', 'yocto_recipe', or 'any'.
    """
    base_dir = search_dir or WORKSPACE_ROOT
    results = []
    
    for root, dirs, files in os.walk(base_dir):
        if component_type in ('flutter_plugin', 'any'):
            if 'pubspec.yaml' in files:
                pubspec_path = os.path.join(root, 'pubspec.yaml')
                try:
                    with open(pubspec_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if 'flutter.plugin.platforms.webos' in content.replace(' ', ''):
                            if query.lower() in content.lower():
                                results.append({
                                    'type': 'flutter_plugin',
                                    'path': root,
                                    'metadata': {'file': 'pubspec.yaml'}
                                })
                except Exception:
                    pass

        if component_type in ('luna_service', 'any'):
            if 'CMakeLists.txt' in files:
                cmake_path = os.path.join(root, 'CMakeLists.txt')
                try:
                    with open(cmake_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if 'luna-service2' in content:
                            if query.lower() in content.lower() or query.lower() in os.path.basename(root).lower():
                                results.append({
                                    'type': 'luna_service',
                                    'path': root,
                                    'metadata': {'file': 'CMakeLists.txt'}
                                })
                except Exception:
                    pass

        if component_type in ('yocto_recipe', 'any'):
            for file in files:
                if file.endswith('.bb'):
                    bb_path = os.path.join(root, file)
                    if query.lower() in file.lower():
                        results.append({
                            'type': 'yocto_recipe',
                            'path': bb_path,
                            'metadata': {'name': file}
                        })
                        continue
                    try:
                        with open(bb_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            summary_match = re.search(r'^SUMMARY\s*=\s*"(.*?)"', content, re.MULTILINE)
                            if summary_match and query.lower() in summary_match.group(1).lower():
                                results.append({
                                    'type': 'yocto_recipe',
                                    'path': bb_path,
                                    'metadata': {'summary': summary_match.group(1)}
                                })
                    except Exception:
                        pass
                        
    return json.dumps(results, indent=2)

@mcp.tool()
def scan_yocto_layers(workspace_dir: str = '') -> str:
    """
    Discovers Yocto layers in the workspace.
    Looks for bblayers.conf to find active layers and scans for meta-* directories.
    """
    base_dir = workspace_dir or WORKSPACE_ROOT
    layers = []
    
    # Check for meta-* directories
    for root, dirs, files in os.walk(base_dir):
        # We only want top-level or one-level deep meta- directories
        dir_name = os.path.basename(root)
        if dir_name.startswith('meta-') and 'conf/layer.conf' in [os.path.join(r, f) for r, d, fs in os.walk(root) for f in fs]:
            layer_conf_path = os.path.join(root, 'conf', 'layer.conf')
            if os.path.exists(layer_conf_path):
                recipe_count = sum(1 for r, _, fs in os.walk(root) for f in fs if f.endswith('.bb'))
                layers.append({
                    'name': dir_name,
                    'path': root,
                    'recipe_count': recipe_count
                })
        
        # Prevent going too deep if we found a layer
        if dir_name.startswith('meta-'):
            dirs.clear()

    return json.dumps({'discovered_layers': layers}, indent=2)

@mcp.tool()
def bitbake_layer_validator(recipe_path: str, layer_conf_path: str = '', scan_deps_dir: str = '') -> str:
    """
    Validates a BitBake recipe.
    """
    results = {}
    try:
        results['recipe_parse'] = parse_recipe(recipe_path)
        if layer_conf_path:
            results['layer_conf'] = parse_layer_conf(layer_conf_path)
        results['validation'] = validate_recipe(recipe_path)
        if scan_deps_dir:
            results['dependency_graph'] = build_dependency_graph(recipe_path, scan_deps_dir)
        return json.dumps(results, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})

@mcp.tool()
def diagnose_build_error(error_log: str) -> str:
    """
    Analyzes raw build error text and categorizes it.
    """
    result = {
        'error_type': 'Unknown',
        'root_cause': 'Could not determine from log',
        'affected_file': None,
        'recommended_fix': 'Review the raw build logs.'
    }
    
    if re.search(r'undefined reference to', error_log, re.IGNORECASE):
        result['error_type'] = 'Linker Error'
        result['root_cause'] = 'Missing library in DEPENDS or target_link_libraries'
        result['recommended_fix'] = 'Check if all required libraries are specified in DEPENDS and linked properly.'
    elif re.search(r'fatal error: .* No such file or directory', error_log, re.IGNORECASE):
        result['error_type'] = 'Compilation Error'
        result['root_cause'] = 'Missing header/package'
        match = re.search(r'fatal error: (.*?): No such file', error_log, re.IGNORECASE)
        if match:
            result['affected_file'] = match.group(1)
        result['recommended_fix'] = 'Ensure the package providing the header is in DEPENDS.'
    elif re.search(r'installed-vs-shipped|installed but not shipped', error_log, re.IGNORECASE):
        result['error_type'] = 'Packaging Error'
        result['root_cause'] = 'Missing FILES:${PN}'
        result['recommended_fix'] = 'Add the installed files to FILES:${PN} in the recipe.'
    elif re.search(r'non -dev package contains symlink \.so', error_log, re.IGNORECASE):
        result['error_type'] = 'Packaging Error'
        result['root_cause'] = 'SOLIBS packaging issue'
        result['recommended_fix'] = 'Ensure .so files go into the -dev package or adjust SOLIBS/SOLIBSDEV.'
    elif re.search(r'Nothing PROVIDES', error_log, re.IGNORECASE):
        result['error_type'] = 'Dependency Error'
        result['root_cause'] = 'Missing recipe or dependency'
        match = re.search(r'Nothing PROVIDES \'(.*?)\'', error_log, re.IGNORECASE)
        if match:
            result['affected_file'] = match.group(1)
        result['recommended_fix'] = 'Make sure the layer providing the dependency is included or fix the dependency name.'
    elif re.search(r'do_compile failed', error_log, re.IGNORECASE):
        result['error_type'] = 'Compilation Error'
        result['root_cause'] = 'General compilation error'
        result['recommended_fix'] = 'Check compiler output preceding the do_compile failure.'
        
    return json.dumps(result, indent=2)

class HostHeaderBypassMiddleware:
    def __init__(self, app):
        self.app = app
    async def __call__(self, scope, receive, send):
        if scope.get('type') in ('http', 'websocket'):
            headers = []
            for k, v in scope.get('headers', []):
                if k.lower() == b'host':
                    headers.append((b'host', b'localhost:8000'))
                else:
                    headers.append((k, v))
            scope['headers'] = headers
        await self.app(scope, receive, send)

if hasattr(mcp, 'http_app'):
    app = mcp.http_app(transport='sse')
else:
    app = mcp.sse_app()

async def health_check(request: Request) -> Response:
    return Response(content='OK', status_code=200)

app.routes.append(Route('/health', health_check, methods=['GET']))

if __name__ == '__main__':
    import uvicorn
    print(f'🏗️ Code Implementation Agent starting on port {SERVER_PORT}...')
    print(f'📡 SSE endpoint: http://0.0.0.0:{SERVER_PORT}/sse')
    wrapped_app = HostHeaderBypassMiddleware(app)
    uvicorn.run(wrapped_app, host='0.0.0.0', port=SERVER_PORT, proxy_headers=True, forwarded_allow_ips='*')
