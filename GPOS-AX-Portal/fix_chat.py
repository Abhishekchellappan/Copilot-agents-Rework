import re

with open('/app/static/js/chat_v2.js', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

content = re.sub(
    r'avatar = \s*<div class="w-8 h-8 rounded-full bg-blue-500/20 border border-blue-500/50 flex items-center justify-center shrink-0 mt-1">\s*<i data-lucide="bot" class="w-4 h-4 text-blue-400"></i>\s*</div>\s*;',
    '''const isDev = this.currentAgentId === "device-agent";
      avatar = 
        <div class="w-8 h-8 rounded-full  border flex items-center justify-center shrink-0 mt-1">
          <i data-lucide="" class="w-4 h-4 "></i>
        </div>
      ;''',
    content
)

content = content.replace('GPOS Jira Agent &bull;', ' &bull;')
content = content.replace('GPOS Jira Agent •', ' •')

with open('/app/static/js/chat_v2.js', 'w', encoding='utf-8') as f:
    f.write(content)
