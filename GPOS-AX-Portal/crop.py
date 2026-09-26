from PIL import Image
import os
import shutil
os.makedirs('static/img', exist_ok=True)
shutil.copy('favicon_src.png', 'static/img/favicon.png')
img = Image.open('mockup_src.jpg')
w, h = img.size
left_half = img.crop((0, 0, int(w*0.55), h))
left_half.save('static/img/login_mascot.jpg')
print('OK')
