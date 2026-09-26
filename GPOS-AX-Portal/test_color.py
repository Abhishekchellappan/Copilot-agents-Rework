from PIL import Image
img = Image.open('static/img/login_mascot.jpg')
w, h = img.size
print(f'Top Left: #{img.getpixel((10, 10))[0]:02x}{img.getpixel((10, 10))[1]:02x}{img.getpixel((10, 10))[2]:02x}')
print(f'Top Right: #{img.getpixel((w-10, 10))[0]:02x}{img.getpixel((w-10, 10))[1]:02x}{img.getpixel((w-10, 10))[2]:02x}')
print(f'Bottom Left: #{img.getpixel((10, h-10))[0]:02x}{img.getpixel((10, h-10))[1]:02x}{img.getpixel((10, h-10))[2]:02x}')
print(f'Bottom Right: #{img.getpixel((w-10, h-10))[0]:02x}{img.getpixel((w-10, h-10))[1]:02x}{img.getpixel((w-10, h-10))[2]:02x}')
