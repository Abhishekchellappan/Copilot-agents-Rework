from PIL import Image
img = Image.open('media.png')
rgb = img.getpixel((10, 10))
print(f'Color: #{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}')
