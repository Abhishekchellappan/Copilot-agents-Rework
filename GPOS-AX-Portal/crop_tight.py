from PIL import Image
img = Image.open('mockup_src.jpg')
# Original size is likely 1024x1024. Left half is x=0..512.
# Let's crop tightly around the penguin: x=30 to 480, y=280 to 750
cropped = img.crop((30, 260, 480, 750))
cropped.save('static/img/login_mascot.jpg')
print('Cropped successfully:', cropped.size)
