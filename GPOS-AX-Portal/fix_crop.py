from PIL import Image
img = Image.open('static/img/full_bg.jpg')
# Original size 1024x1024. The penguin is on the left.
# Let's crop from x=20 to x=500. This should capture the entire penguin and its aura.
cropped = img.crop((10, 240, 520, 780))
cropped.save('static/img/login_mascot.jpg')
print('Cropped successfully:', cropped.size)
