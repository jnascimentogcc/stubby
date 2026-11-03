from PIL import Image


def thumb(path):
    return Image.open(path).resize((64, 64))
