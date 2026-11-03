from PIL import ImageMath


def calc(expr, im):
    return ImageMath.eval(expr, a=im)
