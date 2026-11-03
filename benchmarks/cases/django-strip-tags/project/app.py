from django.utils.html import strip_tags


def clean(text):
    return strip_tags(text)
