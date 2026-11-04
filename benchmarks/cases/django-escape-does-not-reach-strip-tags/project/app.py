from django.utils.html import escape


def clean(text):
    return escape(text)
