from django.template.defaultfilters import striptags


def clean(text):
    return striptags(text)
