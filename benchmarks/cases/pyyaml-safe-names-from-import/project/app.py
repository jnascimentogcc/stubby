from yaml import safe_load, SafeLoader

LOADER = SafeLoader


def parse(text):
    return safe_load(text)
