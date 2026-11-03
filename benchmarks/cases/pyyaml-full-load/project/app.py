import yaml


def parse(text):
    return yaml.full_load(text)
