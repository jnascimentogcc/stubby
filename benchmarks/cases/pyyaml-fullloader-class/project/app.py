import yaml


def parse(text):
    return yaml.load(text, Loader=yaml.FullLoader)
