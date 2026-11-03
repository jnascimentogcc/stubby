import importlib

import yaml


def plugin(name):
    return importlib.import_module(name)


def parse(text):
    return yaml.safe_load(text)
