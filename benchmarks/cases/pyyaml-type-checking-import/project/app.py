from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from yaml import FullLoader


def parse(text):
    return yaml.safe_load(text)
