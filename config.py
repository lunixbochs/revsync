from __future__ import print_function

import json
import os

try:
    # TODO: We can look in $HOME/.config or $HOME/.revsync or something
    path = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(path, "config.json"), "r") as f:
        config = json.loads(f.read())
except Exception:
    raise ImportError
