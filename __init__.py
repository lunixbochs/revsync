import sys
import os
sys.path.append(os.path.dirname(__file__))

from config import config
good = False

try:
    import binaryninja
    import binja_frontend
    #import binja_coverage
    good = True
except ImportError:
    pass

try:
    import idaapi
    import ida_frontend
    good = True
except ImportError:
    pass

if not good:
    print('Warning: both IDA and Binary Ninja plugin API imports failed')
