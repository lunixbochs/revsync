import sys
import os
sys.path.append(os.path.dirname(__file__))

good = False

try:
    import binaryninja
    import binaryninja.interaction
    try:
        import config
    except ImportError:
        binaryninja.interaction.show_message_box(title="Revsync error", text="Revsync: You must setup myconfig.py!")
        raise
    import binja_frontend
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
