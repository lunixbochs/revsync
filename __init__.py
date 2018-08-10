import json
import sys
import os
sys.path.append(os.path.dirname(__file__))

good = False

def write_config(host, port, nick, password):
    path = os.path.dirname(os.path.abspath(__file__))
    config = {
        "host": host,
        "port": port,
        "nick": nick,
        "password": password
    }
    with open(os.path.join(path, "config.json"), "w") as f:
        config = f.write(json.dumps(config))

try:
    import binaryninja
    import binaryninja.interaction as bi
    try:
        import config
    except ImportError:
        host_f = bi.TextLineField("host")
        port_f = bi.IntegerField("port")
        nick_f = bi.TextLineField("nick")
        password_f = bi.TextLineField("password")
        success = bi.get_form_input([None, host_f, port_f, nick_f, password_f], "Configure Revsync")
        if not success:
            binaryninja.interaction.show_message_box(title="Revsync error", text="Failed to configure revsync")
            raise

        write_config(host_f.result, port_f.result, nick_f.result, password_f.result)
        import config
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
    raise ImportError
