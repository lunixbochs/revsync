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
    # check if running in BinaryNinja:
    if binaryninja.core_ui_enabled():
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

# check if running in Vivisect:
if globals().get('vw') is not None:
    print("vivisect startup...")
    try:
        import vivisect
        try:
            import config
        except ImportError:
            #host_f = bi.TextLineField("host")
            #port_f = bi.IntegerField("port")
            #nick_f = bi.TextLineField("nick")
            #password_f = bi.TextLineField("password")
            #success = bi.get_form_input([None, host_f, port_f, nick_f, password_f], "Configure Revsync")
            #if not success:
            #    binaryninja.interaction.show_message_box(title="Revsync error", text="Failed to configure revsync")
            #    raise

            #write_config(host_f.result, port_f.result, nick_f.result, password_f.result)
            #import config
            print("import error importing config (revsync)") 

        import viv_frontend
        good = True
    except ImportError:
        pass


# if idaapi loads, go with it.
try:
    import idaapi
    import ida_frontend
    good = True
except ImportError:
    pass

if not good:
    print('Warning: Could not find an appropriate plugin environment: IDA, Binary Ninja, and Vivisect plugin API imports failed')
    raise ImportError

# Vivisect looks for this in a plugin
def vivExtension(vw, vwgui):
    import viv_frontend
    viv_frontend.vivExtension(vw, vwgui)
