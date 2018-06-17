try:
    config = __import__("myconfig").config
except ImportError:
    print "[!] You must setup myconfig.py!"
    raise
