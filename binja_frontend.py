from binaryninja import *

import hashlib
from client import Client 
from config import config

log_info('revsync loaded!!!!')

def get_fhash(fname):
    with open(fname, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest().upper()

fhash = None
client = Client(**config)

def onmsg(key, data, replay=False):
    log_info('revsync: callback fired')
    if key != fhash:
        log_info('revsync: hash mismatch, dropping command')
        return

    cmd, user = data['cmd'], data['user']
    if cmd == 'comment':
        log_info('revsync: <%s> %s %#x %s' % (user, cmd, data['addr'], data['text']))
    elif cmd == 'extra_comment':
        log_info('revsync: <%s> %s %#x %s' % (user, cmd, data['addr'], data['text']))
    elif cmd == 'area_comment':
        log_info('revsync: <%s> %s %s %s' % (user, cmd, data['range'], data['text']))
    elif cmd == 'rename':
        log_info('revsync: <%s> %s %#x %s' % (user, cmd, data['addr'], data['text']))
    elif cmd == 'join':
        log_info('revsync: <%s> joined' % (user))
    else:
        log_info('revsync: unknown cmd %s' % data)

def load(bv):
    global fhash
    if fhash:
        client.leave(fhash)
    fhash = get_fhash(bv.file.filename)
    log_info('revsync: connecting with %s' % fhash)
    client.join(fhash, onmsg)
    log_info('revsync: connected!')


PluginCommand.register('revsync', 'revsync!!!', load)