from idaapi import *
from idc import *
from idautils import *

from client import Client
from config import config

get_fhash = retrieve_input_file_sha256
fhash = None
client = Client(**config)
auto_wait = False

def onmsg(key, data, replay=False):
    if key != fhash or key != retrieve_input_file_sha256():
        print 'revsync: hash mismatch, dropping command'
        return

    cmd, user = data['cmd'], data['user']
    if cmd == 'comment':
        print 'revsync: %s %s %#x %s' % (cmd, user, data['addr'], data['text'])
    elif cmd == 'extra_command':
        print 'revsync: %s %s %#x %s' % (cmd, user, data['addr'], data['text'])
    elif cmd == 'area_comment':
        print 'revsync: %s %s %#x %s' % (cmd, user, data['range'], data['text'])
    elif cmd == 'rename':
        print 'revsync: %s %s %#x %s' % (cmd, user, data['addr'], data['text'])
    else:
        print 'revsync: unknown cmd', data

def on_load():
    global fhash
    if fhash:
        client.leave(fhash)
    fhash = get_fhash()
    print 'revsync: connecting with', fhash
    client.join(fhash, onmsg)

def publish(data):
    if not autoIsOk():
        return
    if fhash == get_fhash():
        client.publish(fhash, data)

class IDPHooks(IDP_Hooks):
    def renamed(self, ea, new_name, local_name):
        if isLoaded(ea):
            publish({'cmd': 'rename', 'addr': ea, 'text': new_name})
        return IDP_Hooks.renamed(self, ea, new_name, local_name)

    def newfile(self, fname):
        global auto_wait
        auto_wait = True
        print 'revsync: waiting for auto analysis'
        return IDP_Hooks.newfile(self, fname)

    def oldfile(self, fname):
        on_load()
        return IDP_Hooks.oldfile(self, fname)

    def auto_empty_finally(self):
        global auto_wait
        if auto_wait:
            auto_wait = False
            on_load()

        return IDP_Hooks.auto_empty_finally(self)

class IDBHooks(IDB_Hooks):
    def cmt_changed(self, ea, repeatable):
        cmt = GetCommentEx(ea, repeatable)
        publish({'cmd': 'comment', 'addr': ea, 'text': cmt})
        return IDB_Hooks.cmt_changed(self, ea, repeatable)

    def extra_cmt_changed(self, ea, line_idx, repeatable):
        cmt = GetCommentEx(ea, repeatable)
        publish({'cmd': 'extra_comment', 'addr': ea, 'line': line_idx, 'text': cmt})
        return IDB_Hooks.extra_cmt_changed(self, ea, line_idx, repeatable)

    def area_cmt_changed(self, cb, a, cmt, repeatable):
        publish({'cmd': 'area_comment', 'range': [a.startEA, a.endEA], 'text': cmt})
        return IDB_Hooks.area_cmt_changed(self, cb, a, cmt, repeatable)

class UIHooks(UI_Hooks):
    pass

hook1 = IDPHooks()
hook2 = IDBHooks()
hook3 = UIHooks()
hook1.hook()
hook2.hook()
hook3.hook()
