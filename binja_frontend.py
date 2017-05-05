from binaryninja import *

import hashlib
from time import sleep
from client import Client 
from config import config

def get_fhash(fname):
    with open(fname, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest().upper()

def get_can_addr(bv, addr):
    return addr - bv.start

def get_ea(bv, addr):
    return addr + bv.start

def get_func_by_addr(bv, addr):
    bb = bv.get_basic_blocks_at(addr)
    if len(bb) > 0:
        return bb[0].function
    return None

def rename_symbol(bv, addr, name):
    sym = bv.get_symbol_at(addr)
    if sym is not None:
        # symbol already exists for this address
        if sym.auto == True:
            bv.undefine_auto_symbol(sym)
        else:
            bv.undefine_user_symbol(sym)
    # is it a function?
    func = get_func_by_addr(bv, addr)
    if func is not None:
        # function 
        sym = types.Symbol(SymbolType.FunctionSymbol, addr, name)
    else:
        # data
        sym = types.Symbol(SymbolType.DataSymbol, addr, name)
    bv.define_user_symbol(sym)

def publish(bv, data):
    if bv.session_data['fhash'] == get_fhash(bv.file.filename):
        bv.session_data['client'].publish(bv.session_data['fhash'], data)

def onmsg(bv, key, data, replay):
    if key != bv.session_data['fhash']:
        log_info('revsync: hash mismatch, dropping command')
        return
    cmd, user = data['cmd'], data['user']
    if cmd == 'comment':
        log_info('revsync: <%s> %s %#x %s' % (user, cmd, data['addr'], data['text']))
        addr = get_ea(bv, int(data['addr']))
        func = get_func_by_addr(bv, addr)
        # binja does not support comments on data symbols??? IDA does.
        if func is not None:
            func.set_comment(addr, data['text'])
    elif cmd == 'extra_comment':
        log_info('revsync: <%s> %s %#x %s' % (user, cmd, data['addr'], data['text']))
    elif cmd == 'area_comment':
        log_info('revsync: <%s> %s %s %s' % (user, cmd, data['range'], data['text']))
    elif cmd == 'rename':
        log_info('revsync: <%s> %s %#x %s' % (user, cmd, data['addr'], data['text']))
        addr = get_ea(bv, int(data['addr']))
        rename_symbol(bv, addr, data['text'])
    elif cmd == 'join':
        log_info('revsync: <%s> joined' % (user))
    else:
        log_info('revsync: unknown cmd %s' % data)

def revsync_callback(bv):
    def callback(key, data, replay=False):
        onmsg(bv, key, data, replay)
    return callback

def revsync_comment(bv, addr):
    comment = interaction.get_text_line_input('Enter comment: ', 'revsync comment')
    publish(bv, {'cmd': 'comment', 'addr': get_can_addr(bv, addr), 'text': comment or ''})
    get_func_by_addr(bv, addr).set_comment(addr, comment)

def revsync_rename(bv, addr):
    name = interaction.get_text_line_input('Enter symbol name: ', 'revsync rename')
    publish(bv, {'cmd': 'rename', 'addr': get_can_addr(bv, addr), 'text': name}) 
    rename_symbol(bv, addr, name)

def revsync_loop(bv):
    last_func = get_func_by_addr(bv, bv.offset)
    last_comments = {} 
    if last_func:
        last_comments = last_func.comments
    last_addr = bv.offset
    last_addr_sym = bv.get_symbol_at(last_addr) 
    while True:
        if last_addr == bv.offset:
            sleep(0.25)
        else:
            # gross, but here we go...
            log_info('cursor position changed to %#x' % bv.offset)
            # cursor position changed
            sym = bv.get_symbol_at(last_addr)
            if sym:
                # was there a symbol before?
                if last_addr_sym is None:
                    # new symbol defined, publish
                    log_info('new symbol at %#x: %s' % (last_addr, sym.name))
                    publish(bv, {'cmd': 'rename', 'addr': get_can_addr(bv, last_addr), 'text': sym.name}) 
                else:
                    # rename?
                    if sym.name != last_addr_sym.name:
                        # renamed symbol, publish 
                        log_info('renamed symbol at %#x: %s' % (last_addr, sym.name))
                        publish(bv, {'cmd': 'rename', 'addr': get_can_addr(bv, last_addr), 'text': sym.name}) 
            # were we just in a function?
            if last_func:
                comments = last_func.comments
                if comments != last_comments:
                    # check for changed comments
                    for addr, text in comments.items():
                        if last_comments is None:
                            # no previous comment at that addr, publish
                            log_info('changed comment: %#x, %s' % (addr, text))
                            publish(bv, {'cmd': 'comment', 'addr': get_can_addr(bv, addr), 'text': text})
                            continue
                        elif last_comments.get(addr) != text:
                            # changed comment, publish
                            log_info('changed comment: %#x, %s' % (addr, text))
                            publish(bv, {'cmd': 'comment', 'addr': get_can_addr(bv, addr), 'text': text})
                    # check for removed comments
                    if last_comments:
                        removed = set(last_comments.keys()) - set(comments.keys())
                        for addr in removed:
                            log_info('removed comment: %#x' % addr)
                            publish(bv, {'cmd': 'comment', 'addr': get_can_addr(bv, addr), 'text': ''})
            # update current function/addr info
            last_func = get_func_by_addr(bv, bv.offset)
            if last_func:
                last_comments = last_func.comments
            else:
                last_comments = {}
            last_addr = bv.offset
            last_addr_sym = bv.get_symbol_at(last_addr)

def revsync_load(bv):
    if bv.session_data.has_key('client') and bv.session_data.has_key('fhash'):
        # close out the previous session
        bv.session_data['client'].leave(bv.session_data['fhash'])
    client = Client(**config)
    fhash = get_fhash(bv.file.filename)
    bv.session_data['client'] = client 
    bv.session_data['fhash'] = fhash
    log_info('revsync: connecting with %s' % fhash)
    client.join(fhash, revsync_callback(bv))
    log_info('revsync: connected!')
    interaction.show_message_box('revsync', 'revsync is now loaded!\nremember to use ' + 
        'the UI for commenting and renaming.', buttons=MessageBoxButtonSet.OKButtonSet)
    t = threading.Thread(target=revsync_loop, args=(bv,))
    t.daemon = True
    t.start()

PluginCommand.register('revsync: load', 'load revsync!!!', revsync_load)
PluginCommand.register_for_address('revsync: comment', 'revsync comment', revsync_comment)
PluginCommand.register_for_address('revsync: rename symbol', 'revsync rename', revsync_rename)