import hashlib
from time import sleep

from binaryninja import *
from binaryninja.plugin import PluginCommand

from client import Client
from config import config
from comments import NoChange
from comments import comments as cmt_data

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

def stack_dict_from_list(stackvars):
    d = {}
    for var in stackvars:
        d[var.storage] = (var.name, var.type)
    return d

def rename_symbol(bv, addr, name):
    sym = bv.get_symbol_at(addr)
    if sym is not None:
        # symbol already exists for this address
        if sym.auto is True:
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

def rename_stackvar(bv, func_addr, offset, name):
    func = get_func_by_addr(bv, func_addr)
    if func is None:
        log_info('revsync: bad func addr %#x during rename_stackvar' % func_addr)
        return
    # we need to figure out the variable type before renaming
    stackvars = stack_dict_from_list(func.vars)
    var = stackvars.get(offset)
    if var is None:
        log_info('revsync: could not locate stack var with offset %#x during rename_stackvar' % offset)
        return
    var_name, var_type = var
    func.create_user_stack_var(offset, var_type, name)
    return

def publish(bv, data):
    if bv.session_data['fhash'] == get_fhash(bv.file.filename):
        bv.session_data['client'].publish(bv.session_data['fhash'], data)

def onmsg(bv, key, data, replay):
    if key != bv.session_data['fhash']:
        log_info('revsync: hash mismatch, dropping command')
        return
    cmd, user = data['cmd'], data['user']
    ts = int(data.get('ts', 0))
    if cmd == 'comment':
        log_info('revsync: <%s> %s %#x %s' % (user, cmd, data['addr'], data['text']))
        addr = get_ea(bv, int(data['addr']))
        func = get_func_by_addr(bv, addr)
        # binja does not support comments on data symbols??? IDA does.
        if func is not None:
            text = cmt_data.set(addr, user, data['text'], ts)
            func.set_comment(addr, text)
    elif cmd == 'extra_comment':
        log_info('revsync: <%s> %s %#x %s' % (user, cmd, data['addr'], data['text']))
    elif cmd == 'area_comment':
        log_info('revsync: <%s> %s %s %s' % (user, cmd, data['range'], data['text']))
    elif cmd == 'rename':
        log_info('revsync: <%s> %s %#x %s' % (user, cmd, data['addr'], data['text']))
        addr = get_ea(bv, int(data['addr']))
        rename_symbol(bv, addr, data['text'])
    elif cmd == 'stackvar':
        log_info('revsync: <%s> %s %s %#x %s' % (user, cmd, data['func_name'], data['offset'], data['name']))
        rename_stackvar(bv, data['addr'], data['offset'], data['name'])
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

def watch_syms(bv, sym_type):
    """ Watch symbols of a given type (e.g. DataSymbol) for changes and publish diffs """
    def get_syms():
        # comes as list of Symbols
        syms = bv.get_symbols_of_type(sym_type)
        # turn our list into dict of addr => sym name
        syms_dict = dict()
        for sym in syms:
            syms_dict[sym.address] = sym.name
        return syms_dict

    last_syms = get_syms()
    while True:
        syms = get_syms()
        if syms != last_syms:
            for addr, name in syms.items():
                if last_syms.get(addr) != name:
                    # name changed, publish
                    log_info('revsync: user renamed symbol at %#x: %s' % (addr, name))
                    publish(bv, {'cmd': 'rename', 'addr': get_can_addr(bv, addr), 'text': name})
        last_syms = syms
        sleep(0.5)

def watch_cur_func(bv):
    """ Watch current function (if we're in code) for comment changes and publish diffs """
    def get_cur_func():
        return get_func_by_addr(bv, bv.offset)

    last_func = get_cur_func()
    last_comments = {}
    last_stackvars = {} 
    if last_func:
        last_comments = last_func.comments
        last_stackvars = stack_dict_from_list(last_func.vars)
    last_addr = bv.offset
    while True:
        if last_addr == bv.offset:
            sleep(0.25)
        else:
            # were we just in a function?
            if last_func:
                comments = last_func.comments
                if comments != last_comments:
                    # check for changed comments
                    for addr, text in comments.items():
                        if last_comments is None:
                            # no previous comment at that addr, publish
                            try:
                                addr = get_can_addr(bv, addr)
                                changed = cmt_data.parse_comment_update(addr, client.nick, text)
                                log_info('revsync: user changed comment: %#x, %s' % (addr, changed))
                                publish(bv, {'cmd': 'comment', 'addr': addr, 'text': changed})
                            except NoChange:
                                pass
                            continue
                        elif last_comments.get(addr) != text:
                            # changed comment, publish
                            try:
                                addr = get_can_addr(bv, addr)
                                changed = cmt_data.parse_comment_update(addr, client.nick, text)
                                log_info('resync: user changed comment: %#x, %s' % (addr, changed))
                                publish(bv, {'cmd': 'comment', 'addr': addr, 'text': changed})
                            except NoChange:
                                pass
                    # check for removed comments
                    if last_comments:
                        removed = set(last_comments.keys()) - set(comments.keys())
                        for addr in removed:
                            log_info('revsync: user removed comment: %#x' % addr)
                            publish(bv, {'cmd': 'comment', 'addr': get_can_addr(bv, addr), 'text': ''})

                # similar dance, but with stackvars 
                stackvars = stack_dict_from_list(last_func.vars)
                if stackvars != last_stackvars:
                    # check for changed stack var names
                    for offset, data in stackvars.items():
                        old_data = last_stackvars.get(offset)
                        if old_data != data:
                            cur_name, cur_type = data
                            old_name, old_type = old_data
                            if old_name != cur_name:
                                # stack var name changed, publish
                                log_info('revsync: user changed stackvar name at offset %#x to %s' % (offset, cur_name))
                                publish(bv, {'cmd': 'stackvar', 'addr': last_func.start, 'func_name': last_func.name, 'offset': offset, 'name': cur_name})

            # update current function/addr info
            last_func = get_cur_func()
            if last_func:
                last_comments = last_func.comments
                last_stackvars = stack_dict_from_list(last_func.vars)
            else:
                last_comments = {}
                last_stackvars = {} 
            last_addr = bv.offset


def revsync_load(bv):
    global client
    try:
        client
    except:
        client = Client(**config)
    if bv.session_data.has_key('client') and bv.session_data.has_key('fhash'):
        # close out the previous session
        bv.session_data['client'].leave(bv.session_data['fhash'])
    fhash = get_fhash(bv.file.filename)
    bv.session_data['client'] = client
    bv.session_data['fhash'] = fhash
    log_info('revsync: connecting with %s' % fhash)
    client.join(fhash, revsync_callback(bv))
    log_info('revsync: connected!')
    t1 = threading.Thread(target=watch_cur_func, args=(bv,))
    t2 = threading.Thread(target=watch_syms, args=(bv,SymbolType.DataSymbol))
    t3 = threading.Thread(target=watch_syms, args=(bv,SymbolType.FunctionSymbol))
    t1.daemon = True
    t2.daemon = True
    t3.daemon = True
    t1.start()
    t2.start()
    t3.start()

PluginCommand.register('revsync: load', 'load revsync!!!', revsync_load)
