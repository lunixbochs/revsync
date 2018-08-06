import hashlib
from time import sleep

from binaryninja import *
from binaryninja.plugin import PluginCommand

from client import Client
from config import config
from comments import NoChange
from comments import comments as cmt_data

SHOW_VISITS = True
SHOW_LENGTH = True
SHOW_VISITORS = False
TRACK_COVERAGE = True
IDLE_ASK = 250
COLOUR_PERIOD = 20
bb_coverage = {}

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

def get_bb_by_addr(bv, addr):
    bb = bv.get_basic_blocks_at(addr)
    if len(bb) > 0:
        return bb[0]
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

def publish(bv, data, **kwargs):
    if bv.session_data['fhash'] == get_fhash(bv.file.filename):
        bv.session_data['client'].publish(bv.session_data['fhash'], data, **kwargs)

def push_cv(bv, data, **kwargs):
    if bv.session_data['fhash'] == get_fhash(bv.file.filename):
        bv.session_data['client'].push("%s_COVERAGE" % bv.session_data['fhash'], data, **kwargs)

def update_bb_coverage(bv, cov):
    global bb_coverage
    for addr in cov.keys():
        bb = get_bb_by_addr(bv, get_ea(bv, int(addr)))
        if bb is not None:
            bb_coverage[bb] = cov[addr]

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
    elif cmd == 'stackvar_renamed':
        func_name = '???'
        func = get_func_by_addr(bv, data['addr'])
        if func:
            func_name = func.name
        log_info('revsync: <%s> %s %s %#x %s' % (user, cmd, func_name, data['offset'], data['name']))
        rename_stackvar(bv, data['addr'], data['offset'], data['name'])
    elif cmd == 'join':
        log_info('revsync: <%s> joined' % (user))
    elif cmd == 'coverage':
        log_info("Updating Coverage")
        update_bb_coverage(bv, json.loads(data['blocks']))
    else:
        log_info('revsync: unknown cmd %s' % data)

def revsync_callback(bv):
    def callback(key, data, replay=False):
        onmsg(bv, key, data, replay)
    return callback

def revsync_comment(bv, addr):
    comment = interaction.get_text_line_input('Enter comment: ', 'revsync comment')
    publish(bv, {'cmd': 'comment', 'addr': get_can_addr(bv, addr), 'text': comment or ''}, send_uuid=False)
    get_func_by_addr(bv, addr).set_comment(addr, comment)

def revsync_rename(bv, addr):
    name = interaction.get_text_line_input('Enter symbol name: ', 'revsync rename')
    publish(bv, {'cmd': 'rename', 'addr': get_can_addr(bv, addr), 'text': name})
    rename_symbol(bv, addr, name)

def colour_blocks(blocks, max_visits, max_length, max_visitors):
    global SHOW_VISITS
    global SHOW_LENGTH
    global SHOW_VISITORS
    for bb in blocks:
        cov = blocks[bb]
        R, B, G = 0, 0, 0
        if SHOW_VISITS and cov["v"] > 0:
            R = (cov["v"] * 0x96) / max_visits
        if SHOW_LENGTH and cov["l"] > 0:
            B = (cov["l"] * 0x96) / max_length
        if SHOW_VISITORS and cov["u"] > 0:
            G = (cov["u"] * 0x96) / max_visitors
        if R == 0 and B == 0 and G == 0:
            bb.set_user_highlight(highlight.HighlightColor(red=74, blue=74, green=74))
        else:
            bb.set_user_highlight(highlight.HighlightColor(red=R, blue=B, green=G))

def colour_coverage(cur_func):
    global bb_coverage
    if cur_func is None:
        return
    blocks = {}
    max_visits = 0
    max_length = 0
    max_visitors = 0
    for bb in bb_coverage:
        if bb_coverage[bb]["v"] > max_visits:
            max_visits = bb_coverage[bb]["v"]
        if bb_coverage[bb]["l"] > max_length:
            max_length = bb_coverage[bb]["l"]
        if bb_coverage[bb]["u"] > max_visitors:
            max_visitors = bb_coverage[bb]["u"]
        if bb.function == cur_func:
            blocks[bb] = bb_coverage[bb]
    colour_blocks(blocks, max_visits, max_length, max_visitors)

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
    global TRACK_COVERAGE
    """ Watch current function (if we're in code) for comment changes and publish diffs """
    def get_cur_func():
        return get_func_by_addr(bv, bv.offset)

    def get_cur_bb():
        return get_bb_by_addr(bv, bv.offset)

    last_func = get_cur_func()
    last_bb = get_cur_bb()
    last_comments = {}
    last_stackvars = {}
    bb_local_coverage = {}
    bb_interval = 0
    BB_REPORT = 10
    colour = 0
    COLOUR_PERIOD = 20
    if last_func:
        last_comments = last_func.comments
        last_stackvars = stack_dict_from_list(last_func.vars)
    last_addr = None
    while True:
        bb_interval += 1
        if bb_interval > BB_REPORT:
            if len(bb_local_coverage.keys()) > 0:
                new_bb_coverage = {}
                if last_bb:
                    bb_addr = get_can_addr(bv, last_bb.start)
                    new_bb_coverage[bb_addr] = {"v": 0, "l": 0}
                push_cv(bv, {"b": bb_local_coverage})
                bb_local_coverage = new_bb_coverage
                bb_interval = 0
        if last_addr == bv.offset:
            bb_start = get_can_addr(bv, last_bb.start)
            if bb_start in bb_local_coverage:
                bb_local_coverage[bb_start]["l"] += 1
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
                                publish(bv, {'cmd': 'stackvar_renamed', 'addr': last_func.start, 'offset': offset, 'name': cur_name})

                if TRACK_COVERAGE:
                    cur_bb = get_cur_bb()
                    if cur_bb != last_bb:
                        if cur_bb is not None:
                            cur_bb_addr = get_can_addr(bv, cur_bb.start)
                            if cur_bb_addr is not None:
                                if cur_bb_addr not in bb_coverage:
                                    bb_local_coverage[cur_bb_addr] = {"v": 0, "l": 0}
                                    bb_local_coverage[cur_bb_addr]["v"] += 1

            # update current function/addr info
            last_func = get_cur_func()
            last_bb = get_cur_bb()
            if last_func:
                last_comments = last_func.comments
                last_stackvars = stack_dict_from_list(last_func.vars)
            else:
                last_comments = {}
                last_stackvars = {} 
            last_addr = bv.offset
        colour += 1
        if colour > COLOUR_PERIOD:
            colour_coverage(last_func)
            colour = 0

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

def toggle_visits(bv):
    global SHOW_VISITS
    SHOW_VISITS = not SHOW_VISITS
    if SHOW_VISITS:
        log_info("Visit Visualization Enabled (Red)")
    else:
        log_info("Visit Visualization Disabled (Red)")

def toggle_length(bv):
    global SHOW_LENGTH
    SHOW_LENGTH = not SHOW_LENGTH
    if SHOW_LENGTH:
        log_info("Length Visualization Enabled (Blue)")
    else:
        log_info("Length Visualization Disabled (Blue)")

def toggle_visitors(bv):
    global SHOW_VISITORS
    SHOW_VISITORS = not SHOW_VISITORS
    if SHOW_VISITORS:
        log_info("Visitor Visualization Enabled (Green)")
    else:
        log_info("Visitor Visualization Disabled (Green)")

def toggle_track(bv):
    global TRACK_COVERAGE
    TRACK_COVERAGE = not TRACK_COVERAGE
    if TRACK_COVERAGE:
        log_info("Tracking Enabled")
    else:
        log_info("Tracking Disabled")

PluginCommand.register('Coverage: Toggle Tracking', 'Toggle Tracking', toggle_track)
PluginCommand.register('Coverage: Toggle Visits (RED)', 'Toggle Red', toggle_visits)
PluginCommand.register('Coverage: Toggle Length (BLUE)', 'Toggle Blue', toggle_length)
PluginCommand.register('Coverage: Toggle Visitors (GREEN)', 'Toggle Green', toggle_visitors)
PluginCommand.register('revsync: load', 'load revsync!!!', revsync_load)
