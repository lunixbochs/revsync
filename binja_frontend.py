import hashlib
import time
from collections import defaultdict

from binaryninja import *
from binaryninja.plugin import PluginCommand

from client import Client
from config import config
from comments import Comments, NoChange
from coverage import Coverage

class State:
    @staticmethod
    def get(bv):
        return bv.session_data.get('revsync')

    show_visits = True
    show_length = True
    show_visitors = True
    track_coverage = True
    color_now = False
    running = False

    def __init__(self, bv):
        self.cov = Coverage()
        self.comments = Comments()
        self.fhash = get_fhash(bv.file.filename)
        self.running = True

    def close(self):
        self.running = False

IDLE_ASK = 250
COLOUR_PERIOD = 20
MAX_COLOR = 148
BB_REPORT = 50

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
    state = State.get(bv)
    if state:
        client.publish(state.fhash, data, **kwargs)

def push_cv(bv, data, **kwargs):
    state = State.get(bv)
    if state:
        client.push("%s_COVERAGE" % state.fhash, data, **kwargs)

def onmsg(bv, key, data, replay):
    state = State.get(bv)
    if key != state.fhash:
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
            text = state.comments.set(addr, user, data['text'], ts)
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
        log_info("Updating Global Coverage")
        # FIXME: don't double-json-encode data['blocks']
        state.cov.update(json.loads(data['blocks']))
        state.color_now = True
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

def colour_coverage(bv, cur_func):
    state = State.get(bv)
    for bb in cur_func.basic_blocks:
        color = state.cov.color(get_can_addr(bb.start), visits=state.show_visits, time=state.show_length, users=state.show_visitors)
        if color:
            r, g, b = color
            color = highlight.HighlightColor(red=int(r * MAX_COLOR), green=int(g * MAX_COLOR), blue=int(b * MAX_COLOR))
            bb.set_user_highlight(color)

def watch_syms(bv, sym_type):
    """ Watch symbols of a given type (e.g. DataSymbol) for changes and publish diffs """
    state = State.get(bv)

    def get_syms():
        # comes as list of Symbols
        syms = bv.get_symbols_of_type(sym_type)
        # turn our list into dict of addr => sym name
        syms_dict = dict()
        for sym in syms:
            syms_dict[sym.address] = sym.name
        return syms_dict

    last_syms = get_syms()
    while state.running:
        syms = get_syms()
        if syms != last_syms:
            for addr, name in syms.items():
                if last_syms.get(addr) != name:
                    # name changed, publish
                    log_info('revsync: user renamed symbol at %#x: %s' % (addr, name))
                    publish(bv, {'cmd': 'rename', 'addr': get_can_addr(bv, addr), 'text': name})
        last_syms = syms
        time.sleep(0.5)

def watch_cur_func(bv):
    """ Watch current function (if we're in code) for comment changes and publish diffs """
    def get_cur_func():
        return get_func_by_addr(bv, bv.offset)

    def get_cur_bb():
        return get_bb_by_addr(bv, bv.offset)

    state = State.get(bv)
    last_func = get_cur_func()
    last_bb = get_cur_bb()
    last_comments = {}
    last_stackvars = {}
    last_time = time.time()
    #temp_length = 0
    last_bb_report = time.time()
    last_bb_addr = None
    if last_func:
        last_comments = last_func.comments
        last_stackvars = stack_dict_from_list(last_func.vars)
    last_addr = None
    while state.running:
        now = time.time()
        if state.track_coverage and now - last_bb_report >= BB_REPORT:
            last_bb_report = now
            push_cv(bv, {'b': state.cov.flush()})

        if last_addr == bv.offset:
            time.sleep(0.25)
            continue
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
                                changed = state.comments.parse_comment_update(addr, client.nick, text)
                                log_info('revsync: user changed comment: %#x, %s' % (addr, changed))
                                publish(bv, {'cmd': 'comment', 'addr': addr, 'text': changed})
                            except NoChange:
                                pass
                            continue
                        elif last_comments.get(addr) != text:
                            # changed comment, publish
                            try:
                                addr = get_can_addr(bv, addr)
                                changed = state.comments.parse_comment_update(addr, client.nick, text)
                                log_info('resync: user changed comment: %#x, %s' % (addr, changed))
                                publish(bv, {'cmd': 'comment', 'addr': addr, 'text': changed})
                            except NoChange:
                                pass
                    # check for removed comments
                    if last_comments:
                        removed = set(last_comments.keys()) - set(comments.keys())
                        for addr in removed:
                            addr = get_can_addr(bv, addr)
                            log_info('revsync: user removed comment: %#x' % addr)
                            publish(bv, {'cmd': 'comment', 'addr': addr, 'text': ''})

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

                if state.track_coverage:
                    cur_bb = get_cur_bb()
                    if cur_bb != last_bb:
                        state.color_now = True
                        now = time.time()
                        if last_bb_addr is not None:
                            state.cov.visit_addr(last_bb_addr, elapsed=now - last_time, visits=1)
                        last_time = now
                        if cur_bb is None:
                            last_bb_addr = None
                        else:
                            last_bb_addr = get_can_addr(bv, cur_bb.start)

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

            if state.color_now:
                colour_coverage(bv, last_func)
                state.color_now = False

def revsync_load(bv):
    global client
    try:
        client
    except:
        client = Client(**config)
    state = bv.session_data.get('revsync')
    if state:
        # close out the previous session
        client.leave(state.fhash)
        state.close()

    state = bv.session_data['revsync'] = State(bv)
    log_info('revsync: connecting with %s' % state.fhash)
    client.join(state.fhash, revsync_callback(bv))
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
    state = State.get(bv)
    state.show_visits = not state.show_visits
    if state.show_visits:
        log_info("Visit Visualization Enabled (Red)")
    else:
        log_info("Visit Visualization Disabled (Red)")
    state.color_now = True

def toggle_length(bv):
    state = State.get(bv)
    state.show_length = not state.show_length
    if state.show_length:
        log_info("Length Visualization Enabled (Blue)")
    else:
        log_info("Length Visualization Disabled (Blue)")
    state.color_now = True

def toggle_visitors(bv):
    state = State.get(bv)
    state.show_visitors = not state.show_visitors
    if state.show_visitors:
        log_info("Visitor Visualization Enabled (Green)")
    else:
        log_info("Visitor Visualization Disabled (Green)")
    state.color_now = True

def toggle_track(bv):
    state = State.get(bv)
    state.track_coverage = not state.track_coverage
    if state.track_coverage:
        log_info("Tracking Enabled")
    else:
        log_info("Tracking Disabled")

PluginCommand.register('Coverage: Toggle Tracking', 'Toggle Tracking', toggle_track)
PluginCommand.register('Coverage: Toggle Visits (RED)', 'Toggle Red', toggle_visits)
PluginCommand.register('Coverage: Toggle Length (BLUE)', 'Toggle Blue', toggle_length)
PluginCommand.register('Coverage: Toggle Visitors (GREEN)', 'Toggle Green', toggle_visitors)
PluginCommand.register('revsync: load', 'load revsync!!!', revsync_load)
