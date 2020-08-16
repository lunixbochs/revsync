import math
import time
import hashlib
from collections import defaultdict

from vivisect import *

from client import Client
from config import config
from comments import Comments, NoChange
from coverage import Coverage
from threading import Lock
from collections import namedtuple

Struct = namedtuple('Struct', 'name typedef')

class State:
    @staticmethod
    def get(vw):
        return vw.metadata.get('revsync')

    show_visits = True
    show_time = True
    show_visitors = False
    track_coverage = True
    color_now = False
    running = False

    def __init__(self, vw):
        self.cov = Coverage()
        self.comments = Comments()
        self.running = True
        self.cmt_changes = {} 
        self.cmt_lock = Lock()
        self.stackvar_changes = {} 
        self.stackvar_lock = Lock()
        self.syms = get_syms(vw)
        self.syms_lock = Lock()
        self.structs = {}   # get_structs(vw) 
        self.structs_lock = Lock()

        self.filedata_by_sha = {}
        self.filedata_by_fname = {}
        for fname in vw.getFiles():
            sha256 = vw.getFileMeta(fname, 'sha256')
            mdict = dict(vw.getFileMetaDict(fname))
            mdict['name'] = fname
            self.filedata_by_sha[sha256] = mdict
            self.filedata_by_fname[fname] = mdict

    def close(self):
        # close out the previous session
        for shaval in self.genFhashes():
            client.leave(shaval)

        self.running = False

    def getMetaBySha(self, key):
        return self.filedata_by_sha.get(key)

    def getMetaByFname(self, key):
        return self.filedata_by_fname.get(key)

    def genFhashes(self):
        for fdict in self.filedata_by_sha.values():
            try:
                yield fdict['sha256']
            except KeyError:
                print "keyerror: no 'sha256' key in metadict: %r" % fdict

MIN_COLOR = 0
MAX_COLOR = 200

IDLE_ASK = 250
COLOUR_PERIOD = 20
BB_REPORT = 50


def get_can_addr(vw, addr):
    fname = vw.getFileByVa(addr)
    if fname is None:
        raise Exception("ARRG! get_can_addr(0x%x)" % addr)

    imagebase = vw.getFileMeta(fname, 'imagebase')
    return addr - imagebase

def get_ea(vw, sha_key, addr):
    imagebase = None
    for fname in vw.getFiles():
        fmeta = vw.getFileMetaDict(fname)
        if fmeta.get('sha256') == sha_key:
            imagebase = fmeta.get('imagebase')
            break

    return addr + imagebase

def get_func_by_addr(vw, addr):
    return vw.getFunction(addr)

def get_bb_by_addr(bv, addr):
    return vw.getCodeBlock(addr)

# in order to map IDA type sizes <-> binja types,
# take the 'size' field and attempt to divine some
# kind of type in binja that's close as possible.
# right now, that means try to use uint8_t ... uint64_t,
# anything bigger just make an array
def get_type_by_size(bv, size):
    typedef = None
    if size <= 8:
        try:
            typedef, name = bv.parse_type_string('uint{}_t'.format(8*size))
        except SyntaxError:
            pass
    else:
        try:
            typedef, name = bv.parse_type_string('char a[{}]'.format(8*size))
        except SyntaxError:
            pass
    return typedef

def get_structs(bv):
    d = dict()
    for name, typedef in bv.types.items():
        if typedef.structure:
            typeid = bv.get_type_id(name)
            struct = Struct(name, typedef.structure)
            d[typeid] = struct
    return d

def get_syms(vw):
    syms = dict(vw.name_by_va)
    return syms

def stack_dict_from_list(stackvars):
    d = {}
    for var in stackvars:
        d[var.storage] = (var.name, var.type)
    return d

def member_dict_from_list(members):
    d = {}
    for member in members:
        d[member.name] = member
    return d

def rename_symbol(vw, addr, name):
    vw.makeName(addr, name)
    '''
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
    '''

def rename_stackvar(bv, func_addr, offset, name):
    func = get_func_by_addr(bv, func_addr)
    if func is None:
        vw.vprint('revsync: bad func addr %#x during rename_stackvar' % func_addr)
        return
    # we need to figure out the variable type before renaming
    stackvars = stack_dict_from_list(func.vars)
    var = stackvars.get(offset)
    if var is None:
        vw.vprint('revsync: could not locate stack var with offset %#x during rename_stackvar' % offset)
        return
    var_name, var_type = var
    func.create_user_stack_var(offset, var_type, name)
    return

def publish(vw, data, fhash, **kwargs):
    state = State.get(vw)
    if state:
        client.publish(fhash, data, **kwargs)

def push_cv(vw, data, **kwargs):
    state = State.get(vw)
    if state:
        client.push("%s_COVERAGE" % state.fhash, data, **kwargs)

def map_color(x):
    n = x
    if x == 0: return 0
    # x = min(max(0, (x ** 2) / (2 * (x ** 2 - x) + 1)), 1)
    # if x == 0: return 0
    return int(math.ceil((MAX_COLOR - MIN_COLOR) * x + MIN_COLOR))

def convert_color(color):
    r, g, b = [map_color(x) for x in color]
    return highlight.HighlightColor(red=r, green=g, blue=b)

def colour_coverage(bv, cur_func):
    state = State.get(bv)
    for bb in cur_func.basic_blocks:
        color = state.cov.color(get_can_addr(bv, bb.start), visits=state.show_visits, time=state.show_time, users=state.show_visitors)
        if color:
            bb.set_user_highlight(convert_color(color))
        else:
            bb.set_user_highlight(highlight.HighlightColor(red=74, blue=74, green=74))

def watch_structs(bv):
    """ Check structs for changes and publish diffs"""
    state = State.get(bv)

    while state.running:
        state.structs_lock.acquire()
        structs = get_structs(bv)
        if structs != state.structs:
            for struct_id, struct in structs.items():
                last_struct = state.structs.get(struct_id)
                struct_name = struct.name
                if last_struct == None:
                    # new struct created, publish
                    vw.vprint('revsync: user created struct %s' % struct_name)
                    # binja can't really handle unions at this time
                    publish(bv, {'cmd': 'struc_created', 'struc_name': str(struct_name), 'is_union': False})
                    # if there are already members, publish them
                    members = member_dict_from_list(struct.typedef.members)
                    if members:
                        for member_name, member_def in members.items():
                            publish(bv, {'cmd': 'struc_member_created', 'struc_name': str(struct_name), 'offset': member_def.offset, 'member_name': member_name, 'size': member_def.type.width, 'flag': None})
                    continue
                last_name = last_struct.name
                if last_name != struct_name:
                    # struct renamed, publish
                    vw.vprint('revsync: user renamed struct %s' % struct_name)
                    publish(bv, {'cmd': 'struc_renamed', 'old_name': str(last_name), 'new_name': str(struct_name)})
                
                # check for member differences
                members = member_dict_from_list(struct.typedef.members)
                last_members = member_dict_from_list(last_struct.typedef.members)

                # first checks for deletions
                removed_members = set(last_members.keys()) - set(members.keys())
                for member in removed_members:
                    vw.vprint('revsync: user deleted struct member %s in struct %s' % (last_members[member].name, str(struct_name)))
                    publish(bv, {'cmd': 'struc_member_deleted', 'struc_name': str(struct_name), 'offset': last_members[member].offset})

                # now check for additions
                new_members = set(members.keys()) - set(last_members.keys())
                for member in new_members:
                    vw.vprint('revsync: user added struct member %s in struct %s' % (members[member].name, str(struct_name)))
                    publish(bv, {'cmd': 'struc_member_created', 'struc_name': str(struct_name), 'offset': members[member].offset, 'member_name': str(member), 'size': members[member].type.width, 'flag': None})

                # check for changes among intersection of members
                intersec = set(members.keys()) & set(last_members.keys())
                for m in intersec:
                    if members[m].type.width != last_members[m].type.width:
                        # type (i.e., size) changed
                        vw.vprint('revsync: user changed struct member %s in struct %s' % (members[m].name, str(struct_name)))
                        publish(bv, {'cmd': 'struc_member_changed', 'struc_name': str(struct_name), 'offset': members[m].offset, 'size': members[m].type.width})

            for struct_id, struct_def in state.structs.items():
                if structs.get(struct_id) == None:
                    # struct deleted, publish
                    vw.vprint('revsync: user deleted struct %s' % struct_def.name)
                    publish(bv, {'cmd': 'struc_deleted', 'struc_name': str(struct_def.name)})
        state.structs = get_structs(bv)
        state.structs_lock.release()
        time.sleep(0.5)



'''
################################################################ unused
def watch_syms(bv, sym_type):
    """ Watch symbols of a given type (e.g. DataSymbol) for changes and publish diffs """
    state = State.get(bv)

    while state.running:
        state.syms_lock.acquire()
        # DataSymbol
        data_syms = get_syms(bv, SymbolType.DataSymbol)
        if data_syms != state.data_syms:
            for addr, name in data_syms.items():
                if state.data_syms.get(addr) != name:
                    # name changed, publish
                    vw.vprint('revsync: user renamed symbol at %#x: %s' % (addr, name))
                    publish(bv, {'cmd': 'rename', 'addr': get_can_addr(bv, addr), 'text': name})

        # FunctionSymbol
        func_syms = get_syms(bv, SymbolType.FunctionSymbol)
        if func_syms != state.func_syms:
            for addr, name in func_syms.items():
                if state.func_syms.get(addr) != name:
                    # name changed, publish
                    vw.vprint('revsync: user renamed symbol at %#x: %s' % (addr, name))
                    publish(bv, {'cmd': 'rename', 'addr': get_can_addr(bv, addr), 'text': name})

        state.data_syms = get_syms(bv, SymbolType.DataSymbol)
        state.func_syms = get_syms(bv, SymbolType.FunctionSymbol)
        state.syms_lock.release()
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
    last_time = time.time()
    last_bb_report = time.time()
    last_bb_addr = None
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
                state.cmt_lock.acquire()
                comments = last_func.comments
                # check for changed comments
                for cmt_addr, cmt in comments.items():
                    last_cmt = state.cmt_changes.get(cmt_addr)
                    if last_cmt == None or last_cmt != cmt:
                        # new/changed comment, publish
                        try:
                            addr = get_can_addr(bv, cmt_addr)
                            changed = state.comments.parse_comment_update(addr, client.nick, cmt)
                            vw.vprint('revsync: user changed comment: %#x, %s' % (addr, changed))
                            publish(bv, {'cmd': 'comment', 'addr': addr, 'text': changed})
                            state.cmt_changes[cmt_addr] = changed
                        except NoChange:
                            pass
                        continue

                # TODO: this needs to be fixed later
                """
                # check for removed comments
                if last_comments:
                    removed = set(last_comments.keys()) - set(comments.keys())
                    for addr in removed:
                        addr = get_can_addr(bv, addr)
                        vw.vprint('revsync: user removed comment: %#x' % addr)
                        publish(bv, {'cmd': 'comment', 'addr': addr, 'text': ''})
                """
                state.cmt_lock.release()

                # similar dance, but with stackvars
                state.stackvar_lock.acquire()
                stackvars = stack_dict_from_list(last_func.vars)
                for offset, data in stackvars.items():
                    # stack variables are more difficult than comments to keep state on, since they
                    # exist from the beginning, and have a type.  track each one.  start by tracking the first
                    # time we see it.  if there are changes after that, publish.
                    stackvar_name, stackvar_type = data
                    stackvar_val = state.stackvar_changes.get((last_func.start,offset))
                    if stackvar_val == None:
                        # never seen before, start tracking
                        state.stackvar_changes[(last_func.start,offset)] = stackvar_name
                    elif stackvar_val != stackvar_name:
                        # stack var name changed, publish
                        vw.vprint('revsync: user changed stackvar name at offset %#x to %s' % (offset, stackvar_name))
                        publish(bv, {'cmd': 'stackvar_renamed', 'addr': last_func.start, 'offset': offset, 'name': stackvar_name})
                        state.stackvar_changes[(last_func.start,offset)] = stackvar_name
                state.stackvar_lock.release()

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
            last_addr = bv.offset

        if state.color_now and last_func != None:
            colour_coverage(bv, last_func)
            state.color_now = False
################################################## ends: unused
'''

def do_analysis_and_wait(vw):
    vw.vprint('revsync: running analysis update...')
    vw.analyze()
    vw.vprint('revsync: analysis finished.')
    return

### handle remote events:
def onmsg(vw, key, data, replay):
    print "onmsg: %r : %r  (%r)" % (key, data, replay)
    try:
        state = State.get(vw)
        meta = state.getMetaBySha(key)
        if meta is None:
            vw.vprint('revsync: hash mismatch, dropping command')
            return

        cmd, user = data['cmd'], data['user']
        ts = int(data.get('ts', 0))
        if cmd == 'comment':
            state.cmt_lock.acquire()
            vw.vprint('revsync: <%s> %s %#x %s' % (user, cmd, data['addr'], data['text']))
            addr = get_ea(vw, key, int(data['addr']))
            #func = get_func_by_addr(vw, addr)
            ## binja does not support comments on data symbols??? IDA does.
            #if func is not None:
            text = state.comments.set(addr, user, data['text'], ts)
            vw.setComment(addr, text)
            state.cmt_changes[addr] = text
            state.cmt_lock.release()

        elif cmd == 'extra_comment':
            vw.vprint('revsync: <%s> %s %#x %s' % (user, cmd, data['addr'], data['text']))

        elif cmd == 'area_comment':
            vw.vprint('revsync: <%s> %s %s %s' % (user, cmd, data['range'], data['text']))

        elif cmd == 'rename':
            state.syms_lock.acquire()
            vw.vprint('revsync: <%s> %s %#x %s' % (user, cmd, data['addr'], data['text']))
            addr = get_ea(vw, key, int(data['addr']))
            rename_symbol(vw, addr, data['text'])
            state.syms = get_syms(vw)
            state.syms_lock.release()

        elif cmd == 'stackvar_renamed':
            state.stackvar_lock.acquire()
            func_name = '???'
            func = get_func_by_addr(vw, data['addr'])
            if func:
                func_name = vw.getName(func)
            vw.vprint('revsync: <%s> %s %s %#x %s' % (user, cmd, func_name, data['offset'], data['name']))
            rename_stackvar(vw, data['addr'], data['offset'], data['name'])
            # save stackvar changes using the tuple (func_addr, offset) as key
            state.stackvar_changes[(data['addr'],data['offset'])] = data['name']
            state.stackvar_lock.release()

        elif cmd == 'struc_created':
            # note: binja does not seem to appreciate the encoding of strings from redis
            struct_name = data['struc_name'].encode('ascii', 'ignore')
            '''  not ready to wrap this into Viv yet.
            state.structs_lock.acquire()
            struct = bv.get_type_by_name(struct_name)
            # if a struct with the same name already exists, undefine it
            if struct:
                bv.undefine_user_type(struct_name)
            struct = Structure()
            bv.define_user_type(struct_name, binaryninja.types.Type.structure_type(struct))
            state.structs = get_structs(bv)
            state.structs_lock.release()
            '''
            vw.vprint('revsync: <%s> %s %s' % (user, cmd, struct_name))
        elif cmd == 'struc_deleted':
            struct_name = data['struc_name'].encode('ascii', 'ignore')
            '''  not ready to wrap this into Viv yet.
            state.stackvar_lock.acquire()
            struct = bv.get_type_by_name(struct_name)
            # make sure the type is defined first
            if struct is None:
                vw.vprint('revsync: unknown struct name %s during struc_deleted cmd' % struct_name)
                return
            bv.undefine_user_type(struct_name)
            state.structs = get_structs(bv)
            state.structs_lock.release()
            '''
            vw.vprint('revsync: <%s> %s %s' % (user, cmd, struct_name))
        elif cmd == 'struc_renamed':
            old_struct_name = data['old_name'].encode('ascii', 'ignore')
            new_struct_name = data['new_name'].encode('ascii', 'ignore')
            '''  not ready to wrap this into Viv yet.
            state.structs_lock.acquire()
            struct = bv.get_type_by_name(old_struct_name)
            # make sure the type is defined first
            if struct is None:
                vw.vprint('revsync: unknown struct name %s during struc_renamed cmd' % old_struct_name)
                return
            bv.rename_type(old_struct_name, new_struct_name)
            state.structs = get_structs(bv)
            state.structs_lock.release()
            '''
            vw.vprint('revsync: <%s> %s %s %s' % (user, cmd, old_struct_name, new_struct_name))
        elif cmd == 'struc_member_created':
            struct_name = data['struc_name'].encode('ascii', 'ignore')
            '''  not ready to wrap this into Viv yet.
            state.structs_lock.acquire()
            struct = bv.get_type_by_name(struct_name)
            if struct is None:
                vw.vprint('revsync: unknown struct name %s during struc_member_created cmd' % struct_name)
                return
            member_name = data['member_name'].encode('ascii', 'ignore')
            struct_type = get_type_by_size(bv, data['size'])
            if struct_type is None:
                vw.vprint('revsync: bad struct member size %d for member %s during struc_member_created cmd' % (data['size'], member_name))
                return
            # need actual Structure class, not Type
            struct = struct.structure
            struct.insert(data['offset'], struct_type, member_name)
            # we must redefine the type
            bv.define_user_type(struct_name, binaryninja.types.Type.structure_type(struct))
            state.structs = get_structs(bv)
            state.structs_lock.release()
            '''
            vw.vprint('revsync: <%s> %s %s->%s' % (user, cmd, struct_name, member_name))
        elif cmd == 'struc_member_deleted':
            struct_name = data['struc_name'].encode('ascii', 'ignore')
            member_name = '???'
            '''  not ready to wrap this into Viv yet.
            state.structs_lock.acquire()
            struct = bv.get_type_by_name(struct_name)
            if struct is None:
                vw.vprint('revsync: unknown struct name %s during struc_member_deleted cmd' % struct_name)
                return
            offset = data['offset']
            # need actual Structure class, not Type
            struct = struct.structure
            # walk the list and find the index to delete (seriously, why by index binja and not offset?)
            member_name = '???'
            for i,m in enumerate(struct.members):
                if m.offset == offset:
                    # found it
                    member_name = m.name
                    struct.remove(i)
            # we must redefine the type
            bv.define_user_type(struct_name, binaryninja.types.Type.structure_type(struct))
            state.structs = get_structs(bv)
            state.structs_lock.release()
            '''
            vw.vprint('revsync: <%s> %s %s->%s' % (user, cmd, struct_name, member_name))
        elif cmd == 'struc_member_renamed':
            struct_name = data['struc_name'].encode('ascii', 'ignore')
            member_name = data['member_name'].encode('ascii', 'ignore')
            '''  not ready to wrap this into Viv yet.
            state.structs_lock.acquire()
            struct = bv.get_type_by_name(struct_name)
            if struct is None:
                vw.vprint('revsync: unknown struct name %s during struc_member_renamed cmd' % struct_name)
                return
            offset = data['offset']
            # need actual Structure class, not Type
            struct = struct.structure
            for i,m in enumerate(struct.members):
                if m.offset == offset:
                    struct.replace(i, m.type, member_name)
                    bv.define_user_type(struct_name, binaryninja.types.Type.structure_type(struct))
                    vw.vprint('revsync: <%s> %s %s->%s' % (user, cmd, struct_name, member_name))
                    break
            state.structs = get_structs(bv)
            state.structs_lock.release()
            '''
            vw.vprint('revsync: <%s> %s %s->%s' % (user, cmd, struct_name, member_name))
        elif cmd == 'struc_member_changed':
            struct_name = data['struc_name'].encode('ascii', 'ignore')
            '''  not ready to wrap this into Viv yet.
            state.structs_lock.acquire()
            struct = bv.get_type_by_name(struct_name)
            if struct is None:
                vw.vprint('revsync: unknown struct name %s during struc_member_renamed cmd' % struct_name)
                return
            # need actual Structure class, not Type
            struct = struct.structure
            offset = data['offset']
            for i,m in enumerate(struct.members):
                if m.offset == offset:
                    struct.replace(i, get_type_by_size(bv, data['size']), m.name)
                    bv.define_user_type(struct_name, binaryninja.types.Type.structure_type(struct))
                    vw.vprint('revsync: <%s> %s %s->%s' % (user, cmd, struct_name, m.name))
                    break
            state.structs = get_structs(bv)
            state.structs_lock.release()
            '''
            vw.vprint('revsync: <%s> %s %s->%s' % (user, cmd, struct_name, m.name))
        elif cmd == 'join':
            vw.vprint('revsync: <%s> joined' % (user))
        elif cmd == 'coverage':
            vw.vprint("Updating Global Coverage")
            state.cov.update(json.loads(data['blocks']))
            state.color_now = True
        else:
            vw.vprint('revsync: unknown cmd %s' % data)

    except Exception as e:
        vw.vprint('onmsg error: %r' % e)

def revsync_callback(vw):
    def callback(key, data, replay=False):
        onmsg(vw, key, data, replay)
    return callback

'''
def revsync_comment(vw, addr):
    comment = interaction.get_text_line_input('Enter comment: ', 'revsync comment')
    publish(vw, {'cmd': 'comment', 'addr': get_can_addr(vw, addr), 'text': comment or ''}, send_uuid=False)
    get_func_by_addr(vw, addr).set_comment(addr, comment)

def revsync_rename(vw, addr):
    name = interaction.get_text_line_input('Enter symbol name: ', 'revsync rename')
    publish(vw, {'cmd': 'rename', 'addr': get_can_addr(vw, addr), 'text': name})
    rename_symbol(vw, addr, name)
'''

### handle local events and hand up to REDIS
import vivisect.base as viv_base
class VivEventClient(viv_base.VivEventCore):
    # make sure all VA's are reduced to base-addr-offsets
    def VWE_COMMENT(self, vw, event, loc):
        print vw, event, loc
        # make sure something has changed (and that we're not repeating what we just received from revsync
        # publish comment to revsync
        #fname, fhash, offset = self.getFileContext(vw, loc[L_VA])
        publish(vw, {'cmd': 'comment', 'addr': get_can_addr(vw, addr), 'text': comment or ''}, send_uuid=False)

    def VWE_SETNAME(self, vw, event, loc):
        print vw, event, loc
        publish(vw, {'cmd': 'rename', 'addr': get_can_addr(vw, addr), 'text': name})

    def VWE_SETFUNCARGS(self, vw, event, loc):
        print vw, event, loc

    def VWE_SETFUNCMETA(self, vw, event, loc):
        print vw, event, loc


    def VWE_ADDLOCATION(self, vw, event, loc):
        # what kind of location?
        # * LOC_STRUCT
        # * LOC_STRING
        # * LOC_UNICODE
        # * LOC_POINTER
        # * LOC_NUMBER
        # * LOC_OP
        if loc[L_LTYPE] is LOC_OP:
            return
        print vw, event, loc

    def VWE_DELLOCATION(self, vw, event, loc):
        print vw, event, loc

    def VWE_SETMETA(self, vw, event, loc):
        print vw, event, loc

    def VWE_ADDFUNCTION(self, vw, event, loc):
        print vw, event, loc

    def VWE_DELFUNCTION(self, vw, event, loc):
        print vw, event, loc

    def VWE_ADDCOLOR(self, vw, event, loc):
        print vw, event, loc

    def VWE_DELCOLOR(self, vw, event, loc):
        print vw, event, loc

    def VWE_CHAT(self, vw, event, loc):
        print vw, event, loc


client = None
evtdist = None


def revsync_load(vw):
    global client, evtdist

    ### hook into the viv event stream

    # lets ensure auto-analysis is finished by forcing another analysis
    t0 = threading.Thread(target=do_analysis_and_wait, args=(vw,))
    t0.start()
    t0.join()

    if client is None:
        client = Client(**config)

    state = vw.metadata.get('revsync')
    if state:
        state.close()

    vw.vprint('revsync: working...')
    state = vw.metadata['revsync'] = State(vw)
    vw.vprint('revsync: connecting with hashes: %s' % repr([x for x in state.genFhashes()]))

    for fhash in state.genFhashes():
        client.join(fhash, revsync_callback(vw))

    vw.vprint('revsync: connected!')

    if evtdist is None:
        evtdist = VivEventClient(vw)


def toggle_visits(bv):
    state = State.get(bv)
    state.show_visits = not state.show_visits
    if state.show_visits:
        vw.vprint("Visit Visualization Enabled (Red)")
    else:
        vw.vprint("Visit Visualization Disabled (Red)")
    state.color_now = True

def toggle_time(bv):
    state = State.get(bv)
    state.show_time = not state.show_time
    if state.show_time:
        vw.vprint("Time Visualization Enabled (Blue)")
    else:
        vw.vprint("Time Visualization Disabled (Blue)")
    state.color_now = True

def toggle_visitors(bv):
    state = State.get(bv)
    state.show_visitors = not state.show_visitors
    if state.show_visitors:
        vw.vprint("Visitor Visualization Enabled (Green)")
    else:
        vw.vprint("Visitor Visualization Disabled (Green)")
    state.color_now = True

def toggle_track(bv):
    state = State.get(bv)
    state.track_coverage = not state.track_coverage
    if state.track_coverage:
        vw.vprint("Tracking Enabled")
    else:
        vw.vprint("Tracking Disabled")


######### register the plugin #########
import sys
try:
    from PyQt5 import QtGui,QtCore
except:
    from PyQt4 import QtGui,QtCore

from vqt.main import idlethread,idlethreadsync
from vqt.basics import VBox
from vqt.common import *

@idlethread
def vivExtension(vw, vwgui):
    vwgui.vqAddMenuField('&Tools.&revsync.&Coverage: Toggle Tracking', ACT(toggle_track))
    vwgui.vqAddMenuField('&Tools.&revsync.&Coverage: Toggle Visits (RED)', ACT(toggle_visits))
    vwgui.vqAddMenuField('&Tools.&revsync.&Coverage: Toggle Time (BLUE)', ACT(toggle_time))
    vwgui.vqAddMenuField('&Tools.&revsync.&Coverage: Toggle Visitors (GREEN)', ACT(toggle_visitors))
    vwgui.vqAddMenuField('&Tools.&revsync.&load', 'load revsync!!!', ACT(revsync_load))

def register(vw, vwgui):
    import vqt.main as vq_main
    vq_main.guiq.append((vivExtension, (), {'vw':vw, 'vwgui':vwgui}, ))

if globals().get('vwgui') is not None:
    register(vw, vwgui)

