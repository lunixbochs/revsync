import math
import time
import hashlib
import logging
from collections import defaultdict

from vivisect import *

from client import Client
from config import config
from comments import Comments, NoChange
from coverage import Coverage
from threading import Lock
from collections import namedtuple

logger = logging.getLogger(__name__)

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
            mdict['maps'] = [mmap for mmap in vw.getMemoryMaps() if mmap[MAP_FNAME] == fname]
            mdict['sha256'] = sha256
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

    def getHashByAddr(self, addr):
        for mdict in self.filedata_by_fname.values():
            for mmap in mdict.get('maps'):
                mva, msz, mperm, mfname = mmap
                if addr >= mva and addr < mva+msz:
                    fhash = mdict.get('sha256')
                    return fhash, mfname

    def genFhashes(self):
        for fdict in self.filedata_by_sha.values():
            try:
                yield fdict['sha256']
            except KeyError:
                vw.vprint("keyerror: no 'sha256' key in metadict: %r" % fdict)

MIN_COLOR = 0
MAX_COLOR = 200

IDLE_ASK = 250
COLOUR_PERIOD = 20
BB_REPORT = 50


def get_can_addr(vw, addr):     #done
    '''
    normalizing addresses
    '''
    fname = vw.getFileByVa(addr)
    if fname is None:
        raise Exception("ARRG! get_can_addr(0x%x)" % addr)

    imagebase = vw.getFileMeta(fname, 'imagebase')
    return addr - imagebase

def get_ea(vw, sha_key, addr):      #done
    '''
    normalizing addresses
    '''
    imagebase = None
    for fname in vw.getFiles():
        fmeta = vw.getFileMetaDict(fname)
        if fmeta.get('sha256') == sha_key:
            imagebase = fmeta.get('imagebase')
            break

    return addr + imagebase

def get_func_by_addr(vw, addr):     #done
    return vw.getFunction(addr)

def get_bb_by_addr(vw, addr):
    return vw.getCodeBlock(addr)        #done

# in order to map IDA type sizes <-> viv types,
# take the 'size' field and attempt to divine some
# kind of type in viv that's close as possible.
# right now, that means try to use uint8_t ... uint64_t,
# anything bigger just make an array
def get_type_by_size(vw, size):
    typedef = None
    if size <= 8:
        try:
            typedef, name = vw.parse_type_string('uint{}_t'.format(8*size))
        except SyntaxError:
            pass
    else:
        try:
            typedef, name = vw.parse_type_string('char a[{}]'.format(8*size))
        except SyntaxError:
            pass
    return typedef

def get_syms(vw):   #done
    syms = dict(vw.name_by_va)
    return syms

def stack_dict_from_list(stackvars):
    d = {}
    for fva, offset, unknown, (vartype, varname) in stackvars:
        d[offset] = (varname, vartype)
    return d

def rename_symbol(vw, addr, name):  # done
    vw.makeName(addr, name)

def rename_stackvar(vw, func_addr, offset, name):   # TESTME
    func = vw.getFunction(func_addr)
    if func is None:
        vw.vprint('revsync: bad func addr %#x during rename_stackvar' % func_addr)
        return

    # we need to figure out the variable type before renaming
    stackvars = stack_dict_from_list(vw.getFunctionLocals(func_addr))
    var = stackvars.get(offset)
    if var is None:
        vw.vprint('revsync: could not locate stack var with offset %#x during rename_stackvar' % offset)
        return
    var_name, var_type = var
    # CHECKME: does this set function args too?  do i need to split them?
    vw.setFunctionLocal(func_addr, offset, var_type, name)
    #aidx = offset // vw.getPointerSize()
    #vw.setFunctionArg(func_addr, aidx, var_type, name)
    return

def publish(vw, data, fhash, **kwargs):
    state = State.get(vw)
    if state:
        client.publish(fhash, data, **kwargs)

def analyze(vw):   #done
    vw.vprint('revsync: running analysis update...')
    vw.analyze()
    vw.vprint('revsync: analysis finished.')
    return





##### structs are not currently supported
def get_structs(vw):
    d = dict()
    for name, typedef in vw.types.items():
        if typedef.structure:
            typeid = vw.get_type_id(name)
            struct = Struct(name, typedef.structure)
            d[typeid] = struct
    return d

def member_dict_from_list(members):
    d = {}
    for member in members:
        d[member.name] = member
    return d


#### again, no struct just yet
def watch_structs(vw):
    """ Check structs for changes and publish diffs"""
    state = State.get(vw)

    while state.running:
        state.structs_lock.acquire()
        structs = get_structs(vw)
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

###### Coverage not yet implemented
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




### handle remote events:
def onmsg(vw, key, data, replay):
    logger.warning("onmsg: %r : %r  (%r)" % (key, data, replay))
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
            vw.vprint('revsync: <%s> %s %s' % (user, cmd, struct_name))
        
        elif cmd == 'struc_deleted':
            struct_name = data['struc_name'].encode('ascii', 'ignore')
            vw.vprint('revsync: <%s> %s %s' % (user, cmd, struct_name))
        
        elif cmd == 'struc_renamed':
            old_struct_name = data['old_name'].encode('ascii', 'ignore')
            new_struct_name = data['new_name'].encode('ascii', 'ignore')
            vw.vprint('revsync: <%s> %s %s %s' % (user, cmd, old_struct_name, new_struct_name))
        
        elif cmd == 'struc_member_created':
            struct_name = data['struc_name'].encode('ascii', 'ignore')
            vw.vprint('revsync: <%s> %s %s->%s' % (user, cmd, struct_name, member_name))
        
        elif cmd == 'struc_member_deleted':
            struct_name = data['struc_name'].encode('ascii', 'ignore')
            member_name = '???'
            vw.vprint('revsync: <%s> %s %s->%s' % (user, cmd, struct_name, member_name))
            
        elif cmd == 'struc_member_renamed':
            struct_name = data['struc_name'].encode('ascii', 'ignore')
            member_name = data['member_name'].encode('ascii', 'ignore')
            vw.vprint('revsync: <%s> %s %s->%s' % (user, cmd, struct_name, member_name))

        elif cmd == 'struc_member_changed':
            struct_name = data['struc_name'].encode('ascii', 'ignore')
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

def revsync_callback(vw):   #done
    def callback(key, data, replay=False):
        onmsg(vw, key, data, replay)
    return callback


### handle local events and hand up to REDIS
import vivisect.base as viv_base
class VivEventClient(viv_base.VivEventCore):
    def __init__(self, vw):
        viv_base.VivEventCore.__init__(self, vw)
        self.mythread = self._ve_fireListener()
        self.state = vw.getMeta('revsync')

    # make sure all VA's are reduced to base-addr-offsets
    def VWE_COMMENT(self, vw, event, locinfo):  #done
        logger.warning("%r  %r  %r" % (vw, event, locinfo))
        cmt_addr, cmt = locinfo
        # make sure something has changed (and that we're not repeating what we just received from revsync
        # publish comment to revsync
        last_cmt = self.state.cmt_changes.get(cmt_addr)
        if last_cmt is None or last_cmt != cmt:
            # new/changed comment, publish
            try:
                fhash, fname = self.state.getHashByAddr(cmt_addr)
                addr = get_can_addr(vw, cmt_addr)
                changed = self.state.comments.parse_comment_update(addr, client.nick, cmt)
                vw.vprint('revsync: user changed comment: %#x, %s' % (addr, changed))
                publish(vw, {'cmd': 'comment', 'addr': addr, 'text': changed}, fhash)
                self.state.cmt_changes[cmt_addr] = changed
            except NoChange:
                pass

    def VWE_SETNAME(self, vw, event, locinfo):  #done
        logger.warning("%r  %r  %r" % (vw, event, locinfo))
        name_addr, name = locinfo
        addr = get_can_addr(vw, name_addr)
        if self.state.syms.get(addr) != name:
            # name changed, publish
            fhash, fname = self.state.getHashByAddr(name_addr)
            vw.vprint('revsync: user renamed symbol at %#x: %s' % (addr, name))
            publish(vw, {'cmd': 'rename', 'addr': addr, 'text': name}, fhash)
            self.state.syms[addr] = name

    def VWE_SETFUNCARGS(self, vw, event, loc):
        vw.vprint("%r  %r  %r" % (vw, event, locinfo))

    def VWE_SETFUNCMETA(self, vw, event, loc):
        vw.vprint("%r  %r  %r" % (vw, event, locinfo))


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
        vw.vprint("%r  %r  %r" % (vw, event, locinfo))

    def VWE_DELLOCATION(self, vw, event, loc):
        #vw.vprint("%r  %r  %r" % (vw, event, locinfo))
        pass

    def VWE_SETMETA(self, vw, event, loc):
        vw.vprint("%r  %r  %r" % (vw, event, locinfo))

    def VWE_ADDFILE(self, vw, event, loc):
        #vw.vprint("%r  %r  %r" % (vw, event, locinfo))
        pass

    def VWE_ADDFUNCTION(self, vw, event, loc):
        #vw.vprint("%r  %r  %r" % (vw, event, locinfo))
        pass

    def VWE_DELFUNCTION(self, vw, event, loc):
        #vw.vprint("%r  %r  %r" % (vw, event, locinfo))
        pass

    def VWE_ADDCOLOR(self, vw, event, loc):
        vw.vprint("%r  %r  %r" % (vw, event, locinfo))

    def VWE_DELCOLOR(self, vw, event, loc):
        vw.vprint("%r  %r  %r" % (vw, event, locinfo))

    def VWE_CHAT(self, vw, event, loc):
        #vw.vprint("%r  %r  %r" % (vw, event, locinfo))
        pass


client = None
evtdist = None


def revsync_load(vw):   #done
    global client, evtdist
    vw.vprint('Connecting to RevSync Server')

    ### hook into the viv event stream

    # lets ensure auto-analysis is finished by forcing another analysis
    analyze(vw)

    if client is None:
        vw.vprint("creating a new revsync connection")
        client = Client(**config)

    state = vw.metadata.get('revsync')
    if state:
        vw.vprint("closing existing revsync state")
        state.close()

    vw.vprint('revsync: working...')
    state = vw.metadata['revsync'] = State(vw)
    vw.vprint('revsync: connecting with hashes: %s' % repr([x for x in state.genFhashes()]))

    for fhash in state.genFhashes():
        client.join(fhash, revsync_callback(vw))

    vw.vprint('revsync: connected!')

    if evtdist is None:
        evtdist = VivEventClient(vw)


def toggle_visits(vw):  #done
    state = State.get(vw)
    state.show_visits = not state.show_visits
    if state.show_visits:
        vw.vprint("Visit Visualization Enabled (Red)")
    else:
        vw.vprint("Visit Visualization Disabled (Red)")
    state.color_now = True

def toggle_time(vw):    #done
    state = State.get(vw)
    state.show_time = not state.show_time
    if state.show_time:
        vw.vprint("Time Visualization Enabled (Blue)")
    else:
        vw.vprint("Time Visualization Disabled (Blue)")
    state.color_now = True

def toggle_visitors(vw):    #done
    state = State.get(vw)
    state.show_visitors = not state.show_visitors
    if state.show_visitors:
        vw.vprint("Visitor Visualization Enabled (Green)")
    else:
        vw.vprint("Visitor Visualization Disabled (Green)")
    state.color_now = True

def toggle_track(vw):   #done
    state = State.get(vw)
    state.track_coverage = not state.track_coverage
    if state.track_coverage:
        vw.vprint("Tracking Enabled")
    else:
        vw.vprint("Tracking Disabled")


######### register the plugin #########
from vqt.main import idlethread

@idlethread
def vivExtension(vw, vwgui):
    vwgui.vqAddMenuField('&Plugins.&revsync.&Coverage: Toggle Tracking', toggle_track, args=(vw,))
    vwgui.vqAddMenuField('&Plugins.&revsync.&Coverage: Toggle Visits (RED)', toggle_visits, args=(vw,))
    vwgui.vqAddMenuField('&Plugins.&revsync.&Coverage: Toggle Time (BLUE)', toggle_time, args=(vw,))
    vwgui.vqAddMenuField('&Plugins.&revsync.&Coverage: Toggle Visitors (GREEN)', toggle_visitors, args=(vw,))
    vwgui.vqAddMenuField('&Plugins.&revsync.&load: Load revsync for binary(s) in this workspace', revsync_load, args=(vw,))

