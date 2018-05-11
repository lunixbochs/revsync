from collections import defaultdict
import json
import re
import redis
import threading
import traceback

key_dec = {
    'c': 'cmd',
    'a': 'addr',
    'u': 'user',
    't': 'text',
}
key_enc = dict((v, k) for k, v in key_dec.items())
nick_filter = re.compile(r'[^a-zA-Z0-9_\-]')

def decode(data):
    d = json.loads(data)
    return dict((key_dec.get(k, k), v) for k, v in d.items())

def dtokey(d):
    return tuple(((k, v) for k, v in d.items() if k != 'user'))

class Client:
    def __init__(self, host, port, nick, password=None):
        self.r = redis.StrictRedis(host=host, port=port, password=password)
        self.nick = nick_filter.sub('_', nick)
        self.ps = {}
        self.nolock = threading.Lock()
        self.nosend = defaultdict(list)
        self.norecv = defaultdict(list)

    def debounce(self, no, data):
        dkey = dtokey(data)
        with self.nolock:
            if dkey in no:
                no.remove(dkey)
                return True
        return False

    def _sub_thread(self, ps, cb, key):
        for item in ps.listen():
            try:
                if item['type'] == 'message':
                    data = decode(item['data'])
                    if 'user' in data:
                        data['user'] = nick_filter.sub('_', data['user'])
                    if self.debounce(self.norecv[key], data):
                        continue
                    with self.nolock:
                        self.nosend[key].append(dtokey(data))
                    cb(key, data)
                elif item['type'] == 'subscribe':
                    decoded = []
                    for data in self.r.lrange(key, 0, -1):
                        try:
                            decoded.append(decode(data))
                        except Exception:
                            print 'error decoding history', data
                            traceback.print_exc()

                    state = []
                    dedup = set()
                    for data in reversed(decoded):
                        hashkey = tuple([str(data.get(k)) for k in ('cmd', 'user', 'addr')])
                        if all(hashkey):
                            if hashkey in dedup:
                                continue
                            dedup.add(hashkey)
                        state.append(data)

                    for data in reversed(state):
                        try:
                            with self.nolock:
                                self.nosend[key].append(dtokey(data))
                            cb(key, data, replay=True)
                        except Exception:
                            print 'error replaying history', data
                            traceback.print_exc()
                else:
                    print 'unknown redis push', item
            except Exception:
                print 'error processing item', item
                traceback.print_exc()

    def join(self, key, cb):
        ps = self.r.pubsub()
        ps.subscribe(key)
        t = threading.Thread(target=self._sub_thread, args=(ps, cb, key))
        t.daemon = True
        t.start()

        self.ps[key] = ps
        self.publish(key, {'cmd': 'join'}, perm=False)

    def leave(self, key):
        ps = self.ps.pop(key, None)
        if ps:
            ps.unsubscribe(key)

    def publish(self, key, data, perm=True):
        if self.debounce(self.nosend[key], data):
            return
        self.norecv[key].append(dtokey(data))

        data['user'] = self.nick
        data['ts'] = self.r.time()[0]
        data = dict((key_enc.get(k, k), v) for k, v in data.items())
        data = json.dumps(data, separators=(',', ':'), sort_keys=True)
        if perm:
            self.r.rpush(key, data)
        self.r.publish(key, data)
