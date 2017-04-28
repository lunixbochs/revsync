import json
import redis
import threading
import traceback

key_dec = {
    'c': 'cmd',
    'a': 'addr',
    'u': 'user',
    't': 'text',
}
key_enc = {v: k for k, v in key_dec.items()}

def decode(data):
    d = json.loads(data)
    return {key_dec.get(k, k): v for k, v in d.items()}

class Client:
    def __init__(self, host, port, nick, password=None):
        self.r = redis.StrictRedis(host=host, port=port, password=password)
        self.nick = nick

    def _sub_thread(self, key, cb):
        pubsub = self.r.pubsub()
        pubsub.subscribe(key)
        for item in pubsub.listen():
            try:
                if item['type'] == 'message':
                    cb(key, decode(item['data']))
                elif item['type'] == 'subscribe':
                    for data in self.r.lrange(key, 0, -1):
                        try:
                            cb(key, decode(data), replay=True)
                        except Exception:
                            print 'error replaying history', data
                            traceback.print_exc()
                else:
                    print 'unknown redis push', item
            except Exception:
                print 'error processing item', item
                traceback.print_exc()

    def subscribe(self, key, cb):
        t = threading.Thread(target=self._sub_thread, args=(key, cb))
        t.daemon = True
        t.start()

    def start(self, key, cb):
        self.subscribe(key, cb)
        self.publish(key, {'cmd': 'join'}, perm=False)

    def publish(self, key, data, perm=True):
        data['user'] = self.nick
        data = {key_enc.get(k, k): v for k, v in data.items()}
        data = json.dumps(data, separators=(',', ':'))
        if perm:
            self.r.rpush(key, data)
        self.r.publish(key, data)
