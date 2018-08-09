from collections import defaultdict
import math

MIN = 60
HOUR = 60 * MIN
DAY = 24 * HOUR

# def scale_band(x): return (x ** 2) / (2 * (x ** 2 - x) + 1)
scale_band = lambda x: x
def log_band(n, scale=1): return math.log(n + 2) / scale

bands = [scale_band(x) for x in [0, 0.1, 0.2, 0.3, 0.4, 0.5]]

VISIT_SCALE = math.log(1000)
def visit_band(n):
    if 1  <= n < 2:  return bands[1]
    if 2  <= n < 5:  return bands[2]
    if 5  <= n < 10: return bands[3]
    if 10 <= n < 20: return bands[4]
    if 20 <= n < 50: return bands[5]
    if n >= 50: return max(log_band(n, VISIT_SCALE), 0.5)
    return 0

TIME_SCALE = math.log(48 * HOUR)
def time_band(n):
    n /= float(MIN)
    if 0  <= n < 0.5: return bands[0]
    if 0.5  <= n < 5: return bands[1]
    if 5  <= n < 10:  return bands[2]
    if 10 <= n < 20:  return bands[3]
    if 20 <= n < 30:  return bands[4]
    if 30 <= n < 60:  return bands[5]
    if n >= 60: return max(log_band(n, TIME_SCALE), 0.5)
    return bands[0]

def user_band(n):
    if 0  <= n < 2:  return bands[0]
    if 2  <= n < 3:  return bands[1]
    if 4  <= n < 6:  return bands[2]
    if 6  <= n < 10: return bands[3]
    if 10 <= n < 15: return bands[4]
    if n >= 15:      return bands[5]
    return bands[0]

class Block:
    def __init__(self):
        self.time = 0
        self.visits = 0
        self.users = 1

    def dump(self):
        return {'l': self.time, 'v': self.visits, 'u': self.users}

    def add(self, block):
        self.time += block.time
        self.visits += block.visits
        self.users += block.users

    def update(self, b):
        self.time += b['l']
        self.visits += b['v']
        self.users += b['u']

    def color(self, visits, time, users):
        r = g = b = 0
        if visits:
            r = visit_band(self.visits)
        if time:
            b = time_band(self.time)
        if users:
            g = user_band(self.users)
        if r == g == b == 0:
            return None

        # this semi-softmax hedges against the colors ending up too close together and making grey
        m = max((r, g, b))
        r, g, b = r ** 2, g ** 2, b ** 2
        total = float(r + g + b)
        r, g, b = r / total * m, g / total * m, b / total * m
        return r, g, b

class Blocks(defaultdict):
    def __init__(self):
        defaultdict.__init__(self, Block)

    def merge(self, blocks):
        for addr, block in blocks.items():
            mine = self.get(addr, None)
            if mine:
                mine.add(block)
            else:
                self[addr] = block

    def update(self, blocks):
        for addr, data in blocks.items():
            block = self[addr]
            block.update(data)

    def visit(self, addr, elapsed=0, visits=0):
        block = self[addr]
        block.time += elapsed
        block.visits += visits

class Coverage:
    def __init__(self):
        self.pending = Blocks()
        self.local = Blocks()
        self.shared = Blocks()

    def visit_addr(self, addr, elapsed=0, visits=0):
        self.pending.visit(addr, elapsed, visits)

    def color(self, addr, time=True, visits=True, users=True):
        block = self.shared.get(addr, None)
        if not block: block = self.local.get(addr, None)
        if not block: block = self.pending.get(addr, None)
        if not block: return None
        return block.color(time=time, visits=visits, users=users)

    def update(self, blocks):
        self.shared.update(blocks)

    def flush(self):
        pending = {addr: block.dump() for addr, block in self.local.items()}
        self.local.merge(self.pending)
        self.pending = Blocks()
        return pending
