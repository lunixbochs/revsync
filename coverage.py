from collections import defaultdict
import math

class Block:
    def __init__(self):
        self.time = 0
        self.visits = 0
        self.users = 1

    @property
    def log_time(self):
        return math.log(self.time, 2)

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

    def color(self, max_visits, max_time, max_users):
        r = g = b = 0.5
        if max_visits and self.visits > 0:
            r = self.visits / max_visits
        if max_time and self.time > 0:
            g = self.log_time / max_time
        if max_users and self.users > 0:
            b = self.users / max_users
        return r, g, b

class Blocks(defaultdict):
    def __init__(self):
        defaultdict.__init__(self, Block)
        self.max_time = 0
        self.max_visits = 0
        self.max_users = 0

    def merge(self, blocks):
        for addr, block in blocks.items():
            mine = self.get(addr, None)
            if mine:
                mine.add(block)
            else:
                self[addr] = block

    def update(self, data):
        for addr, data in blocks.items():
            block = self[addr]
            block.update(data)
            self.max_time = max(self.max_time, block.log_time)
            self.max_visits = max(self.max_visits, block.visits)
            self.max_users = max(self.max_users, block.users)

    def visit(self, addr, elapsed=0, visits=0):
        block = self[addr]
        block.time += elapsed
        block.visits += visits
        self.max_time = max(self.max_time, block.log_time)
        self.max_visits = max(self.max_visits, block.visits)
        self.max_users = max(self.max_users, block.users)

class Coverage:
    def __init__(self):
        self.pending = Blocks()
        self.local = Blocks()
        self.shared = Blocks()

    def visit_addr(self, addr, elapsed=0, visits=0):
        self.pending.visit(addr, elapsed, visits)

    def max(self):
        time = max(self.pending.max_time, self.local.max_time, self.shared.max_time)
        visits = max(self.pending.max_visits, self.local.max_visits, self.shared.max_visits)
        users = max(self.pending.max_users, self.local.max_users, self.shared.max_users)
        return time, visits, users

    def color(self, addr, time=True, visits=True, users=True):
        block = self.shared.get(addr, None)
        if not block: block = self.local.get(addr, None)
        if not block: block = self.pending.get(addr, None)
        if not block: return None
        tmax, vmax, umax = self.max()
        return block.color(time and tmax, visits and vmax, users and umax)

    def update(self, blocks):
        self.shared.update(blocks)

    def flush(self):
        pending = {addr: block.dump() for addr, block in self.local.items()}
        self.local.merge(self.pending)
        self.pending = Blocks()
        return pending
