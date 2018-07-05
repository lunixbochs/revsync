from collections import defaultdict
from difflib import Differ

def fmtuser(user):
    return '[{}] '.format(user)

class NoChange(Exception): pass

class Comments:
    def __init__(self):
        self.comments = defaultdict(dict)
        self.text = defaultdict(str)
        self.delimiter = '\x1f\n'

    def set(self, ea, user, cmt, timestamp):
        if cmt.strip():
            self.comments[ea][user] = (timestamp, user, cmt)
        else:
            self.comments[ea].pop(user, None)
        result = str(self.delimiter.join(
            [''.join((fmtuser(user), cmt))
             for _, user, cmt in
             sorted(self.comments[ea].values())]))
        self.text[ea] = result
        return result

    def get_comment_at_addr(self, ea):
        return self.text[ea]

    def parse_comment_update(self, ea, user, cmt):
        if not cmt: return ''
        if cmt == self.text[ea]: raise NoChange
        f = fmtuser(user)
        for cmt in cmt.split(self.delimiter):
            if cmt.startswith(f):
                 new = cmt.split('] ', 1)[1]
                 break
        else:
            # Assume new comments are always appended
            new = cmt.split(self.delimiter)[-1]
        old = self.comments[ea].get(user)
        if old:
            _, _, old = old
            if old.strip() == new.strip():
                raise NoChange
        return new

comments = Comments()
comments_extra = Comments()

if __name__ == '__main__':
    ts = 1
    def add(addr, user, comment):
        global ts
        ts += 1
        print('[+] {:#x} [{}] {}'.format(addr, user, comment))
        comments.set(addr, user, comment, ts)
        print('Comment at {:#x}:\n{}'.format(addr, comments.get_comment_at_addr(addr)))
        print()

    ea = 0x1000
    add(ea, 'alice', 'hello from alice')
    add(ea, 'bob', 'hello from bob')
    add(ea, 'alice', 'update from alice')

    text = comments.get_comment_at_addr(ea)
    print('-'*40)
    split = text.split(comments.delimiter)
    for i, line in enumerate(split):
        if fmtuser('alice') in line:
            split[i] += ' added stuff'
            update = comments.delimiter.join(split)
            print('[-] update:\n{}'.format(update))
            changed = comments.parse_comment_update(ea, 'alice', update)
            print('[-] changed text:\n{}'.format(changed))
            print('[-] set:')
            add(ea, 'alice', changed)
            break

    print('-'*40)
    changed = comments.parse_comment_update(ea, 'alice', 'replaced all text')
    add(ea, 'alice', changed)

    print('-'*40)
    try:
        text = comments.get_comment_at_addr(ea)
        comments.parse_comment_update(ea, 'alice', text)
        print('[!] oh no, change detected!')
    except NoChange:
        print('[+] no change detected')

    print('-'*40)
    print('empty update:', repr(comments.parse_comment_update(ea, 'alice', '')))

    print
