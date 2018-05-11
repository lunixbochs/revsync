from collections import defaultdict
from difflib import Differ

class Comments:
    def __init__(self):
        self.comments = defaultdict(list)
        self.delimiter = '\x1f\n'

    def add(self, ea, user, cmt, timestamp):
        # Remove old comment by user
        curr_cmt_index = [i for (i, (_, u, _)) in enumerate(self.comments[ea]) if u == user]
        if curr_cmt_index:
            self.comments[ea].pop(curr_cmt_index[0])

        # Add new comment by user
        self.comments[ea].append((timestamp, user, cmt))

    def get_comment_at_addr(self, ea):
        result = []
        for _, user, cmt in sorted(self.comments[ea]):
            result.append('[{}]\n{}'.format(user, cmt))
        return self.delimiter.join(result)

    def get_comment_by_user(self, cmt, user):
        if not cmt:
            return ''

        curr_cmt = [x for x in cmt.split(self.delimiter) if user in x]
        if curr_cmt:
            curr_cmt = curr_cmt[0].replace('[{}]\n'.format(user), '')
            return curr_cmt
        if self.delimiter not in cmt:
            return cmt
        else:
            # Assume new comments are always appended
            return cmt.split(self.delimiter)[-1]

comments = Comments()
