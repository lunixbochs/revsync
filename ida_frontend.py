print 'revsync IDA!!!'

from idaapi import *
from idc import *
from idautils import *

class IDPHooks(IDP_Hooks):
    def renamed(self, ea, new_name, local_name):
        if isLoaded(ea):
            print('renamed!', ea, new_name, local_name)
        return IDP_Hooks.renamed(self, ea, new_name, local_name)

class IDBHooks(IDB_Hooks):
    def cmt_changed(self, ea, repeatable):
        print 'cmt_changed', GetCommentEx(ea, repeatable)
        return IDB_Hooks.cmt_changed(self, ea, repeatable)

    def extra_cmt_changed(self, ea, repeatable):
        print 'extra_cmt_changed', GetCommentEx(ea, repeatable)
        return IDB_Hooks.extra_cmt_changed(self, ea, repeatable)

    def area_cmt_changed(self, cb, a, cmt, repeatable):
        print 'area_cmt_changed', a.startEA, a.endEA, cmt, repeatable
        return IDB_Hooks.area_cmt_changed(self, cb, a, cmt, repeatable)

hook1 = IDPHooks()
hook2 = IDBHooks()
hook1.hook()
hook2.hook()
