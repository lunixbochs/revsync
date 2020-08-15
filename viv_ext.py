# hook into the analysis modules to set the fhash since we only have the file at initial analysis. store in filemeta
def get_fhash(fname):
    with open(fname, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest().upper()



# add key start/stop capabilities in Sharing menu
# 
from vqt.main import *
@idlethread
def viv_Extension(vw, vwgui):
    from viv_frontend import ACT, toggle_track, toggle_visits, toggle_time, toggle_visitors, revsync_load
    vwgui.vqAddMenuField('&Tools.&revsync.&Coverage: Toggle Tracking', ACT(toggle_track))
    vwgui.vqAddMenuField('&Tools.&revsync.&Coverage: Toggle Visits (RED)', ACT(toggle_visits))
    vwgui.vqAddMenuField('&Tools.&revsync.&Coverage: Toggle Time (BLUE)', ACT(toggle_time))
    vwgui.vqAddMenuField('&Tools.&revsync.&Coverage: Toggle Visitors (GREEN)', ACT(toggle_visitors))
    vwgui.vqAddMenuField('&Tools.&revsync.&load', 'load revsync!!!', ACT(revsync_load))
