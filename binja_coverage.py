from time import sleep
from binaryninja import *
from binaryninja.plugin import PluginCommand
import logging
import random

logging.disable(logging.WARNING)
COVERAGE_FIRST_LOAD = True
SHOW_VISITS = True
SHOW_LENGTH = True
SHOW_VISITORS = False
TRACK_COVERAGE = True
IDLE_ASK = 250
COLOUR_PERIOD = 20
bb_visit_count = {}
bb_visit_length = {}
bb_visitors = {}
func_visit_count = {}
func_visit_length = {}


def get_func_by_addr(bv, addr):
    bb = bv.get_basic_blocks_at(addr)
    if len(bb) > 0:
        return bb[0].function
    return None


def get_bb_by_addr(bv, addr):
    bb = bv.get_basic_blocks_at(addr)
    if len(bb) > 0:
        return bb[0]
    return None


def colour_blocks(blocks):
    for block in blocks:
        b = blocks[block]
        b["f"].set_comment_at(b["b"].start, "R: %d B: %d G: %d" % (b["R"], b["B"], b["G"]))
        if not SHOW_VISITS:
            b["R"] = 0
        if not SHOW_LENGTH:
            b["B"] = 0
        if not SHOW_VISITORS:
            b["G"] = 0
        if b["R"] == 0 and b["B"] == 0 and b["G"] == 0:
            b["b"].set_user_highlight(highlight.HighlightColor(red=42, blue=42, green=42))
        else:
            b["b"].set_user_highlight(highlight.HighlightColor(red=b["R"], blue=b["B"], green=b["G"]))


def colour_coverage(bv, visits, length, visitors):
    blocks = {}
    max_count = visits[max(visits, key=visits.get)]
    for addr in visits:
        if addr not in blocks:
            blocks[addr] = {"b": get_bb_by_addr(bv, addr), "f": get_func_by_addr(bv, addr), "R": 0, "B": 0, "G": 0}
        blocks[addr]["R"] = (visits[addr] * 0xff) / max_count
    max_count = length[max(length, key=length.get)]
    for addr in length:
        if addr not in blocks:
            blocks[addr] = {"b": get_bb_by_addr(addr), "f": get_func_by_addr(bv, addr), "R": 0, "B": 0, "G": 0}
        blocks[addr]["B"] = (length[addr] * 0xff) / max_count
    max_count = visitors[max(visitors, key=visitors.get)]
    for addr in visitors:
        if addr not in blocks:
            blocks[addr] = {"b": get_bb_by_addr(addr), "f": get_func_by_addr(bv, addr), "R": 0, "B": 0, "G": 0}
        blocks[addr]["G"] = (visitors[addr] * 0xff) / max_count
    colour_blocks(blocks)


def watch_cur_func(bv):
    global SHOW_VISITS
    global SHOW_LENGTH
    global SHOW_VISITORS
    global TRACK_COVERAGE
    global bb_visit_count
    global bb_visit_length
    global bb_visitors
    global func_visit_count
    global func_visit_length

    def get_cur_func():
        return get_func_by_addr(bv, bv.offset)

    def get_cur_bb():
        return get_bb_by_addr(bv, bv.offset)

    last_func = None
    last_bb = None
    last_addr = None
    idle = 0
    colour = 0
    while True:
        if idle > IDLE_ASK:
            res = get_choice_input("Continue coverage tracking?", "Idle Detection", ["Disable", "Continue"])
            if res == 0:
                log_info('Coverage: Tracking Stopped')
                exit()
            else:
                idle = 0
        if TRACK_COVERAGE:
            colour += 1
            if colour > COLOUR_PERIOD:
                colour_coverage(bv, bb_visit_count, bb_visit_length, bb_visitors)
                colour = 0
            if last_addr == bv.offset:
                idle += 1
                if last_bb is not None:
                    bb_visit_length[last_bb.start] += 1
                if last_func is not None:
                    func_visit_length[last_func.start] += 1
                sleep(0.50)
            else:
                cur_bb = get_cur_bb()
                cur_func = get_cur_func()
                last_addr = bv.offset
                idle = 0
                if cur_bb != last_bb:
                    if cur_bb is not None:
                        if cur_bb.start not in bb_visit_count:
                            bb_visit_count[cur_bb.start] = 0
                        if cur_bb.start not in bb_visit_length:
                            bb_visit_length[cur_bb.start] = 0
                        if cur_bb.start not in bb_visitors:
                            bb_visitors[cur_bb.start] = random.randint(1, 50)
                        bb_visit_count[cur_bb.start] += 1
                    last_bb = cur_bb
                if cur_func != last_func:
                    if cur_func is not None:
                        if cur_func.start not in func_visit_count:
                            func_visit_count[cur_func.start] = 0
                        if cur_func.start not in func_visit_length:
                            func_visit_length[cur_func.start] = 0
                        func_visit_count[cur_func.start] += 1
                    last_func = cur_func
        else:
            idle = 0
            sleep(2)


def coverage_load(bv):
    global COVERAGE_FIRST_LOAD
    global SHOW_VISITS
    global SHOW_LENGTH
    global SHOW_VISITORS
    log_info('Coverage: Tracking Started')
    if COVERAGE_FIRST_LOAD:
        opt_visit = ChoiceField("Visualize Visits (Red)", ["Yes", "No"])
        opt_length = ChoiceField("Visualize Length (Blue)", ["Yes", "No"])
        opt_visitors = ChoiceField("Visualize Visitors (Green)", ["No", "Yes"])
        res = get_form_input(["Visualize by colouring backgrounds?", None, opt_visit, opt_length, opt_visitors],
                             "Visualization Options")
        if res:
            log_info('Coverage: Visualization Options Set')
            if opt_visit.result > 0:
                SHOW_VISITS = not SHOW_VISITS
            if opt_length.result > 0:
                SHOW_LENGTH = not SHOW_LENGTH
            if opt_visitors.result > 0:
                SHOW_VISITORS = not SHOW_VISITORS
        COVERAGE_FIRST_LOAD = False
    t1 = threading.Thread(target=watch_cur_func, args=(bv,))
    t1.daemon = True
    t1.start()


def toggle_visits(bv):
    global SHOW_VISITS
    SHOW_VISITS = not SHOW_VISITS


def toggle_length(bv):
    global SHOW_LENGTH
    SHOW_LENGTH = not SHOW_LENGTH


def toggle_visitors(bv):
    global SHOW_VISITORS
    SHOW_VISITORS = not SHOW_VISITORS


PluginCommand.register('Coverage: Start Tracking', 'Track Coverage', coverage_load)
PluginCommand.register('Coverage: Toggle Visits (RED)', 'Toggle Red', toggle_visits)
PluginCommand.register('Coverage: Toggle Length (BLUE)', 'Toggle Blue', toggle_length)
PluginCommand.register('Coverage: Toggle Visitors (GREEN)', 'Toggle Green', toggle_visitors)