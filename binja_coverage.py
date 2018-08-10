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
bb_coverage = {}


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


def colour_blocks(blocks, max_visits, max_length, max_visitors):
    global SHOW_VISITS
    global SHOW_LENGTH
    global SHOW_VISITORS
    for bb in blocks:
        cov = blocks[bb]
        R, B, G = 0, 0, 0
        if SHOW_VISITS and cov["visits"] > 0:
            R = (cov["visits"] * 0x96) / max_visits
        if SHOW_LENGTH and cov["length"] > 0:
            B = (cov["length"] * 0x96) / max_length
        if SHOW_VISITORS and cov["visitors"] > 0:
            G = (cov["visitors"] * 0x96) / max_visitors
        if R == 0 and B == 0 and G == 0:
            bb.set_user_highlight(highlight.HighlightColor(red=74, blue=74, green=74))
        else:
            bb.set_user_highlight(highlight.HighlightColor(red=R, blue=B, green=G))


def colour_coverage(cur_func, coverage):
    if cur_func is None:
        return
    blocks = {}
    max_visits = 0
    max_length = 0
    max_visitors = 0
    for bb in coverage:
        if coverage[bb]["visits"] > max_visits:
            max_visits = coverage[bb]["visits"]
        if coverage[bb]["length"] > max_length:
            max_length = coverage[bb]["length"]
        if coverage[bb]["visitors"] > max_visitors:
            max_visitors = coverage[bb]["visitors"]
        if bb.function == cur_func:
            blocks[bb] = coverage[bb]
    colour_blocks(blocks, max_visits, max_length, max_visitors)


def watch_cur_func(bv):
    global TRACK_COVERAGE
    global bb_coverage

    def get_cur_func():
        return get_func_by_addr(bv, bv.offset)

    def get_cur_bb():
        return get_bb_by_addr(bv, bv.offset)

    last_func = None
    last_bb = None
    last_addr = None
    cur_func = None
    idle = 0
    colour = 0
    while True:
        if TRACK_COVERAGE:
            if idle > IDLE_ASK:
                res = get_choice_input("Continue coverage tracking?", "Idle Detection", ["Disable", "Continue"])
                if res == 0:
                    log_info('Coverage: Tracking Stopped')
                    exit()
                else:
                    idle = 0
            if last_addr == bv.offset:
                idle += 1
                if last_bb is not None:
                    bb_coverage[last_bb]["length"] += 1
                sleep(0.50)
            else:
                cur_bb = get_cur_bb()
                cur_func = get_cur_func()
                last_addr = bv.offset
                idle = 0
                if cur_bb != last_bb:
                    if cur_bb is not None:
                        if cur_bb not in bb_coverage:
                            bb_coverage[cur_bb] = {"visits": 0, "length": 0, "visitors": random.randint(1, 50)}
                        bb_coverage[cur_bb]["visits"] += 1
                    last_bb = cur_bb
                if cur_func != last_func:
                    colour = COLOUR_PERIOD
                    last_func = cur_func
            colour += 1
            if colour > COLOUR_PERIOD:
                colour_coverage(cur_func, bb_coverage)
                colour = 0
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