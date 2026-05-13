from dataclasses import dataclass
from pwndbg.commands.context import contextoutput, output, clear_screen, context, resetcontextoutput
from subprocess import check_output, CalledProcessError, run
import atexit
import copy
import fcntl
import gdb
import io, sys
import math
import os
import pwndbg
import pwndbg.commands.context as ctx
import re
import struct
import termios
import time

# TODO: maybe cleanup define/init order
# TODO: render sections only if running. The flipflop command tries to render when not running and that causes 
#       pwndbg to raise errors.
# TODO: override ctx command and make it redraw instead
#       -> when no code is avail, going up into a function with avail code does not list code, 
#       we need to hook ctx for this
# TODO: init with code first if debug info is available,
#       maybe run maintenance info sections and check output
# TODO: scrolling in code/disasm should request more code/disasm

def debugprint(s):
    import time
    with open("/tmp/debug", "a") as f:
        f.write(f"[{time.time()}]: {s}\n")

flipflopper = None
MAIN_WINDOW_TITLE = "PWNDBG"
TMUX_DRAW_OFFSET = 2

context_functions_dict = {
    "args": ctx.context_args,
    "regs": ctx.context_regs,
    "disasm": ctx.context_disasm,
    "stack": ctx.context_stack,
    "backtrace": ctx.context_backtrace,
    "code": ctx.context_code,
    "last_signal": ctx.context_last_signal,
    "expressions": ctx.context_expressions,
    "heap_tracker": ctx.context_heap_tracker,
    "threads": ctx.context_threads,
}

def context_disasm_code(**kwargs):
    return context_functions_dict[flipflopper.display_tuple[flipflopper.active_display]](with_banner=False)

special_displays_dict = {
    MAIN_WINDOW_TITLE: None,
    "tty": None,
    "disasm/code combo": context_disasm_code
}

@dataclass
class PtsSize:
    rows: int = None
    cols: int = None

def read_tmux_output(res, delimiter=':'):
  try:
    res = res.decode("utf-8")
  except:
    pass
  return res.strip().split(delimiter)

def pts_size(split):
    res = check_output(['tmux','display','-p','-F', '#{pane_width}:#{pane_height}','-t', split.id])
    res = read_tmux_output(res)
    return PtsSize(cols=int(res[0]), rows=int(res[1]))

@dataclass
class TmuxSplit:
    id: str
    tty: str
    display: str
    active_display: int = 0
    display_tuple: list = None
    pts_size: PtsSize = None
    scrollable: bool = True

def tmux_pane_title(pane, title):
    if pane is not None:
        check_output(['tmux','select-pane','-T',title,'-t',pane.id])
        return
    check_output(['tmux','select-pane','-T',title])

class Mind():
    def __init__(self):
        self.last = None
        self.panes = [TmuxSplit(os.environ["TMUX_PANE"], None, MAIN_WINDOW_TITLE, {}) ]
        self._saved_tmux_options = read_tmux_output(check_output(['tmux', 'show-options', '-w']), delimiter="\n")
        if not [o for o in self._saved_tmux_options if o.startswith("pane-border-status")]:
            self._saved_tmux_options.append("pane-border-status off")
        atexit.register(self.close)
        gdb.execute("set context-sections last_signal expressions")

    def get(self, display):
        if isinstance(display, TmuxSplit):
            return display
        try:
            return [p for p in self.panes if p.display == display][0]
        except IndexError:
            return None

    def split(self, tmux_split_direction, target=None, display=None, **tmux_params):
        global flipflopper

        size = tmux_params.get("size", None)
        commands = [
            'tmux', 'split-window', '-P', '-d', '-F', '#{pane_id}:#{pane_tty}',
            f'{tmux_split_direction}',
            '-t', str(self.get(target).id),
            *(['-l', size] if size else []),
            'exec sleep infinity'
        ]
        res = check_output(commands)
        split = TmuxSplit(*read_tmux_output(res), display)
        tmux_pane_title(split, display)
        self.panes.append(split)

        # If we add more props that are specific to a split containing a certain context, 
        # we might want to create a better config system.
        if split.display == "tty":
            gdb.execute(f"set inferior-tty {split.tty}")
            run(['stty', 'sane', '-F', split.tty])
        if split.display == "disasm/code combo":
            flipflopper = split
            split.display_tuple = ("disasm", "code")
            split.scrollable = False

    def left (self, of=None, display=None, **kwargs):
        self.split("-hb", target=of, display=display, **kwargs)
        return self

    def right(self, of=None, display=None, **kwargs):
        self.split("-h", target=of, display=display, **kwargs)
        return self

    def above(self, of=None, display=None, **kwargs):
        self.split("-vb", target=of, display=display, **kwargs)
        return self

    def below(self, of=None, display=None, **kwargs):
        self.split("-v", target=of, display=display, **kwargs)
        return self

    def build(self, **kwargs):
        check_output(['tmux', 'select-pane', "-t", os.environ["TMUX_PANE"]])
        # store sizes:
        for split in self.panes:
            if split.tty == None:
                continue
            split.pts_size = pts_size(split)
        # request code/disasm lines to fill pane
        print(f"debug: code_disasm_size {flipflopper.pts_size.rows}")
        gdb.execute(f"set context-code-lines {flipflopper.pts_size.rows}")
        # disasm does not always honor this; does not matter, we scroll up anyways
        gdb.execute(f"set context-disasm-lines {flipflopper.pts_size.rows}")

    def tell_splitter(self, target=None, show_titles=None, set_title=None):
        if target is None:
            target = self.last
        if show_titles is not None:
            check_output(['tmux','set' ,'pane-border-status', {"bottom":"bottom", False:"off"}.get(show_titles, "top")])
        if set_title is not None:
            tmux_pane_title(self.get(target), set_title)
        return self

    def close(self):
        for pane in set(pane.id for pane in self.panes[1:]):
            try:
                check_output(['tmux','kill-pane','-t',pane])
            except CalledProcessError as err:
                print(err)
        for option in [o for o in self._saved_tmux_options if o]:
            check_output(["tmux", "set"] + option.split(" "))

def render_to_pts(section_fn, split):
    buf = section_fn(with_banner=False)
    if not split.scrollable:
        # write only as many lines as needed
        count = 0
        lines = 0
        for line in buf:
            visible_line_len = len(re.sub(r'\033\[[0-9;]*[a-zA-Z]', '', line))
            count += max(1, math.ceil(visible_line_len / split.pts_size.cols)) if visible_line_len else 1
            if count > split.pts_size.rows:
                break
            lines += 1
        del buf[lines:]
    string = '\n'.join(buf)
    with open(split.tty, "w") as pts:
        pts.write("\033[2J\033[H")
        pts.write(string)
        pts.flush()

class flipflop(gdb.Command):
    def __init__(self):
        super().__init__("flipflop", gdb.COMMAND_USER, gdb.COMPLETE_NONE, False)

    def invoke(self, arg, from_tty):
        if flipflopper.active_display:
            flipflopper.active_display = 0
        else:
            flipflopper.active_display = 1
        render_to_pts(context_disasm_code, flipflopper)
mind = Mind()

def on_stop(event):
    for split in mind.panes:
        fn = context_functions_dict.get(split.display, None)
        if fn is None:
            fn = special_displays_dict[split.display]
        if fn:
            render_to_pts(fn, split)

gdb.events.stop.connect(on_stop)
flipflop()