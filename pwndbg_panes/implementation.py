from dataclasses import dataclass
from pwndbg.commands.context import contextoutput, output, clear_screen, context, resetcontextoutput
from subprocess import check_output, CalledProcessError, run
import atexit
import copy
import io, sys
import os
import pwndbg
import pwndbg.commands.context as ctx
import time
import gdb

# TODO: maybe cleanup define/init order
# TODO: modify size to be percentage of screen after everything is drawn ?
# TODO: render sections only if running. The flipflop command tries to render when not running and that causes 
#       pwndbg to raise errors.
# TODO: figure out a way to make pwndbg disasm not have empty lines after BBs. Alternatively
#       make pwndbg honor the set context-disasm-lines even with the spaces.
# TODO: override ctx command and make it redraw instead
#       -> when no code is avail, going up into a function with avail code does not list code, 
#       we need to hook ctx for this
# TODO: init with code first if debug info is available,
#       maybe run maintenance info sections and check output

def debugprint(s):
    import time
    with open("/tmp/debug", "a") as f:
        f.write(f"[{time.time()}]: {s}\n")

flipflopper = None
MAIN_WINDOW_TITLE = "PWNDBG"

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
class TmuxSplit:
    id: str
    tty: str
    display: str
    active_display: int = 0
    display_tuple: list = None

    def size(self):
        res = check_output(['tmux','display','-p','-F', '#{pane_width}:#{pane_height}','-t', self.id])
        return [int(x) for x in read_tmux_output(res)]

def read_tmux_output(res, delimiter=':'):
  try:
    res = res.decode("utf-8")
  except:
    pass
  return res.strip().split(delimiter)

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

        if split.display == "tty":
            gdb.execute(f"set inferior-tty {split.tty}")
            run(['stty', 'sane', '-F', split.tty])
        if split.display == "disasm/code combo":
            flipflopper = split
            split.display_tuple = ("disasm", "code")

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
        # request code/disasm lines to fill pane
        code_disasm_size = flipflopper.size()[1]
        gdb.execute(f"set context-code-lines {code_disasm_size}")
        gdb.execute(f"set context-disasm-lines {code_disasm_size}")
        # 
        # gdb.execute("set disasm-annotations-right-margin 0")

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

def render_to_pts(section_fn, pts_path):
    buf = section_fn(with_banner=False)
    string = buf
    if type(buf) == list:
        string = '\n'.join(buf)
    with open(pts_path, "w") as pts:
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
        render_to_pts(context_disasm_code, flipflopper.tty)

mind = Mind()

def on_stop(event):
    for split in mind.panes:
        fn = context_functions_dict.get(split.display, None)
        if fn is None:
            fn = special_displays_dict[split.display]
        if fn:
            render_to_pts(fn, split.tty)

gdb.events.stop.connect(on_stop)
flipflop()