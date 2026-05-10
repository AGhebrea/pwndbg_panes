# Credits
Portions of this code were originally from [splitmind](https://github.com/jerdna-regeiz/splitmind) by Andrej Zieger

# Setup
I also add to *.tmux.conf*:
``` sh
set -g mouse on
bind-key -n F12 run-shell 'tmux send-keys -t $(tmux list-panes -t pwndbg_panes -a -F "##{pane_title}:##{pane_id}" | grep "^PWNDBG:" | head -1 | cut -d: -f2) flipflop Enter'
```

## Example .gdbinit

``` sh
source <PATH TO pwndbg_panes>/gdbinit.py
python
import pwndbg_panes
( pwndbg_panes.mind
  .tell_splitter(show_titles=True, set_title="PWNDBG")
  .right(of="PWNDBG", display="regs", size="35%")
  .above(of="PWNDBG", display="disasm/code combo", size="65%")
  .below(of="disasm/code combo", display="stack", size="25%")
  .below(of="regs", display="tty", size="50%", clearing=False)
).build(nobanner=True)
end
set context-sections ''
```