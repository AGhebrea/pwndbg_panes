#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
if os.getenv("TMUX_PANE") is not None:
    import sys


    directory, file = os.path.split(__file__)
    directory       = os.path.expanduser(directory)
    directory       = os.path.abspath(directory)

    sys.path.append(directory)

    import pwndbg_panes # isort:skip