#!/usr/bin/env python3

import tkinter as tk
from tkinter import filedialog

r = tk.Tk()
r.withdraw()

file_path=filedialog.askopenfilename(
    title="选择加解密目录",
)

r.mainloop()