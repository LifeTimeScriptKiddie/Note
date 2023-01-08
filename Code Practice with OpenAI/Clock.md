```
#!/usr/bin/env python3

import tkinter as tk
import time

class Clock(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.label = tk.Label(self, font= ('times', 20, 'bold'), bg='white')
        self.label.pack(fill='both', expand=1)
        self.update_clock()

    def update_clock(self):
        now=time.strftime('%H:%M:%S')
        self.label.configure(text=now)
        self.after(1000, self.update_clock)

app = Clock()
app.mainloop()

```