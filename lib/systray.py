#!/usr/bin/env python


import os
import wx.adv
import wx
import json
import servicewall


lib_path = "/usr/lib/servicewall/"
#lib_path = os.path.dirname(os.path.abspath(__file__)) + "/"
TRAY_TOOLTIP = 'ServiceWall' 
TRAY_ICON = lib_path + "icon.png"
TRAY_ICON2 = lib_path + "icon2.png"

def create_menu_item(menu, label, func):
    item = wx.MenuItem(menu, -1, label)
    #item = wx.MenuItem(menu, item.GetId(), label)
    menu.Bind(wx.EVT_MENU, func, id=item.GetId())
    menu.Append(item)
    return item


class TaskBarIcon(wx.adv.TaskBarIcon):
    def __init__(self, frame):
        self.frame = frame
        super(TaskBarIcon, self).__init__()
        self.set_icon(TRAY_ICON2)
        #self.SetIcon(wx.Icon(wx.IconLocation(TRAY_ICON)), "ServiceWall")
        self.Bind(wx.adv.EVT_TASKBAR_LEFT_DOWN, self.on_left_down)

    def CreatePopupMenu(self):
        menu = wx.Menu()
        create_menu_item(menu, 'Exit', self.on_exit)
        #site_item = menu.Append(-1, "run...", "run")
        #self.Bind(wx.EVT_MENU, self.on_left_down, site_item)
        #menu.AppendSeparator()
        #exit_item = menu.Append(-1, "exit...", "exit")
        #self.Bind(wx.EVT_MENU, self.on_exit, exit_item)
        return menu

    def CreateApplet(self):
        r = wx.GetClientDisplayRect()
        position = (r.top, r.right)
        window = wx.PopupTransientWindow(self.frame, flags=wx.BORDER_NONE)
        fw = servicewall.ServiceWall()
        yielder = fw.log_yielder(limit=10)
        panel = wx.Panel(window)
        i = 0
        panel_sizer = wx.BoxSizer(wx.HORIZONTAL)
        list_sizer = wx.BoxSizer(wx.VERTICAL)
        panel_sizer.Add(list_sizer, 1, wx.ALL, 5)
        sizers = []
        icons = []
        labels = []
        logs_by_port = {}

        # First sort logs by port :
        for log in yielder:
            if log["DPT"] not in logs_by_port:
                logs_by_port[log["DPT"]] = [log,]
            else:
                logs_by_port[log["DPT"]].append(log)

        # Then display them :
        for name, logpile in logs_by_port.items():
            #age = int(datetime.timestamp(now) - datetime.timestamp(logpile[0]["DATE"]))
            date = logpile[0]["DATE"]
            delta = date.now() - date
            if delta.seconds <= 60:
                age = str(delta.seconds) + "'"
            else:
                age = ":".join(str(delta).split(".")[0].split(":")[0:2])
            item_text = "port %s : %i hits %s %s ago" % (name, len(logpile), logpile[0]["SRC"], age)
            sizers.append(wx.BoxSizer(wx.HORIZONTAL))
            #icons.append(wx.StaticBitmap(panel))
            icons.append(wx.Icon(TRAY_ICON))
            labels.append(wx.StaticText(panel, label=item_text, pos=(100, 50)))
            #sizers[i].Add(icons[i], 1, wx.ALL, 5)
            sizers[i].Add(labels[i], 7, wx.ALL, 0)
            list_sizer.Add(sizers[i], 1, wx.ALL, 5)
            i += 1
        panel.SetSizer(panel_sizer)
        panel.SetAutoLayout(True)
        panel_sizer.Fit(panel)
        window.SetPosition((r.right - panel_sizer.Size[0], r.top))
        window.SetSize(panel_sizer.Size)
        #window.Show(True)
        window.Popup()
        return window

    def set_icon(self, path):
        icon = wx.Icon(path)
        self.SetIcon(icon, TRAY_TOOLTIP)

    def on_left_down(self, event):      
        #self.set_icon(TRAY_ICON2)
        #self.PopupMenu(self.CreatePopupMenu())
        tray = event.GetEventObject()
        self.CreateApplet()

    def on_hello(self, event):
        print('Hello, world!')

    def log_callback(self, event):
        menu = event.GetEventObject()
        m = menu.GetMenuItems()[event.Id]

    def on_exit(self, event):
        wx.CallAfter(self.Destroy)
        self.frame.Close()


class App(wx.App):
    def OnInit(self):
        frame = wx.Frame(None)
        self.SetTopWindow(frame)
        TaskBarIcon(frame)
        return True


def main():
    app = App(False)
    app.MainLoop()

if __name__ == '__main__':
    main()

