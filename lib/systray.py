#!/usr/bin/env python


import os
import wx.adv
import wx
import json
import servicewall


lib_path = "/usr/lib/servicewall/"
#lib_path = os.path.dirname(os.path.abspath(__file__)) + "/"
LOG_LIMIT = 20
TRAY_TOOLTIP = 'ServiceWall' 
TRAY_ICON = lib_path + "icon.png"
TRAY_ICON2 = lib_path + "icon2.png"


class TaskBarIcon(wx.adv.TaskBarIcon):
    """A systray icon with a panel showing latest hits
    """
    def __init__(self, frame):
        self.frame = frame
        super(TaskBarIcon, self).__init__()
        self.SetIcon(wx.Icon(wx.IconLocation(TRAY_ICON2)), "ServiceWall")
        self.Bind(wx.adv.EVT_TASKBAR_LEFT_DOWN, self.on_left_down)

    def CreatePopupMenu(self):
        """gets automatically called on systray's right-click"""
        menu = wx.Menu()
        exit_item = menu.Append(-1, "Exit", "exit")
        self.Bind(wx.EVT_MENU, self.on_exit, exit_item)
        #menu.AppendSeparator()
        return menu

    def CreateApplet(self):
        r = wx.GetClientDisplayRect()
        position = (r.top, r.right)
        window = wx.PopupTransientWindow(self.frame, flags=wx.BORDER_NONE)
        fw = servicewall.ServiceWall()
        yielder = fw.log_yielder(limit=LOG_LIMIT)
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
            date = logpile[0]["DATE"]
            delta = date.now() - date
            if delta.seconds <= 60:
                age = str(delta.seconds) + "'"
            else:
                # DEBUG does it work with days ?
                age = ":".join(str(delta).split(".")[0].split(":")[0:2])
            sizers.append(wx.BoxSizer(wx.HORIZONTAL))
            #rawbitmap = wx.Bitmap(TRAY_ICON2, type=wx.BITMAP_TYPE_ANY)
            #bitmap = wx.Bitmap(rawbitmap.ConvertToImage().Rescale(40, 40))
            image = wx.Image(TRAY_ICON2, type=wx.BITMAP_TYPE_ANY).Scale(40, 40)
            bitmap = wx.Bitmap(image)
            icons.append(wx.StaticBitmap(panel, -1, bitmap))
            labels.append([
                    wx.StaticText(panel, wx.ALIGN_RIGHT, label="port %s" % logpile[0]["DPT"]),
                    wx.StaticText(panel, wx.ALIGN_RIGHT, label="%i hits" % len(logpile)),
                    wx.StaticText(panel, wx.ALIGN_RIGHT, label="%s ago" % age)
            ])
            sizers[i].Add(icons[i], 0, 5)
            sizers[i].Add(labels[i][0], 1, 5)
            sizers[i].Add(labels[i][1], 1, 5)
            sizers[i].Add(labels[i][2], 1, wx.ALIGN_RIGHT, 5)
            list_sizer.Add(sizers[i], 1, wx.ALL, 0)
            i += 1
        panel.SetSizer(panel_sizer)
        panel.SetAutoLayout(True)
        panel_sizer.Fit(panel)
        window.SetPosition((r.right - panel_sizer.Size[0], r.top))
        window.SetSize(panel_sizer.Size)
        #window.Show(True)
        window.Popup()
        return window

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

