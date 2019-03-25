#!/usr/bin/env python


import os
import wx.adv
import wx
import json
import servicewall


lib_path = "/usr/lib/servicewall/"
#lib_path = os.path.dirname(os.path.abspath(__file__)) + "/"
LOG_LIMIT = 10
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
        status_sizer = wx.BoxSizer(wx.VERTICAL)
        logs_sizer = wx.GridSizer(len(logs_by_port) + 1, 4, 0, 0)
        status_label = wx.StaticText(panel, label="", style=wx.ALIGN_CENTER)
        status_details = wx.StaticText(panel, label="\nrealm : %s" % fw.realm_id, style=wx.ALIGN_CENTER)
        if fw.config["enabled"]:
            status_str = "enabled"
        else:
            status_str = "disabled"
        status_label.SetLabelMarkup("<big>ServiceWall\n%s</big>" %
                (status_str))
        status_sizer.Add(status_label, 1, wx.ALIGN_CENTER, 25)
        status_sizer.Add(status_details, 1, wx.ALIGN_CENTER, 25)
        panel_sizer.Add(status_sizer, 1, wx.ALIGN_CENTER, 5)
        panel_sizer.Add(logs_sizer, 1, wx.ALL, 20)
        image = wx.Image(TRAY_ICON2, type=wx.BITMAP_TYPE_ANY).Scale(32, 32)
        bitmap = wx.Bitmap(image)
        logs_sizer.Add(wx.StaticText(panel, label=""))
        logs_sizer.Add(wx.StaticText(panel, label='port'), 1, wx.ALIGN_RIGHT, 0)
        logs_sizer.Add(wx.StaticText(panel, label="hits"), 1, wx.ALIGN_RIGHT, 0)
        logs_sizer.Add(wx.StaticText(panel, label="age"), 1, wx.ALIGN_RIGHT, 0)
        for name, logpile in logs_by_port.items():
            date = logpile[0]["DATE"]
            delta = date.now() - date
            if delta.seconds <= 60:
                age = str(delta.seconds) + "'"
            else:
                age = ":".join(str(delta).split(".")[0].split(":")[0:2])
            #rawbitmap = wx.Bitmap(TRAY_ICON2, type=wx.BITMAP_TYPE_ANY)
            #bitmap = wx.Bitmap(rawbitmap.ConvertToImage().Rescale(40, 40))
            icons.append(wx.StaticBitmap(panel, -1, bitmap))
            labels.append([
                    wx.StaticText(panel, label="%s" % logpile[0]["DPT"], style=wx.ALIGN_RIGHT),
                    wx.StaticText(panel, label="%i" % len(logpile)),
                    wx.StaticText(panel, label="%s" % age)
            ])
            logs_sizer.Add(icons[i], 1, wx.ALL, 0)
            logs_sizer.Add(labels[i][0], 1, wx.ALIGN_RIGHT, 25)
            logs_sizer.Add(labels[i][1], 1, wx.ALIGN_RIGHT, 0)
            logs_sizer.Add(labels[i][2], 1, wx.ALIGN_RIGHT, 0)
            #for j in range(3):
            #    logs_sizer.Add(labels[i][j], 6)
            i += 1
        panel.SetSizer(panel_sizer)
        panel.SetAutoLayout(True)
        panel_sizer.Fit(panel)
        window.SetPosition((r.right - panel_sizer.Size[0] + 1, r.top))
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

