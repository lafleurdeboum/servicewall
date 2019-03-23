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
        fw = servicewall.ServiceWall()
        yielder = fw.log_yielder(limit=10)
        i = 0
        for y in yielder:
            i += 1
            item_text = y["SRC"] + " " + y["DPT"] + " " + str(y["DATE"])
            #create_menu_item(menu, item_text, self.log_callback)
            j = menu.Append(i, item_text, item_text)
            self.Bind(wx.EVT_MENU, self.log_callback, j)
        create_menu_item(menu, 'Exit', self.on_exit)
        #site_item = menu.Append(-1, "run...", "run")
        #self.Bind(wx.EVT_MENU, self.on_left_down, site_item)
        menu.AppendSeparator()
        #exit_item = menu.Append(-1, "exit...", "exit")
        #self.Bind(wx.EVT_MENU, self.on_exit, exit_item)
        return menu

    def set_icon(self, path):
        icon = wx.Icon(path)
        self.SetIcon(icon, TRAY_TOOLTIP)

    def on_left_down(self, event):      
        print('Tray icon was left-clicked.')
        #self.set_icon(TRAY_ICON2)
        self.PopupMenu(self.CreatePopupMenu())

    def on_hello(self, event):
        print('Hello, world!')

    def log_callback(self, event):
        menu = event.GetEventObject()
        m = menu.GetMenuItems()[event.Id]
        print(dir(m))
        print(m.GetItemLabel())

    def on_exit(self, event):
        wx.CallAfter(self.Destroy)
        self.frame.Close()


class App(wx.App):
    def OnInit(self):
        frame=wx.Frame(None)
        self.SetTopWindow(frame)
        TaskBarIcon(frame)
        return True


def main():
    app = App(False)
    app.MainLoop()

if __name__ == '__main__':
    main()

