#!/usr/bin/env python


import os
import wx.adv
import wx


lib_path = "/usr/lib/servicewall/"
#lib_path = os.path.dirname(os.path.abspath(__file__)) + "/"
TRAY_TOOLTIP = 'ServiceWall' 
TRAY_ICON = lib_path + "icon.png"
TRAY_ICON2 = lib_path + "icon2.png"

def create_menu_item(menu, label, func):
    item = wx.MenuItem(menu, -1, label)
    menu.Bind(wx.EVT_MENU, func, id=item.GetId())
    menu.Append(item)
    return item


class TaskBarIcon(wx.adv.TaskBarIcon):
    def __init__(self, frame):
        self.frame = frame
        super(TaskBarIcon, self).__init__()
        self.set_icon(TRAY_ICON)
        #self.SetIcon(wx.Icon(wx.IconLocation(TRAY_ICON)), "ServiceWall")
        self.Bind(wx.adv.EVT_TASKBAR_LEFT_DOWN, self.on_left_down)

    def CreatePopupMenu(self):
        menu = wx.Menu()
        create_menu_item(menu, 'Site', self.on_hello)
        create_menu_item(menu, 'Exit', self.on_exit)
        #site_item = menu.Append(-1, "run...", "run")
        menu.AppendSeparator()
        #exit_item = menu.Append(-1, "exit...", "exit")
        #self.Bind(wx.EVT_MENU, self.on_left_down, site_item)
        #self.Bind(wx.EVT_MENU, self.on_exit, exit_item)
        return menu

    def set_icon(self, path):
        icon = wx.Icon(path)
        self.SetIcon(icon, TRAY_TOOLTIP)

    def on_left_down(self, event):      
        print('Tray icon was left-clicked.')
        self.set_icon(TRAY_ICON2)
        self.PopupMenu(self.CreatePopupMenu())

    def on_hello(self, event):
        print('Hello, world!')

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

