#!/usr/bin/env python


import os
import wx
import json
import servicewall


lib_path = "/usr/lib/servicewall/"
#lib_path = os.path.dirname(os.path.abspath(__file__)) + "/"
TRAY_TOOLTIP = 'ServiceWall' 
TRAY_ICON = lib_path + "icon.png"
TRAY_ICON2 = lib_path + "icon2.png"


app = wx.App() 
window = wx.Frame(None, title="wxPython Frame", size=(300, 200)) 
panel = wx.Panel(window) 
label = wx.StaticText(panel, label="Hello World", pos=(100, 50)) 
window.Show(True) 
app.MainLoop()

