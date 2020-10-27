#coding:utf-8
#! /usr/bin/env python

from tkinter import *
from threading import Thread
from Content import *

window = Tk()
checkButton = []
boxButton = []
var = []
var.append(IntVar())
pageNum = len(checkButtonText) / 9
pageIndex = 1
treasureBox = Toplevel()

def Init():
    global x,y
    treasureBox.withdraw()
    #初始化窗体
    window.title("网络安全技巧") #标题
    treasureBox.title("百宝箱")#百宝箱
    
    #窗体位置设置
    screenWidth = window.winfo_screenwidth()
    screenHeight = window.winfo_screenheight()  
    x = int((screenWidth - 800) / 2)
    y = int((screenHeight - 600) / 2)
    window.geometry("%sx%s+%s+%s" % (800, 600, x, y))
    window.resizable(0, 0)
    treasureBox.geometry("%sx%s+%s+%s" % (800, 600, x, y))
    treasureBox.resizable(0, 0)

def MainContainer():
    #复选框
    if (pageIndex * 9 + 1 > len(checkButtonText)):
        max = len(checkButtonText)
    else:
        max = pageIndex * 9
    for i in range((pageIndex - 1) * 9, max):
        var.append(IntVar())
        checkButton.append(Checkbutton(window, text = checkButtonText[i], variable = var[i + 1], height = 3, justify = LEFT))
        if i / 3 < pageIndex:
            checkButton[i].grid(row = 1, column = i % 3, padx = 50, pady = 50, sticky = W)
        elif i / 3 < pageIndex * 2:
            checkButton[i].grid(row = 2, column = i % 3, padx = 50, pady = 50, sticky = W)
        elif i / 3 < pageIndex * 3:
            checkButton[i].grid(row = 3, column = i % 3, padx = 50, pady = 50, sticky = W)

def GetFunction(i):
    return checkButtonFunction[i]()

#按钮
def Work():
    if pageIndex == 1:
        for i in range(0,9):
            if var[i + 1].get() == 1:
                GetFunction(i)
    elif pageIndex == 2:
        for i in range(10,15):
            if var[i + 1].get() == 1:
                GetFunction(i)
    IsOk()
Do = Button(window, text = "优化", command = Work, width = 10)
Do.place(x = 335, y = 520)

#推荐
def Recommend():
    if var[0].get() == 1:  
        if pageIndex == 1:
            for i in range(0,9):
                checkButton[i].select()
            checkButton[4].deselect()
        elif pageIndex == 2:
            for i in range(9,len(checkButton)):
                checkButton[i].select()
    else:
        for i in range(len(checkButton)):
            checkButton[i].deselect()
recommend = Checkbutton(window, text = "推荐", variable = var[0], command = Recommend)
recommend.place(x = 50, y = 520)

def CleanGrid():
    global checkButton,recommend
    recommend.deselect()
    for i in range(len(checkButton)):
        checkButton[i].deselect()
        checkButton[i].grid_forget()
            

def NextPage(event):
    global pageIndex
    CleanGrid()
    if pageIndex <= pageNum: 
        pageIndex += 1
        
        MainContainer()
def PrevPage(event):
    global pageIndex
    CleanGrid()
    if pageIndex > 1:
        pageIndex -= 1
        MainContainer()

def PageControl():
    cickLabel = Label(window,text = "下一页")
    cickLabel2 = Label(window,text = "上一页")
    cickLabel.bind('<Button-1>', NextPage)
    cickLabel2.bind('<Button-1>', PrevPage)
    cickLabel.place(x = 695, y = 520)
    cickLabel2.place(x = 625, y = 520)

def Exit():
    def JieShu():
        window.destroy()
        sys.exit(0)
    def Hidden():
        treasureBox.withdraw()
    window.protocol("WM_DELETE_WINDOW", JieShu)
    treasureBox.protocol("WM_DELETE_WINDOW", Hidden)

#版本号
version = Label(window, text = "版本：3.5.4.0")
version.place(x = 0, y = 575)

def GetFunction2(i):
    return treasureBoxFunction[i]

def TreasureBox():
    for i in range(len(treasureBoxText)):
        boxButton.append(Button(treasureBox, text = treasureBoxText[i], height = 2, width = 18, justify = CENTER, wraplength=100, command = GetFunction2(i)))
        if i / 3 < 0:
            boxButton[i].grid(row = 1, column = i % 3, padx = 50, pady = 20, sticky = W)
        elif i / 3 < 1:
            boxButton[i].grid(row = 2, column = i % 3, padx = 50, pady = 20, sticky = W)
        elif i / 3 < 2:
            boxButton[i].grid(row = 3, column = i % 3, padx = 50, pady = 20, sticky = W)
        elif i / 3 < 3:
            boxButton[i].grid(row = 4, column = i % 3, padx = 50, pady = 20, sticky = W)
        elif i / 3 < 4:
            boxButton[i].grid(row = 5, column = i % 3, padx = 50, pady = 20, sticky = W)
    treasureBox.deiconify()
Button(window, text = "百宝箱", command = TreasureBox).place(x = 725, y = 555)


if __name__ == "__main__":
    Init()
    PageControl()
    MainContainer()
    Exit()
    window.mainloop()
    