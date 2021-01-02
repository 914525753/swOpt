#coding:utf-8
#! /usr/bin/env python

from tkinter import messagebox
from os import system
from time import sleep

flag = 0

checkButtonText = [
    '关闭网络共享', '禁用telnet', '禁用guest用户', 'U盘保护', '禁止自动播放', '远程服务禁用', '关闭bing', '自动关闭停止响应的应用', '伪优化清除', '改善超级预读', '禁用搜索索引', '关闭多余视觉效果', '关闭系统休眠', '系统服务项优化', 'office安全优化'
]

treasureBoxText = [
    '清理arp缓存表', '重置winsock', '重新加载dll', 'IE安全警报关闭', '修复windows installer', '组策略启动修复', '修复dns并重新分配ip', '解除CMD禁用', '解除注册表禁用', '解除防火墙禁用（win10）', '路由表重置', '重置系统应用（win10）', '清理桌面图标缓存（win10）', 'ESENT EDB.log错误修复'
]

def IsOk():
    messagebox.showinfo(message = "优化成功")

def UserCancel():
    global flag
    flag += 1
    messagebox.showerror(message = '用户取消了操作')

def NoShare():
    if(messagebox.askyesno(message = '注意，关闭网络共享会无法共享文件') == True):
        system('net share C$ /del & net share D$ /del & net share ADMIN$ /del &  net share E$ /del & net share F$ /del & net share G$ /del')
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v restrictanonymous /t REG_DWORD /d 1 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\services\\LanmanServer\\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer" /v Start /t REG_DWORD /d 4 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation" /v Start /t REG_DWORD /d 4 /f')
        system('net use * /del /y')
        system('netsh wlan set allowexplicitcreds no')
    else:
        UserCancel()

def NoTelnet():
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\tlntsvr" /v Start /t REG_DWORD /d 4 /f')  

def NoGuest():
    system('net user Guest /active:no')

def ProtectUSB():
    if(messagebox.askyesno(message = '注意，U盘保护会导致文件无法写入U盘') == True):
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies" /v WriteProtect /t REG_DWORD /d 1 /f')
    else:
        UserCancel()

def NoAutoRun():
    system('reg add "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f')
    system('reg add "HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer /v NoAutoplayfornonVolume" /t REG_DWORD /d 1 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Services\\cdrom" /v Autorun /t REG_DWORD /d 0 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\cdrom" /v Autorun /t REG_DWORD /d 0 /f')

def NoRemote():
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\RemoteRegistry" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\RemoteRegAccess" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\UmRdpService" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TermService" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SessionEnv" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\RasMan" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\RasAuto" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Secondary Logon" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\SharedAccess" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\HomeGroupListener" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\HomeGroupProvider" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WPCSvc" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WerSvc" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WMPNetworkSvc" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\wscsvc" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetTcpPortSharing" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\QWAVE" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\RpcLocator" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\lmhosts" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetBT" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\NetBIOS" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\RDSessMgr" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\DiagTrack" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\SSDPSRV" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\upnphost" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\lfsvc" /v Start /t REG_DWORD /d 4 /f')

    if(messagebox.askyesno(message = '是否要禁用windows10自带更新') == True):
        system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 1 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate" /v TargetReleaseVersion /t REG_SZ /d 1909 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate" /v TargetReleaseVersion /t REG_DWORD /d 1 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" /v AutoInstallMinorUpdates /t REG_DWORD /d 0 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" /v EnableFeaturedSoftware /t REG_DWORD /d 0 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\wuauserv" /v Start /t REG_DWORD /d 4 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\UsoSvc" /v Start /t REG_DWORD /d 4 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WaaSMedicSvc" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 4 /f')
        system('Schtasks /Change /DISABLE /TN "\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start"')
    else:
        system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\wuauserv" /v Start /t REG_DWORD /d 3 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\UsoSvc" /v Start /t REG_DWORD /d 3 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WaaSMedicSvc" /v ExcludeWUDriversInQualityUpdate /t REG_DWORD /d 3 /f')
        system('Schtasks /Change /ENABLE /TN "\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start"')
        system('reg delete "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate" /v TargetReleaseVersion /f')

    if(messagebox.askyesno(message = '是否要禁用windows10热点') == True):
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\icssvc" /v Start /t REG_DWORD /d 4 /f')
    else:
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\icssvc" /v Start /t REG_DWORD /d 3 /f')

    if(messagebox.askyesno(message = '是否要禁用ADSL拨号') == True):
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TapiSrv" /v Start /t REG_DWORD /d 4 /f')
    else:
       system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TapiSrv" /v Start /t REG_DWORD /d 3 /f') 

    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\p2pimsvc" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\p2psvc" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\PNRPsvc" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\sppsvc" /v Start /t REG_DWORD /d 3 /f')

def NoBing():
    system('reg add "HKEY_CURRENT_USER\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f')

def AutoEndTask():
    system('reg add "HKEY_CURRENT_USER\\Control Panel\\Desktop" /v AutoEndTasks /t REG_SZ /d 1 /f')

def ErrorOptimizationClean():
    system('reg add "HKEY_CURRENT_USER\\Control Panel\\Desktop" /v MenuShowDelay /t REG_SZ /d 400 /f')
    system('reg add "HKEY_CURRENT_USER\\Control Panel\\Desktop" /v WaitToKillAppTimeout /t REG_SZ /d 5000 /f')
    system('reg add "HKEY_CURRENT_USER\\Control Panel\\Desktop" /v HungAppTimeout /t REG_SZ /d 5000 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control" /v WaitToKillServiceTimeout /t REG_SZ /d 5000 /f')
    system('reg delete "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced" /v ThumbnailLivePreviewHoverTime /f')

def OptimizeSuperfetch():
    if(messagebox.askyesno(message = '是否增强超级预读，“是”代表增强，“否”使用系统默认') == True):
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 4 /f')
    else:
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d 3 /f')

def NoSearchIndex():
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WSearch" /v Start /t REG_DWORD /d 4 /f')

def NoVFX():
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\UxSms" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize" /v EnableBlurBehind /t REG_DWORD /d 0 /f')
    system('reg add "HKEY_CURRENT_USER\\Microsoft\\Windows\\DWM" /v EnableAeroPeek /t REG_DWORD /d 0 /f')
    system('reg add "HKEY_CURRENT_USER\\Microsoft\\Windows\\DWM" /v ColorizationGlassAttribute /t REG_DWORD /d 0 /f')

def NoDormancy():
    system('powercfg -h off')

def OptimizeService():
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WpnService" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\OneSyncSvc" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\PushToInstall" /v Start /t REG_DWORD /d 4 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\vmicrdv" /v Start /t REG_DWORD /d 4 /f')


    if(messagebox.askyesno(message = '是否禁用windows应用商店') == True):
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\InstallService" /v Start /t REG_DWORD /d 4 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LicenseManager" /v Start /t REG_DWORD /d 4 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NcbService" /v Start /t REG_DWORD /d 4 /f')
    else:
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\InstallService" /v Start /t REG_DWORD /d 3 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\LicenseManager" /v Start /t REG_DWORD /d 3 /f')
        system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\NcbService" /v Start /t REG_DWORD /d 3 /f')


    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\stisvc" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\wmiApSrvr" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\XLServicePlatform" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TabletInputService" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\MapsBroker" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\DsmSvc" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WbioSrvc" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\DPS" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Spooler" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\DusmSvc" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\iphlpsvc" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CDPSvc" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\DPSCryptSvc" /v Start /t REG_DWORD /d 3 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\DPS" /v Start /t REG_DWORD /d 3 /f')

    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\SysMain" /v DelayedAutostart /t REG_DWORD /d 1 /f')
    system('del /F /Q "C:\\Windows\\System32\\sru"')



def OfficeSecurity():
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Word\\Security" /v RequireAddinSig /t REG_DWORD /d 1 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Word\\Security" /v NoTBPromptUnsignedAddin /t REG_DWORD /d 1 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\ProtectedView" /v DisableAttachmentsInPV /t REG_DWORD /d 0 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\ProtectedView" /v DisableInternetFilesInPV /t REG_DWORD /d 0 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\ProtectedView" /v DisableUnsafeLocationsInPV /t REG_DWORD /d 0 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\Trusted Documents" /v DisableTrustedDocuments /t REG_DWORD /d 1 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\Trusted Documents" /v DisableNetworkTrustedDocuments /t REG_DWORD /d 1 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Word\\Security\\Trusted Locations" /v AllLocationsDisabled /t REG_DWORD /d 1 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security" /v RequireAddinSig /t REG_DWORD /d 1 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security" /v NoTBPromptUnsignedAddin /t REG_DWORD /d 1 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView" /v DisableAttachmentsInPV /t REG_DWORD /d 0 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView" /v DisableInternetFilesInPV /t REG_DWORD /d 0 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView" /v DisableUnsafeLocationsInPV /t REG_DWORD /d 0 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\Trusted Documents" /v DisableTrustedDocuments /t REG_DWORD /d 1 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\Trusted Locations" /v DisableTrustedDocuments /t REG_DWORD /d 1 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\Security" /v RequireAddinSig /t REG_DWORD /d 1 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\Security" /v NoTBPromptUnsignedAddin /t REG_DWORD /d 1 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\Security\\Trusted Documents" /v DisableTrustedDocuments /t REG_DWORD /d 1 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\Security\\Trusted Locations" /v AllLocationsDisabled /t REG_DWORD /d 1 /f')
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\Common\\Security" /v UFIControlsbled /t REG_DWORD /d 4 /f')

def ARPClean():
    system('arp -d')
    IsOk()

def WinsockReset():
    system('netsh winsock reset')
    IsOk()

def DllReload():
    system('for %1 in (%windir%\\system32\\*.dll) do regsvr32.exe /s %1')
    IsOk()

def NoWarn():
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" /v WarnOnHTTPSToHTTPRedirect /t REG_DWORD /d 0 /f')
    IsOk()

def FixMsiServer():
    system('reg add "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\msiserver" /v Start /t REG_DWORD /d 3 /f')
    IsOk()

def FixGpedit():
    system('net start gpsvc & start gpedit.msc')
    IsOk()

def DnsFlush():
    system('ipconfig /flushdns & ipconfig /registerdns & ipconfig /release WLAN & ipconfig /renew WLAN')
    IsOk()

def EnableCMD():
    system('reg add "HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\System" /v DisableCMD /t REG_DWORD /d 0 /f')
    IsOk()

def EnableREG():
    system('reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableRegistrytools /t REG_DWORD /d 0 /f')
    system('reg add "HKEY_LOCAL_MACHINE\\Software\\CLASSES\\.reg" /v "" /t REG_SZ /d regfile /f')
    system('reg add "HKEY_LOCAL_MACHINE\\Software\\CLASSES\\.inf" /v "" /t REG_SZ /d inffile /f')
    IsOk()

def EnableFireWall():
    system('netsh advfirewall set allprofiles state on')
    IsOk()

def RouteClean():
    system('route -f')
    IsOk()

def Win10APPReset():
    system('powershell -e RwBlAHQALQBBAHAAcABYAFAAYQBjAGsAYQBnAGUAIAAtAEEAbABsAFUAcwBlAHIAcwAgAHwAIABGAG8AcgBlAGEAYwBoACAAewBBAGQAZAAtAEEAcABwAHgAUABhAGMAawBhAGcAZQAgAC0ARABpAHMAYQBiAGwAZQBEAGUAdgBlAGwAbwBwAG0AZQBuAHQATQBvAGQAZQAgAC0AUgBlAGcAaQBzAHQAZQByACAAIgAkACgAJABfAC4ASQBuAHMAdABhAGwAbABMAG8AYwBhAHQAaQBvAG4AKQBcAEEAcABwAFgATQBhAG4AaQBmAGUAcwB0AC4AeABtAGwAIgB9ACAA')
    IsOk()

def DesktopCacheClean():
    system('ie4uinit -show')
    IsOk()

def FixEDB():
    makedirs("C:\\WINDOWS\\system32\\config\\systemprofile\\AppData\\Local\\TileDataLayer\\Database")
    IsOk()

checkButtonFunction = [
    NoShare, NoTelnet, NoGuest, ProtectUSB, NoAutoRun, NoRemote, NoBing, AutoEndTask, ErrorOptimizationClean, OptimizeSuperfetch, NoSearchIndex, NoVFX, NoDormancy, OptimizeService, OfficeSecurity
]

treasureBoxFunction = [
    ARPClean, WinsockReset, DllReload, NoWarn, FixMsiServer, FixGpedit, DnsFlush, EnableCMD, EnableREG, EnableFireWall, RouteClean, Win10APPReset, DesktopCacheClean, FixEDB
]