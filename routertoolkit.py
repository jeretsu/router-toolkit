import docker
import sys
import os
import subprocess
import requests
import configparser
from datetime import datetime

#jeretsu 2022-2025

#Nmap (Docker)
#testssl.sh (Docker)
#dirbuster (Docker)
#routersploit (subprocess)
#wifite2 (subprocess)
#zaproxy (Docker)
#Password tester (in Python code)
#google ping (subprocess)

client = docker.from_env()

IP = ""
ESSID = ""
configPortal = ""
testsslPort = ""
interface = ""
wifi_passwd = ""
admin_passwd = ""
userID = ""
wifite2_path = ""
routersploit_path = ""
log_identifier = ""
logfile = ""
wifite_dict = ""
dirbuster_dict = ""
runNmap = ""
runPasswordAnalyze = ""
runWifite2 = ""
runDirbuster = ""
runZAProxy = ""
runTestssl = ""
runRoutersploit = ""
runGooglePing = ""

def configRead():
    """Read config file and return config object"""

    config = configparser.ConfigParser()
    config.read('config.cfg')
    print(config.sections())
    return config
    
def configToGlobal(config):
    """Place config values into global variables"""

    global IP,ESSID, configPortal, testsslPort, interface, wifi_passwd, admin_passwd, userID, wifite2_path, routersploit_path, log_identifier, wifite_dict, dirbuster_dict
    global runNmap, runPasswordAnalyze, runWifite2, runDirbuster, runTestssl, runZAProxy, runRoutersploit

    IP = config['routertoolkit']['IP']
    ESSID = config['routertoolkit']['ESSID']
    configPortal = config['routertoolkit']['configPortal']
    testsslPort = config['routertoolkit']['testsslPort']
    interface = config['routertoolkit']['interface']
    wifi_passwd = config['routertoolkit']['wifi_passwd']
    admin_passwd = config['routertoolkit']['admin_passwd']
    userID = config['routertoolkit']['userID']
    wifite2_path = config['routertoolkit']['wifite2_path']
    routersploit_path = config['routertoolkit']['routersploit_path']
    log_identifier = config['routertoolkit']['log_identifier']
    wifite_dict = config['routertoolkit']['wifite_dict']
    dirbuster_dict = config['routertoolkit']['dirbuster_dict']
    runNmap = config['routertoolkit']['runNmap']
    runPasswordAnalyze = config['routertoolkit']['runPasswordAnalyze']
    runWifite2 = config['routertoolkit']['runWifite2']
    runDirbuster = config['routertoolkit']['runDirbuster']
    runZAProxy = config['routertoolkit']['runZAProxy']
    runTestssl = config['routertoolkit']['runTestssl']
    runRoutersploit = config['routertoolkit']['runRoutersploit']
    runGooglePing = config['routertoolkit']['runGooglePing']
    return

def testPrintGlobals():
    """Test prints for global variables"""

    print(IP)
    print(ESSID)
    print(configPortal)
    print(testsslPort)
    print(interface)
    print(wifi_passwd)
    print(admin_passwd)
    print(userID)
    print(wifite2_path)
    print(routersploit_path)
    print(log_identifier)
    print(wifite_dict)
    print(dirbuster_dict)
    print("Google Ping: " + runGooglePing)
    print("Nmap: " + runNmap)
    print("Password Analyze: " + runPasswordAnalyze)
    print("testssl.sh: " + runTestssl)
    print("ZAProxy: " + runZAProxy)
    print("Dirbuster: " + runDirbuster)
    print("Routersploit: " + runRoutersploit)
    print("Wifite2: " + runWifite2)
    return

def createLog():
    """Creates initial log file. Other functions append to this"""
    global logfile
    now = datetime.now()
    timestamp = now.strftime("%b-%d-%Y %H:%M:%S")
    filename = "RTK " + log_identifier + " " + timestamp + ".txt"
    logfile = filename
    try:
        f = open(filename, "x")
        print("Logfile created with name " + logfile)
    except FileExistsError:
        print("File already exists")
        raise
    return
    

def streamer(container, name):
    """Streams docker container logs line-by-line"""
    
    dirQcounter = 0

    log = open(logfile, "a")
    log.write("START OF " + name + " CONTAINER \n \n")
    log.close()

    if(name == "DIRBUSTER"):
        for line in container.logs(stream=True):
            line = line.decode("utf-8")
            currentLine = line.strip()
            print(currentLine)
            x = currentLine.startswith("DEBUG")
            if(x == True):
                dirQcounter = 0
                pass
            elif(currentLine == "dirQ: 0"):
                dirQcounter += 1
                if(dirQcounter >= 10):
                    log = open(logfile, "a")
                    log.write("END OF " + name + "\n \n")
                    log.close()
                    return
            else:
                log = open(logfile, "a")
                log.write(str(currentLine))
                log.write("\n")
                log.close()
                dirQcounter = 0
    else:
        for line in container.logs(stream=True):
            line = line.decode("utf-8")
            currentLine = line.strip()
            print(currentLine)
            log = open(logfile, "a")
            log.write(str(currentLine))
            log.write("\n")
            log.close()
        
    log = open(logfile, "a")
    log.write("END OF " + name + "\n \n")
    log.close()
    return

def checkCLS4spec(length, variety, consecutiveFlag, sameAsID):
    if(length >= 10 and consecutiveFlag == 0 and variety >= 3 and sameAsID == 0):
        return "Pass"
    else:
        return "Does not meet the requirements"

def checkBSIspec(length, variety):
    if(length >= 8 and variety >= 2):
        return "Pass"
    else:
        return "Does not meet the requirements"

def passwordAnalyze():
    """Password tested for CLS Tier 4 and BSI TR-03148 Specification"""

    if runPasswordAnalyze != "1":
        return

    charUpper = 0
    charLower = 0
    digit = 0
    special = 0
    charUpperFlag = 0
    charLowerFlag = 0
    digitFlag = 0
    specialFlag = 0
    consecutiveFlag = 0
    lastchar = None
    length = len(admin_passwd)
    sameAsID = 0

    log = open(logfile, "a")

    log.write("START OF PASSWORD ANALYSIS  \n \n")

    for i in range(0, len(admin_passwd)):
        if lastchar != None:
            if admin_passwd[i] == lastchar:
                consecutiveFlag = 1
            else:
                pass
        lastchar = admin_passwd[i]
        if(admin_passwd[i].isalpha()):
            if(admin_passwd[i].isupper()):
                charUpper += 1
                charUpperFlag = 1
            else:
                charLower += 1
                charLowerFlag = 1
        elif(admin_passwd[i].isdigit()):
            digit += 1
            digitFlag = 1
        else:
            special += 1
            specialFlag = 1
        variety = charUpperFlag + charLowerFlag + digitFlag + specialFlag

    if(admin_passwd == userID):
        sameAsID = 1
        log.write("User ID and password are the same \n")
        print("User ID and password are the same")
    
    print("Password contains \n" + str(charLower) + " Lowercase characters \n" + str(charUpper) + " Uppercase characters \n" + str(digit) + " Digits \n" + str(special) + " Special characters")
    print("Variety = " + str(variety))
    print("Password length = " + str(length))

    log.write("Password contains \n" + str(charLower) + " Lowercase characters \n" + str(charUpper) + " Uppercase characters \n" + str(digit) + " Digits \n" + str(special) + " Special characters \n")
    log.write("Variety = " + str(variety) + "\n")
    log.write("Password length = " + str(length) + "\n")

    if consecutiveFlag == 1:
        print("Password has consecutive characters")
        log.write("Password has consecutive characters \n")
    
    cls4result = checkCLS4spec(length, variety, consecutiveFlag, sameAsID)
    bsiresult = checkBSIspec(length, variety)

    print("Checking against CLS Tier 4 Test Specification: " + cls4result)
    print("Checking against BSI TR-03148 Specification: " + bsiresult)

    log.write("Checking against CLS Tier 4 Test Specification: " + cls4result + "\n")
    log.write("Checking against BSI TR-03148 Specification: " + bsiresult + "\n")
    log.write("END OF PASSWORD ANALYSIS \n \n")
    log.close()
    return

def googlePing():
    """Google ping with subprocess"""
    if runGooglePing != "1":
        return

    print("Pinging google.com for 5 seconds")
    
    log = open(logfile, "a")
    log.write("START OF GOOGLE PING \n \n")
    log.close()

    log = open(logfile, "a")
    subprocess.run(["ping", "-w", "5", "google.com"], stdout=log, stderr=log)
    #ping -w 5 google.com
    print("Google ping complete")
    log.write("\n")
    log.close()
    return

def wifite2Run():
    """wifite2 run with subprocess"""

    if runWifite2 != "1":
        return

    print("Starting wifite2")
    print("Press enter when ready")
    x = input(">")

    log = open(logfile, "a")
    log.write("START OF WIFITE2 RUN \n \n")
    log.close()
    
    log = open(logfile, "a")
    #Replace 'user' with own arch username
    subprocess.run(["sudo", "python3", "/home/user/kimo-wifite/wifite2/wifite.py", "--dict", wifite_dict, "-e", ESSID], capture_output=False, text=True, stdout=log, stderr=log)

    log.write("\n")
    log.write("END OF WIFITE2 \n \n")
    log.close()
    print("Wifite2 scan complete")
    return

def toManagedMode():
    """Turn wifi-card back to Managed Mode with airmon-ng subprocess"""

    if runWifite2 != "1":
        return

    print("Changing WiFi card to Managed mode")
    subprocess.run(["sudo", "airmon-ng", "stop", interface], capture_output=False, text=True)
    return
    #subprocess.run(["sudo", "airmon-ng", "stop", "wlp3s0mon"], capture_output=False, text=True)
    #sudo airmon-ng stop wlp3s0mon

def zaproxyRun():
    """OWASP Zaproxy run with docker"""

    if runZAProxy != "1":
        return

    name = "OWASP ZAPROXY"

    print("Starting zaproxy")

    zaproxyContainer = client.containers.run("owasp/zap2docker-stable", ["zap-full-scan.py", "-t", configPortal], detach=True)
    streamer(zaproxyContainer, name)
    zaproxyContainer.stop()
    print("Zaproxy Scan Complete")
    return

def nmapRun():
    """Nmap run with docker"""

    if runNmap != "1":
        return

    name = "NMAP"

    print("Starting Nmap scan")
    nmapContainer = client.containers.run("instrumentisto/nmap", ["-v", "-sT", "-p-65535", "-A", IP], detach=True)
    #Other variations of nmap commands were used during testing
    streamer(nmapContainer, name)
    nmapContainer.stop()
    print("Nmap Scan Complete")
    return

def testsslRun():
    """testssl.sh run with docker"""

    if runTestssl != "1":
        return

    name = "TESTSSL.SH"

    print("Starting testssl.sh scan")

    IPandPORT = str(IP + ":" + testsslPort)

    testsslContainer = client.containers.run("drwetter/testssl.sh", ["-U", "--warnings", "off", "--logfile", "loki", IPandPORT], detach=True)
    streamer(testsslContainer, name)
    testsslContainer.stop()
    print("Testssl.sh scan complete")
    return

def dirbusterRun():
    """Dirbuster run with docker"""

    if runDirbuster != "1":
        return

    name = "DIRBUSTER"

    print("Starting dirbuster")

    dirbusterContainer = client.containers.run("hypnza/dirbuster", ["-P", "-R", "-v", "-l", "/DirBuster-0.12/directory-list-2.3-medium.txt", "-u", configPortal], detach=True)
    streamer(dirbusterContainer, name)
    dirbusterContainer.stop()
    print("Stopping dirbuster container")
    return

def routersploitRun():
    """Routersploit run with subprocess"""

    if runRoutersploit != "1":
        return

    print("Starting Routersploit scan")

    log = open(logfile, "a")
    log.write("START OF ROUTERSPLOIT RUN \n \n")
    log.close()
    
    log = open(logfile, "a")

    TARGETandIP = str("target " + IP)
    #Replace 'user' in filepath name
    subprocess.run(["python3", "/home/user/routersploit/rsf.py", "-m", "scanners/autopwn", "-s", TARGETandIP], capture_output=False, text=True, stdout=log, stderr=log)
    log.write("\n")
    log.write("END OF ROUTERSPLOIT \n \n")
    log.close()
    print("Routersploit scan complete")
    return

if __name__=="__main__":
    print("Start of program")
    RTKconfig = configRead()
    configToGlobal(RTKconfig)
    testPrintGlobals()
    createLog()
    googlePing()
    nmapRun()
    testsslRun()
    passwordAnalyze()
    routersploitRun()
    dirbusterRun()
    zaproxyRun()
    wifite2Run()
    toManagedMode()
    print("End of program")

