import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def devicefamily(ip):
    family=requests.get("https://"+ ip +":11443/api/os/devicefamily", verify=False)
    for x in json.loads(family.text):
        return(json.loads(family.text)[x])
    
def machinename(ip):
    machine=requests.get("https://"+ ip +":11443/api/os/machinename", verify=False)
    for x in json.loads(machine.text):
        return(json.loads(machine.text)[x])

def sandbox(ip):
    sb=requests.get("https://"+ ip +":11443/ext/xboxlive/sandbox", verify=False)
    for x in json.loads(sb.text):
        return(json.loads(sb.text)[x]+" test = " + x)

def osversion(ip):
    ver=requests.get("https://"+ip+":11443/ext/xbox/info", verify=False)
    for x in json.loads(ver.text):
        out=(json.loads(ver.text)[x])
        break
    return(out)

def devmode(ip):
    ver=requests.get("https://"+ip+":11443/ext/xbox/info", verify=False)
    i=0
    for x in json.loads(ver.text):
        out=(json.loads(ver.text)[x])
        if i == 1:
            break
        i+=1
    return(out)

def osedition(ip):
    ver=requests.get("https://"+ip+":11443/ext/xbox/info", verify=False)
    i=0
    for x in json.loads(ver.text):
        out=(json.loads(ver.text)[x])
        if i == 2:
            break
        i+=1
    return(out)

def consoletype(ip):
    ver=requests.get("https://"+ip+":11443/ext/xbox/info", verify=False)
    i=0
    for x in json.loads(ver.text):
        out=(json.loads(ver.text)[x])
        if i == 3:
            break
        i+=1
    return(out)

def consoleid(ip):
    ver=requests.get("https://"+ip+":11443/ext/xbox/info", verify=False)
    i=0
    for x in json.loads(ver.text):
        out=(json.loads(ver.text)[x])
        if i == 4:
            break
        i+=1
    return(out)

def deviceid(ip):
    ver=requests.get("https://"+ip+":11443/ext/xbox/info", verify=False)
    i=0
    for x in json.loads(ver.text):
        out=(json.loads(ver.text)[x])
        if i == 5:
            break
        i+=1
    return(out)

def serialnumber(ip):
    ver=requests.get("https://"+ip+":11443/ext/xbox/info", verify=False)
    i=0
    for x in json.loads(ver.text):
        out=(json.loads(ver.text)[x])
        if i == 6:
            break
        i+=1
    return(out)

def devkitcertificationexpirationtime(ip):
    ver=requests.get("https://"+ip+":11443/ext/xbox/info", verify=False)
    i=0
    for x in json.loads(ver.text):
        out=(json.loads(ver.text)[x])
        if i == 7:
            break
        i+=1
    return(out)
