import sys
import datetime
import requests
import urllib3
from base64 import b64encode
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class XboxOneDevmodeApi(object):
    PORT = 11443

    def __init__(self, ip_addr):
        self.ip_addr = ip_addr
        self.base_url = 'https://{0}:{1}'.format(self.ip_addr, self.PORT)
        self.session = requests.session()

        # Console has self-signed / unverified cert
        # SSL verification is disabled here
        self.session.verify = False

    @property
    def _csrf_header(self):
        return {'X-CSRF-Token': self.session.cookies.get('CSRF-Token')}

    def _get(self, endpoint, *args, **kwargs):
        return self.session.get(self.base_url + endpoint, *args, **kwargs)

    def _post(self, endpoint, *args, **kwargs):
        return self.session.post(self.base_url + endpoint, headers=self._csrf_header, *args, **kwargs)

    def _put(self, endpoint, *args, **kwargs):
        return self.session.put(self.base_url + endpoint, headers=self._csrf_header, *args, **kwargs)

    def _delete(self, endpoint, *args, **kwargs):
        return self.session.delete(self.base_url + endpoint, *args, **kwargs)

    def set_credentials(self, user, pwd):
        self.session.auth = (user, pwd)

    def get_root(self):
        return self._get('/')
		
    def launchapp(self, relativeappid):
        rai = str(b64encode(relativeappid.encode()))
        rai = rai[2:-1]
        rai = rai.replace("=", "%3D")
        url="/api/taskmanager/app?appid="+rai
        return self._post(url)

    def setmachinename(self, name):
        name = str(b64encode(name.encode()))
        name = name[2:-1]
        name = name.replace("=", "%3D")
        url="/api/os/machinename?name="+name
        return self._post(url)

    def reboot(self):
        return self._post('/api/control/restart')

    def shutdown(self):
        return self._post('/api/control/shutdown')

    def install(self, appx):
        files = {'upload_file': appx}
        filename=str(appx)
        filename=filename[26:-2]
        url="/api/app/packagemanager/package?package="+filename
        return self._post(url, files=files)

    def get_isproxyenabled(self):
        family = self._get('/ext/fiddler ').json()
        return family.get('IsProxyEnabled') == 'true'
    
    def get_knownfolders(self):
        family = self._get('/api/filesystem/apps/knownfolders').json()
        return family.get('KnownFolders')

    def get_devicefamily(self):
        family = self._get('/api/os/devicefamily').json()
        return family.get('DeviceType')

    def get_connectedcontrollercount(self):
        controllers = self._get('/ext/remoteinput/controllers').json()
        return controllers.get('ConnectedControllerCount')

    def get_machinename(self):
        machine = self._get('/api/os/machinename').json()
        return machine.get('ComputerName')

    def get_xblsandbox(self):
        sandbox = self._get('/ext/xboxlive/sandbox').json()
        return sandbox.get('Sandbox')

    def get_settings(self):
        return self._get('/ext/settings').json()

    def get_setting(self, name):
        return self._get('/ext/settings/{0}'.format(name)).json()

    def get_sandbox(self):
        sandbox = self._get('/ext/xboxlive/sandbox').json()
        return sandbox.get('Sandbox')

    def _get_info(self):
        return self._get('/ext/xbox/info').json()

    def get_osversion(self):
        info = self._get_info()
        return info.get('OsVersion')

    def get_devmode(self):
        info = self._get_info()
        return info.get('DevMode')

    def get_osedition(self):
        info = self._get_info()
        return info.get('OsEdition')

    def get_consoletype(self):
        info = self._get_info()
        return info.get('ConsoleType')

    def get_consoleid(self):
        info = self._get_info()
        return info.get('ConsoleId')

    def get_deviceid(self):
        info = self._get_info()
        return info.get('DeviceId')

    def get_serialnumber(self):
        info = self._get_info()
        return info.get('SerialNumber')

    def get_devkitcertificationexpirationtime(self):
        info = self._get_info()
        timestamp = info.get('DevkitCertificateExpirationTime')
        return datetime.datetime.fromtimestamp(timestamp)

    def _get_osinfo(self):
        return self._get('/api/os/info').json()

    def get_oseditionid(self):
        osinfo = self._get_osinfo()
        return osinfo.get('OsEditionId')

    def get_buildlabex(self):
        osinfo = self._get_osinfo()
        return osinfo.get('OsVersion')

    def get_language(self):
        osinfo = self._get_osinfo()
        return osinfo.get('Language')

    def _get_smbinfo(self):
        return self._get('/ext/smb/developerfolder').json()
    
    def get_smbpath(self):
        smbinfo =  self._get_smbinfo()
        return smbinfo.get('Path')

    def get_smbusername(self):
        smbinfo =  self._get_smbinfo()
        return smbinfo.get('Username')

    def get_smbpassword(self):
        smbinfo =  self._get_smbinfo()
        return smbinfo.get('Password')

    def _get_processes(self):
        return self._get('/api/resourcemanager/processes').json()

    def _get_processlist(self):
        processlist = self._get_processes()
        return processlist.get('Processes')

    def get_processnames(self):
        names=[]
        for i in self._get_processlist():
            proc = i.get('ImageName')
            if proc != '':
                names.append(proc)
        return names

    def get_pidsfromprocessname(self, name):
        pids=[]
        for i in self._get_processlist():
            procname = i.get('ImageName')
            if procname == name:
                pid = i.get('ProcessId')
                pids.append(pid)
        return pids

    def get_processnamefrompid(self, pid):
        for i in self._get_processlist():
            procid = i.get('ProcessId')
            if procid == pid:
                name = i.get('ImageName')
        return name

    def get_usernamefrompid(self, pid):
        for i in self._get_processlist():
            procid = i.get('ProcessId')
            if procid == pid:
                user = i.get('UserName')
        return user

    def get_cpuusagefrompid(self, pid):
        for i in self._get_processlist():
            procid = i.get('ProcessId')
            if procid == pid:
                cpu = i.get('CPUUsage')
        return cpu

    def remove_trustedsshpins(self):
        remove = self._delete('/ext/app/sshpins')
        return remove.status_code

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('ERROR: Please provide IP address')
        print('Usage: {0} <ip> <username> <password>'.format(sys.argv[0]))
        sys.exit(1)
    
    ip_address = sys.argv[1]
    api = XboxOneDevmodeApi(ip_address)

    if len(sys.argv) == 4:
        username = sys.argv[2]
        password = sys.argv[3]
        api.set_credentials(username, password)

    r = api.get_root()
    if r.status_code != 200:
        print('ERROR: Authentication failed, HTTP Status: {0}'.format(r.status_code))
        sys.exit(2)

    print("Is proxy enabled : {0}".format(api.get_isproxyenabled()))	
    print("Folders in top directory : {0}".format(api.get_knownfolders()))
    print('ConsoleId: {0}'.format(api.get_consoleid()))
    print('ConsoleType: {0}'.format(api.get_consoletype()))
    print('DeviceFamily: {0}'.format(api.get_devicefamily()))
    print('DeviceId: {0}'.format(api.get_deviceid()))
    print('Serial: {0}'.format(api.get_serialnumber()))
    print('DevkitExpiration: {0}'.format(api.get_devkitcertificationexpirationtime()))
    print('DevMode: {0}'.format(api.get_devmode()))
    print('MachineName: {0}'.format(api.get_machinename()))
    print('XboxLiveSandbox: {0}'.format(api.get_xblsandbox()))
    print('OsEdition: {0}'.format(api.get_osedition()))
    print('OsEditionId: {0}'.format(api.get_oseditionid()))
    print('OsVersion: {0}'.format(api.get_osversion()))
    print('BuildLabEx: {0}'.format(api.get_buildlabex()))
    print('ConnectedControllerCount: {0}'.format(api.get_connectedcontrollercount()))
    print('Language: {0}'.format(api.get_language()))
    print('SMB Path: {0}'.format(api.get_smbpath()))
    print('SMB Username: {0}'.format(api.get_smbusername()))
    print('SMB Password: {0}'.format(api.get_smbpassword()))
    print('Name of the process with pid 0: {0}'.format(api.get_processnamefrompid(0)))
    print('User currently running the process with pid 0: {0}'.format(api.get_usernamefrompid(0)))
    print('CPU usage of the process with pid 0: {0}%'.format(api.get_cpuusagefrompid(0)))
    #print('Status code from deleting trusted ssh pins: {0}'.format(api.remove_trustedsshpins()))
    #print('currently running processes:')
    #for i in api.get_processnames():
    #    print(i)
    #print('pids for sshd.exe')
    #for i in apik.get_pidsfromprocessname('sshd.exe'):
    #    print(i)
    api.launchapp('DefaultApp_cw5n1h2txyewy!App')
    #this works just doesnt show up in the dev menu app
    #api.setmachinename('XBOXONE')
    #print('Setting: {0}'.format(api.get_setting('DefaultUWPContentTypeToGame')))
	# api.reboot()
