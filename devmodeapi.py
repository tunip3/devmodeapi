import sys
import requests
import json
import urllib3
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

    def _get(self, endpoint):
        r = self.session.get(self.base_url + endpoint)
        return r

    def devicefamily(self):
        family = self._get('/api/os/devicefamily').json()
        return family.get('DeviceType')

    def machinename(self):
        machine = self._get('/api/os/machinename').json()
        return machine.get('ComputerName')

    def sandbox(self):
        sandbox = self._get('/ext/xboxlive/sandbox').json()
        return sandbox.get('Sandbox')

    def _get_info(self):
        return self._get('/ext/xbox/info').json()

    def osversion(self):
        info = self._get_info()
        return info.get('OsVersion')

    def devmode(self):
        info = self._get_info()
        return info.get('DevMode')

    def osedition(self):
        info = self._get_info()
        return info.get('OsEdition')

    def consoletype(self):
        info = self._get_info()
        return info.get('ConsoleType')

    def consoleid(self):
        info = self._get_info()
        return info.get('ConsoleId')

    def deviceid(self):
        info = self._get_info()
        return info.get('DeviceId')

    def serialnumber(self):
        info = self._get_info()
        return info.get('SerialNumber')

    def devkitcertificationexpirationtime(self):
        info = self._get_info()
        return info.get('DevkitCertificateExpirationTime')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Please provide IP address')
        print('Usage: {0} <ip>'.format(sys.argv[0]))
        sys.exit(1)
    
    ip_address = sys.argv[1]
    api = XboxOneDevmodeApi(ip_address)

    print('ConsoleId: {0}'.format(api.consoleid()))
    print('ConsoleType: {0}'.format(api.consoletype()))
    print('DeviceFamily: {0}'.format(api.devicefamily()))
    print('DeviceId: {0}'.format(api.deviceid()))
    print('Serial: {0}'.format(api.serialnumber()))
    print('DevkitExpiration: {0}'.format(api.devkitcertificationexpirationtime()))
    print('DevMode: {0}'.format(api.devmode()))
    print('MachineName: {0}'.format(api.machinename()))
    print('OsEdition: {0}'.format(api.osedition()))
    print('OsVersion: {0}'.format(api.osversion()))
    print('Sandbox: {0}'.format(api.sandbox()))