import requests
import argparse
from requests_ntlm import HttpNtlmAuth
from ldap3 import Server, Connection, ALL, NTLM

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


class ADCSfind(object):
    def __init__(self, domain, username, password, dc_ip, check_web, use_ssl):
        self.adcs_servers = []
        self.web_servers = []
        self.check_web = check_web
        self.protocols = ["http://", "https://"]
        self.domain_user = domain + "\\" + username
        self.password = password

        if use_ssl:
            if dc_ip is not None:
                self.server = Server(dc_ip, use_ssl=True, get_info=ALL)
            else:
                self.server = Server(domain, use_ssl=True, get_info=ALL)
        else:
            if dc_ip is not None:
                self.server = Server(dc_ip, use_ssl=False, get_info=ALL)
            else:
                self.server = Server(domain, use_ssl=False, get_info=ALL)

        self.conn = Connection(self.server, user=self.domain_user, password=password, authentication=NTLM)
        if not self.conn.bind():
            print("[-] Bind error")
            print("[?] Reason: " + self.conn.last_error)
            exit(-1)
        else:
            print("[+] Bind ok")
        self.BasePath = self.server.info.other['defaultNamingContext'][0]

    def getPublicKeyServices(self):
        print("[*] Getting servers from Public Key Services")
        base_path_key = "CN=Public Key Services,CN=Services,CN=Configuration," + self.BasePath
        self.conn.search("CN=Enrollment Services," + base_path_key, '(objectclass=*)')
        for first_ent in self.conn.entries:
            result_search = self.conn.search(first_ent.entry_dn, '(objectclass=*)', attributes="dNSHostName")
            if result_search:
                for second_ent in self.conn.entries:
                    if len(second_ent.dNSHostName) != 0:
                        for dNSHostName in second_ent.entry_raw_attributes['dNSHostName']:
                            self.adcs_servers.append(dNSHostName.decode())

            else:
                result_search = self.conn.search(first_ent.entry_dn, '(objectclass=*)', attributes='*')
                if result_search:
                    print("[?] Cant find dNSHostName, all attributes of object:\n")
                    print(self.conn.entries)

    def getCertPublishers(self):
        print("[*] Getting servers from Cert Publishers")
        self.conn.search("CN=Cert Publishers,CN=Users," + self.BasePath, "(objectclass=*)", attributes="member")
        for first_ent in self.conn.entries:
            for mem_dn in first_ent.member:
                result_search = self.conn.search(mem_dn, '(objectclass=computer)', attributes='dNSHostName')
                if result_search:
                    for secondEnt in self.conn.entries:
                        if len(secondEnt.dNSHostName) != 0:
                            for dNSHostName in secondEnt.entry_raw_attributes['dNSHostName']:
                                self.adcs_servers.append(dNSHostName.decode())
                else:
                    result_search = self.conn.search(mem_dn, '(objectclass=*)', attributes='*')
                    if result_search:
                        print("[?] Cant find dNSHostName, all attributes of object:")
                        print(self.conn.entries)

    def checkWebEnroll(self):
        for protocol in self.protocols:
            for serv in set(self.adcs_servers):
                check_leg_url = False
                check_enroll_url = False
                if requests.get(protocol + serv + "/certsrv/", auth=HttpNtlmAuth(self.domain_user, self.password),
                                verify=False).status_code == 200:
                    check_leg_url = True

                if requests.get(protocol + serv + "/certsrv/mscep/", auth=HttpNtlmAuth(self.domain_user, self.password),
                                verify=False).status_code == 200:
                    check_enroll_url = True

                if check_leg_url or check_enroll_url:
                    self.web_servers.append(serv)

    def printOutput(self, set_arr):
        for serv in set_arr:
            print(serv)

    def run(self):
        self.getPublicKeyServices()
        self.getCertPublishers()

        if self.check_web:
            self.checkWebEnroll()
            print("[+] ADCS and publisher servers:")
            self.printOutput(set(self.adcs_servers))
            print("[+] ADCS servers with web enroll:")
            self.printOutput(set(self.web_servers))
        else:
            print("[+] ADCS and publisher servers:")
            self.printOutput(set(self.adcs_servers))
        self.conn.unbind()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Find ADCS and publisher servers')
    parser.add_argument('-d', '--domain', required=True)
    parser.add_argument('-u', '--username', required=True)
    parser.add_argument('-p', '--password', required=True)
    parser.add_argument('--dc-ip', help="DC ip", required=False)
    parser.add_argument('--check-web', help="check web enroll endpoints", required=False, action='store_true')
    parser.add_argument('--use-ssl', help="use ssl for ldap", required=False, action='store_true')
    args = parser.parse_args()

    findObject = ADCSfind(domain=args.domain, username=args.username, password=args.password, dc_ip=args.dc_ip,
                          check_web=args.check_web, use_ssl=args.use_ssl)
    findObject.run()
