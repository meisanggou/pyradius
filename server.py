#!/usr/bin/python

from __future__ import print_function
import requests
import binascii
from IPy import IP
from pyrad import dictionary, packet, server
from pyrfc.rfc2548 import generate_mppe_key
import logging

logging.basicConfig(filename="pyrad.log", level="DEBUG", format="%(asctime)s [%(levelname)-8s] %(message)s")


class RadiusServer(server.Server):

    secret = "CR_JingYun_CPD-BE-Developer"

    def __init__(self, addresses=[], authport=1812, acctport=1813, coaport=3799, hosts=None, dict=None,
                 auth_enabled=True, acct_enabled=True, coa_enabled=False, net_segment=None):
        server.Server.__init__(self, addresses, authport, acctport, coaport, hosts, dict, auth_enabled, acct_enabled,
                               coa_enabled)
        default_hosts = set()
        default_hosts.add("127.0.0.1")
        if net_segment is not None:
            ips = IP(net_segment)
            for x in ips:
                default_hosts.add(x.strNormal())
        for item in default_hosts:
            if item.startswith("192") is False:
                print(item)
            self.hosts[item] = server.RemoteHost(item, self.secret, item)

    def HandleAuthPacket(self, pkt):
        print("handle auth packet")
        user_name = pkt["User-Name"][0]
        auth_challenge = pkt["MS-CHAP-Challenge"][0]
        response = pkt["MS-CHAP2-Response"][0]
        reply = self.CreateReplyPacket(pkt)
        reply.code = packet.AccessReject
        data = dict(account=user_name, auth_challenge=binascii.b2a_hex(auth_challenge), response=binascii.b2a_hex(response))
        resp = requests.post("https://www.gene.ac/auth/chap/v2/", json=data)
        chap_error = "E=%s R=1 C={0} V=3 M=%s".format('0' * 32)
        if resp.status_code / 100 != 2:
            reply["MS-CHAP-Error"] = response[:1] + chap_error % (691, "Server Error")
        else:
            r = resp.json()
            print(r)
            message = r["message"].encode("utf-8")
            if r["status"] == 001:
                reply["MS-CHAP2-Success"] = response[:1] + r["data"]["auth_response"].encode("utf-8")
                reply["MS-MPPE-Encryption-Policy"] = "\x00\x00\x00\x01"  # Encryption-Allowed
                reply["MS-MPPE-Encryption-Types"] = "\x00\x00\x00\06"  # "RC4-4or128-bit-Allow"
                send_key = binascii.a2b_hex(r["data"]["send_key"])
                recv_key = binascii.a2b_hex(r["data"]["recv_key"])
                reply["MS-MPPE-Send-Key"] = generate_mppe_key(self.secret, pkt.authenticator, send_key)
                reply["MS-MPPE-Recv-Key"] = generate_mppe_key(self.secret, pkt.authenticator, recv_key)
                reply.code = packet.AccessAccept
            elif r["status"] == 30901:
                #  649 ERROR_NO_DIALIN_PERMISSION
                reply["MS-CHAP-Error"] = response[:1] + chap_error % (649, message)
            else:
                pass
        self.SendReplyPacket(pkt.fd, reply)

    def HandleAcctPacket(self, pkt):
        keys = ["NAS-IP-Address", "NAS-Port", "Service-Type", "Framed-Protocol", "User-Name", "Acct-Status-Type"]
        keys_ext = ["Acct-Session-Id", "Framed-IP-Address", "Calling-Station-Id", "Acct-Authentic"]
        keys_ext2 = ["Acct-Input-Packets", "Acct-Output-Packets", "Acct-Input-Octets","Acct-Output-Octets"]
        keys.extend(keys_ext)
        keys.extend(keys_ext2)
        data = []
        for key in keys:
            if key in pkt.keys():
                data.append("%s" % pkt[key][0])
            else:
                data.append("")
        logging.info("\t".join(data))
        reply = self.CreateReplyPacket(pkt)
        self.SendReplyPacket(pkt.fd, reply)

    def HandleCoaPacket(self, pkt):

        print("Received an coa request")
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        self.SendReplyPacket(pkt.fd, reply)

    def HandleDisconnectPacket(self, pkt):

        print("Received an disconnect request")
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        # COA NAK
        reply.code = 45
        self.SendReplyPacket(pkt.fd, reply)

if __name__ == '__main__':
    RadiusServer.secret = "local4"
    srv = RadiusServer(dict=dictionary.Dictionary("dictionary"), net_segment="192.168.120.0/24")
    srv.BindToAddress("")
    srv.Run()
