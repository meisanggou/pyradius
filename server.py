#!/usr/bin/python

from __future__ import print_function
import os
import requests
import binascii
from IPy import IP
from pyrad import dictionary, packet, server
from pyrfc.rfc2548 import generate_mppe_key
import logging

logging.basicConfig(filename="pyrad.log", level="DEBUG", format="%(asctime)s [%(levelname)-8s] %(message)s")

auth_endpoint = os.environ.get("RADIUS_EXTERNAL_AUTH_ENDPOINT", "http://127.0.0.1:6011")


class RadiusServer(server.Server):

    secret = b"testing123"

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
            self.hosts[item] = server.RemoteHost(item, self.secret, item)

    @staticmethod
    def print_pkt(pkt):
        print("-------------------------Start Print-------------------------")
        for key in pkt.keys():
            v = pkt[key][0]
            if isinstance(v, str):
                v = binascii.b2a_hex(v)
            s = "%s = %s" % (key, v)
            print(s)

    def chap_v2_auth(self, pkt):
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

    def eap_auth(self, pkt):
        # self.print_pkt(pkt)
        print(binascii.b2a_hex(pkt["EAP-Message"][0]))
        print(binascii.b2a_hex(pkt["Message-Authenticator"][0]))
        print(binascii.b2a_hex(pkt.authenticator))

        from pyrad.client import Client
        import six
        client = Client("172.16.110.4", secret=self.secret, dict=dictionary.Dictionary("dictionary"))
        kwargs = dict()

        new_pkt = client.CreateAuthPacket(code=packet.AccessRequest)
        all_keys = ["User-Name", "NAS-Identifier", "NAS-IP-Address", "NAS-Port", "Framed-MTU", "NAS-Port-Type", "Called-Station-Id", "Calling-Station-Id"]
        all_keys.append("EAP-Message")
        all_keys.append("Message-Authenticator")
        for key in pkt.keys():
            if key in all_keys:
                new_pkt[key] = pkt[key][0]
            else:
                print(key)
        new_pkt.authenticator = pkt.authenticator
        print(new_pkt.authenticator)
        reply = client.SendPacket(new_pkt)
        return self.SendReplyPacket(pkt.fd, reply)
        reply = self.CreateReplyPacket(pkt)
        reply.code = packet.AccessAccept
        return self.SendReplyPacket(pkt.fd, reply)

    def pap_auth(self, pkt):
        user_name = pkt["User-Name"][0]
        en_password = pkt["User-Password"][0]
        password = pkt.PwDecrypt(en_password)
        reply = self.CreateReplyPacket(pkt)
        reply.code = packet.AccessReject
        data = dict(account=user_name, password=password)
        resp = requests.post(auth_endpoint + "/auth/confirm/", json=data)
        if resp.status_code / 100 == 2:
            r = resp.json()
            if r["status"] == 001:
                reply.code = packet.AccessAccept
            else:
                print(r)
        self.SendReplyPacket(pkt.fd, reply)

    def HandleAuthPacket(self, pkt):
        print("handle auth packet")
        if "MS-CHAP-Challenge" in pkt:
            return self.chap_v2_auth(pkt)
        if "EAP-Message" in pkt:
            return self.eap_auth(pkt)
        elif "User-Password" in pkt:
            return self.pap_auth(pkt)

        self.print_pkt(pkt)
        reply = self.CreateReplyPacket(pkt)
        reply.code = packet.AccessReject
        self.SendReplyPacket(pkt.fd, reply)

    def HandleAcctPacket(self, pkt):
        keys = ["NAS-IP-Address", "NAS-Port", "Service-Type", "Framed-Protocol", "User-Name", "Acct-Status-Type"]
        keys_ext = ["Acct-Session-Id", "Framed-IP-Address", "Calling-Station-Id", "Acct-Authentic"]
        keys_ext2 = ["Acct-Input-Packets", "Acct-Output-Packets", "Acct-Input-Octets", "Acct-Output-Octets"]
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
    srv = RadiusServer(dict=dictionary.Dictionary("dictionary"), net_segment="172.16.110.0/24")
    srv.BindToAddress("0.0.0.0")
    srv.Run()
