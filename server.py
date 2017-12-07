#!/usr/bin/python

from __future__ import print_function
import requests
import binascii
from pyrad import dictionary, packet, server
from pyrfc.rfc2548 import generate_mppe_key
import logging

logging.basicConfig(filename="pyrad.log", level="DEBUG", format="%(asctime)s [%(levelname)-8s] %(message)s")


class RadiusServer(server.Server):

    def HandleAuthPacket(self, pkt):
        print("Received an authentication request")
        user_name = pkt["User-Name"][0]
        auth_challenge = pkt["MS-CHAP-Challenge"][0]
        response = pkt["MS-CHAP2-Response"][0]
        reply = self.CreateReplyPacket(pkt)
        reply.code = packet.AccessReject
        data = dict(account=user_name, auth_challenge=binascii.b2a_hex(auth_challenge), response=binascii.b2a_hex(response))
        resp = requests.post("https://www.gene.ac/auth/chap/v2/", json=data)
        print(resp.text)
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
                reply["MS-MPPE-Send-Key"] = generate_mppe_key("local4", pkt.authenticator, send_key)
                reply["MS-MPPE-Recv-Key"] = generate_mppe_key("local4", pkt.authenticator, recv_key)
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
        print("\t".join(data))
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

    # create server and read dictionary
    srv = RadiusServer(dict=dictionary.Dictionary("dictionary"))
    # srv.dict.ReadDictionary("dictionary.microsoft")
    # add clients (address, secret, name)
    srv.hosts["127.0.0.1"] = server.RemoteHost("127.0.0.1", b"local", "localhost")
    srv.hosts["192.168.120.15"] = server.RemoteHost("192.168.120.15", b"local10", "localhost")
    srv.hosts["192.168.120.4"] = server.RemoteHost("192.168.120.4", b"local4", "local4")
    srv.BindToAddress("")

    # start server
    srv.Run()
