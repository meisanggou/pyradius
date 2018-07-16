#! /usr/bin/env python
# coding: utf-8

__author__ = '鹛桑够'

from pyrad.client import Client
from pyrad.dictionary import Dictionary
import pyrad.packet

srv = Client(server="localhost", secret=b"testing123", dict=Dictionary("dictionary"))
req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest, User_Name="local30", NAS_Identifier="localhost")
req["User-Password"] = req.PwCrypt("123456")
print(req["User-Password"])
reply = srv.SendPacket(req)
print(reply)
