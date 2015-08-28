#!/usr/bin/env python
# -*- encoding: utf-8

"""
Python source code - replace this with a description of the code and write the
code below this text.
"""

from os import environ
from cloudfs import *


client_id = environ['HUBIC_CLIENT_ID']
client_secret = environ['HUBIC_CLIENT_SECRET']
ref_token = environ['HUBIC_REFRESH_TOKEN']

h = Hubic(client_id, client_secret, ref_token)
h.connect()

print("Use h")
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
