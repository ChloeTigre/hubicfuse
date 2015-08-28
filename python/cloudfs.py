#!/usr/bin/env python
# -*- encoding: utf-8

"""
CloudFS API port to python

"""
from collections import namedtuple
import os
import stat
import requests
from requests.auth import HTTPBasicAuth
import json
from urllib2 import unquote, quote

#define BUFFER_INITIAL_SIZE 4096
#define MAX_HEADER_SIZE 8192
#define MAX_PATH_SIZE (1024 + 256 + 3)
#define MAX_URL_SIZE (MAX_PATH_SIZE * 3)
#define USER_AGENT "CloudFuse"
#define OPTION_SIZE 1024

dir_entry = namedtuple("dir_entry", "name full_name content_type size last_modified isdir islink next")

segment_info = namedtuple("segment_info", "fh part size segment_size seg_base method")

options = namedtuple("options", "cache_timeout verify_ssl segment_size segment_above storage_url container temp_dir client_id client_secret refresh_token")


class CloudFS(object):
    """
    Implements CloudFS logic in python
    """
    def _header_dispatch(self, headers):
        # requests takes care of case sensitivity
            if 'x-auth-token' in headers:
                self.storage_token = headers['x-auth-token']
            if 'x-storage-url' in headers:
                self.storage_url = headers['x-storage-url']
            if 'x-account-meta-quota' in headers:
                self.block_quota = int(headers['x-account-meta-quota'])
            if 'x-account-bytes-used' in headers:
                self.free_blocks = self.block_quota - int(headers['x-account-bytes-used'])
            if 'x-account-object-count' in headers:
                print("Not handling")
                #self.

    def _send_request_size(self, method, path, fh = None, 
            extra_headers = {}, file_size = None, is_segment = False):
        tries = 3

        while tries > 0:
            headers = dict(extra_headers)
            url = "{}/{}".format(self.storage_url, path)
            if self.storage_url is None:
                print("No storage URL set")
                return
            path = unquote(path)
            headers['X-Auth-Token'] = self.storage_token
            if method == 'MKDIR':
                headers['Content-Type'] = 'application/directory'
            elif method == 'MKLINK':
                headers['Content-Type'] = 'application/link'
            elif method == 'PUT' and is_segment:
                pass
            elif method == 'PUT' and fp is not None:
                pass
            elif method == 'GET':
                if is_segment:
                    print("unsupported")
                    pass
                elif fh is not None:
                    pass
            elif method == 'DELETE':
                print("method", method)
            else:
                pass
            response = requests.request(method, url=url, headers=headers)
            
            if response.status_code == 401:
                self.connect()
            if response.status_code >= 200 and response.status_code <= 400 or (response.status_code == 409 and method == 'DELETE'):
                return response
            print response
            tries -= 1

    def read_file(self, fh):
        """read a file handler stream"""
        # object_read_fp
        pass

    def write_file(self, fh):
        """write a file handler stream"""
        # object_write_fp
        pass

    def file_size(self, fh):
        pass

    def create_symlink(self, src, dst):
        """create a symlink"""
        pass

    def create_directory(self, label):
        """create a directory"""
        pass

    def list_directory(self, dirpath):
        default_container = self._send_request_size('GET', '').content.replace('\n', '')
        print(default_container)
        data = self._send_request_size('GET', '{}/?format=json'.format(
            default_container)
            ).json()
        return data

    def delete_object(self, objpath):
        pass

    def copy_object(self, src, dst):
        pass

    def truncate_object(self, objpath, size):
        pass

    def set_credentials(self, client_id, client_secret, refresh_token):
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token

    def __init__(self):
        # initialize structures
        self.statcache = dict()
        self.storage_token = None
        self.storage_url = None
        self.block_quota = None
        self.free_blocks = None
        self.file_quota = None
        self.files_free = None


class Hubic(CloudFS):
    def connect(self):
        """ this performs the Hubic authentication """
        token_url = "https://api.hubic.com/oauth/token"
        creds_url = "https://api.hubic.com/1.0/account/credentials"
        req = {"refresh_token": self.refresh_token, "grant_type": "refresh_token" }
        response = requests.post(token_url, auth=(
            self.client_id,
            self.client_secret
            ),
            data=req)
        r = response.json()
        access_token = r['access_token']
        token_type = r['token_type']
        expires_in = r['expires_in']

        resp2 = requests.get(creds_url,
                headers={"Authorization": "Bearer {}".format(access_token)})
        r = resp2.json()
        self.storage_url = r['endpoint']
        self.storage_token = r['token']
        print("Done")

    def __init__(self, client_id, client_secret, refresh_token):
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
