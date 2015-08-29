#!/usr/bin/env python
# -*- encoding: utf-8

"""
CloudFS API port to python

"""
from collections import namedtuple, OrderedDict
import os
import stat
import requests
from requests.auth import HTTPBasicAuth
import json
import enum
import io
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

class File(OrderedDict):
    def __init__(self, *args, **kwargs):

        fname = kwargs.pop('fname', None)
        if fname is None:
            fname = kwargs['name']
        self.fname = fname
        OrderedDict.__init__(self, *args, **kwargs)
    pass

class Directory(OrderedDict):
    def __init__(self, dirname, *args, **kwargs):
        self.dirname = dirname
        OrderedDict.__init__(self, *args, **kwargs)

class FileIO(io.BufferedIOBase):
    def __init__(self, url, cfsobj):
        self.url = url
        self.cfsobj = cfsobj
        self._head = 0
        self._seeksize = 1024 * 512
        self._readable = True
        self._getinfo()
        self._datawindow = bytes()

    def _getinfo(self):
        data = self.cfsobj._send_request('HEAD', self.url)
        if data.status_code >= 200 and data.status_code < 400:
            self._readable = False
            return
        self._size = data.headers['content-length']
        self._seekunit = 1 if 'bytes' in data.headers['accept-ranges'] else 1
        
    def _getchunk(self, size):
        first = self._head
        last = first + size * self._seekunit
        h = { 'Content-Range': 'bytes {}-{}/{}'.format(
                first,
                last,
                self._size
            )}
        data = self.cfsobj._send_request('GET', self.url, extra_headers = h)
        if data.status_code >= 200 and data.status_code < 400:
            self._readable = False
            return
        self._datawindow = bytes(data.content)
        
    def seekable(self):
        return False
    
    def readable(self):
        return self._readable

    def tell(self):
        return self._head

    def close(self):
        self.closed = True
    
    def readline(self, size=-1):
        
        pass

    def readlines(self, hint=-1):
        pass


class CloudFS(object):
    """
    Implements CloudFS logic in python
    """

    @property
    def default_container(self):
        if self._default_container is None:
            self._default_container = ''
            dc = self._send_request('GET', '').content.replace('\n', '')
            self._default_container = '/' + dc
        return self._default_container

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
                pass

    def _send_request(self, method, path, extra_headers = [], params = None):
        tries = 3
        headers = dict(extra_headers)
        headers['X-Auth-Token'] = self.storage_token
        method = method.upper()
        path = unquote(path)
        url = u'{}{}/{}'.format(self.storage_url, self.default_container, path)
        print(url)
        
        if 'MKDIR' == method:
            headers['Content-Type'] = 'application/directory'
            pass
        elif 'MKLINK' == method:
            headers['Content-Type'] = 'application/link'
            pass
        elif 'PUT' == method:
            pass
        elif 'GET' == method:
            pass
        elif 'DELETE' == method:
            pass
        while tries > 0:
            response = requests.request(method, url=url, 
                    headers=headers, params=params)
            if 401 == response.status_code:
                self.connect()
            elif (response.status_code >= 200 and response.status_code <= 400 or 
            (response.status_code == 409 and method == 'DELETE')):
                self._header_dispatch(response.headers)
                return response
            tries -= 1
        return response

    def create_symlink(self, src, dst):
        """create a symlink"""
        pass

    def create_directory(self, label):
        """create a directory"""
        pass

    def _cache_directory(self, refresh = False):
        if refresh or self._dircache is None:
            resp = self._send_request('GET', 
                    '', params={'format':'json'}
                )
            data = resp.json()
            datatree = {}
            for f in data:
                if f['content_type'] == 'application/directory': continue
                pathsplit = f['name'].split('/')
                newpath = datatree
                n = newpath
                for elm in pathsplit[0:-1]:
                    if elm not in n:
                        n[elm] = Directory(dirname=elm)
                    n = n[elm]
                n[pathsplit[-1]] = File(fname=pathsplit[-1], **f)
                datatree.update(newpath)
            self._dircache = datatree
        return self._dircache

    def list_directory(self, dirpath):
        dircache = self._cache_directory()
        spl = dirpath.split('/')
        n = dircache
        for e in spl:
            n = n.get(e, ValueError("Item does not exist"))
            if isinstance(n, ValueError):
                raise n

        files = [a for a in n.itervalues() if isinstance(a, File)]
        dirs = {k: a for k, a in n.iteritems() if isinstance(a, Directory)}
        return files, dirs

    def get_file(self, path, packetsize = 512*1024, offset = 0):
        data = self._send_request('HEAD', path)
        filesize = data.headers['content-length']
        if filesize > packetsize:
            pass
        else:
            pass
        return FileIO(url = path, cfsobj = self)

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
        self._dircache = None
        self._default_container = None


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
        CloudFS.__init__(self)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
