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
from math import ceil
from threading import Thread
from time import sleep
from datetime import datetime
import copy
import sys
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

class CloudFileReader(object):
    MAX_CHUNK_SIZE = 1024 * 1024 * 2

    """
    Totally thread unsafe IO-like interface with a read buffer and some extra functionalities
    """
    def __init__(self, url, cfsobj):
        self.url = url
        self.cfsobj = cfsobj
        self.reset()

    @property 
    def current_data(self):
        return self._datawindow[self._lhead:-1]

    @property
    def feof(self):
        return self._head == self._size

    def reset(self):
        self._head = 0
        self._readable = True
        self._datawindow = bytes()
        self._lhead = 0
        self._feof = False
        self.closed = False
        self._getinfo()

    def stat(self):
        return dict(st_mode=self.cfsobj._mode, st_mtime=self._mtime,
            st_uid=self.cfsobj._uid, st_gid=self.cfsobj._gid)

    def _getinfo(self):
        data = self.cfsobj._send_request('HEAD', self.url)
        if data.status_code >= 200 and data.status_code < 400:
            self._size = int(data.headers['content-length'])
            self._seekunit = 1 if 'bytes' in data.headers['accept-ranges'] else 1
            self._mtime = datetime.fromtimestamp(float(data.headers['x-timestamp']))
        else:
            self._readable = False
        
    def _getchunk(self, size):
        if self._feof:
            return False
        first = self._head
        last = min(self._size, first + size * self._seekunit)
        h = { 'Range': 'bytes={}-{}'.format(
                first,
                last
            )}
        data = self.cfsobj._send_request('GET', self.url, extra_headers = h)
        if data.status_code >= 200 and data.status_code < 400:
            if last == self._size:
                self._feof = True
            self._datawindow = bytes(data.content)
            self._lhead = 0
            self._head += last - first
            return True
        else:
            self._feof = True
            print("Error", data.status_code)
            return False

    def read_generator(self, size=-1):
        if self.closed: raise IOError("reading closed file")
        if size == -1:
            data_to_read = self._size
            size = self.MAX_CHUNK_SIZE
        else:
            data_to_read = size
        while data_to_read >= 0 and self._readable:
            if self._lhead + size > len(self._datawindow):
                oldchunk = self._datawindow
                oldhead = self._lhead
                if not self._getchunk(self.MAX_CHUNK_SIZE):
                    self._readable = False
                    yield oldchunk[oldhead:-1]
                    continue
                else:
                    left = size - len(oldchunk) + oldhead
                    self._lhead = left
                    data_to_read -= size
                    yield oldchunk[oldhead:-1] + self._datawindow[0:left]
            else:
                self._lhead += size
                data_to_read -= size
                yield self._datawindow[self._lhead-size:self._lhead]

    def read(self, size=-1):
        if self.closed: raise IOError("reading closed file")
        return ''.join(a for a in self.read_generator(size))
        
    def read1(self, size=-1):
        return self.read(size)

    def seekable(self):
        return False
    
    def readable(self):
        return self._readable

    def writable(self):
        return False

    def tell(self):
        return self._head + self._lhead

    def close(self):
        self.closed = True

    
    def readline_generator(self, size=-1):
        if self.closed: raise IOError("reading closed file")
        if self.feof: yield ""
        else:
            lfpos = self.current_data.find('\n')
            if lfpos > 0:
                # advance head anyway
                self._lhead += lfpos
                if size > -1:
                    #reduce head if size given: yield incomplete line
                    lfpos = min(lfpos, size)
                yield self._datawindow[self._lhead - lfpos:self._lhead]

    def readline(self, size=-1):
        if self.closed: raise IOError("reading closed file")
        if self.feof: return ""
        return next(self.readline_generator(size))

    def readlines_generator(self, hint=-1):
        if self.closed: raise IOError("reading closed file")
        br = 0
        while not self.feof:
            d = self.readline(-1)
            br += len(d)
            yield d
            if hint > 0 and br > hint:
                break

    def readlines(self, hint=-1):
        if self.closed: raise IOError("reading closed file")
        return [a for a in self.readlines_generator(hint)]

    def readinto(self, b):
        if self.closed: raise IOError("reading closed file")
        if not isinstance(b, bytearray):
            return None
        maxreads = len(b)
        reads = 0
        while reads < maxreads and not self.feof:
            b[reads] = self.read(1)
            reads += 1
        return reads

    def next(self):
        if self.feof: raise StopIteration
        return self.read(1)

    def getvalue(self):
        if self.closed: raise IOError("reading closed file")
        self.reset()
        return self.read(-1)

class CloudFS(object):
    """
    Implements CloudFS logic in python. Some logic is deported to specific objects
        - Files are handled by CloudFileReader which implements an IO-like interface
            to files
    """

    # we split files bigger than 10 MB into chunks
    # and use a manifest file
    MAX_FILE_CHUNK_SIZE = 1024 * 1024 * 10
    CHUNKS_FOLDER = 'system/chunks'
    MAX_UPLOAD_THREADS = 6

    @property
    def default_container(self):
        if self._default_container is None:
            self._default_container = ''
            dc = self._send_request('GET', '').content.replace('\n', '')
            self._default_container = dc
        return self._default_container

    def _header_dispatch(self, headers):
        self._last_headers = headers
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

    def _send_request(self, method, path, extra_headers = [], params = None, payload = None):
        tries = 3
        headers = dict(extra_headers)
        headers['X-Auth-Token'] = self.storage_token
        method = method.upper()
        path = unquote(path)
        extra_args = {}
        url = u'{}/{}/{}'.format(self.storage_url, self.default_container, path)
        
        if 'MKDIR' == method:
            headers['Content-Type'] = 'application/directory'
            method = 'PUT'
            pass
        elif 'MKLINK' == method:
            headers['Content-Type'] = 'application/link'
            pass
        elif 'PUT' == method:
            if isinstance(payload, basestring):
                streamsize = len(payload)
            elif isinstance(payload, io.FileIO) or isinstance(payload, file):
                streamsize = os.path.getsize(payload.name)
            if streamsize > self.MAX_FILE_CHUNK_SIZE:
                # send to upload queue and return
                print("Big file, queueing")
                self._uploadqueue.add((path, payload, streamsize))
                return
            else:
                # dicfrect upload
                extra_args = dict(data=payload)
        elif 'GET' == method:
            pass
        elif 'DELETE' == method:
            pass
        while tries > 0:
            response = requests.request(method, url=url, 
                    headers=headers, params=params, **extra_args)
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
        return self._send_request('MKDIR', label)

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
        return CloudFileReader(url = path, cfsobj = self)

    def delete_object(self, objpath):
        pass

    def write_stream(self, stream, path):
        " writes a stream to a path in an existing container. "
        return self._send_request('PUT', path, payload = stream)

    def copy_object(self, src, dst):
        pass

    def truncate_object(self, objpath, size):
        pass

    def set_credentials(self, client_id, client_secret, refresh_token):
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token

    def upload_queue(self):
        def _get_parts(stream, pfx, sz, totalsize):
            parts = ceil(totalsize / sz)
            partstrlen = len(str(parts)) + 1
            spl = pfx.split('/')
            chunkfolder = '/'.join(spl[0:-1])
            #a = stream.read(sz)
            i = 0
            #while len(a) > 0:
            while True:
                d = stream.read(sz)
                if len(d) == 0: break
                yield (pfx, str(i).zfill(partstrlen), d)
                i += 1

        def _file_uploader(url, headers, data):
            print("Sending %s" % (url,))
            requests.put(url, headers = headers, data = data)
            print("Done putting", url)

        queues = {}
        headers = {}
        threads = []
        for path, stream, streamsize in self._uploadqueue:
            for pfx, chunk, data in _get_parts(stream, 
                    self.CHUNKS_FOLDER + path, self.MAX_FILE_CHUNK_SIZE, streamsize):
                self.create_directory(self.CHUNKS_FOLDER + '/' + path)
                headers['X-Auth-Token'] = self.storage_token
                url = u'{}/{}/{}/{}/{}'.format(self.storage_url, self.default_container, self.CHUNKS_FOLDER, path, chunk)
                t = Thread(target=_file_uploader,
                    args=(url, headers, data))
                threads.append(t)
                t.start()
                while len([_ for _ in threads if _.isAlive()]) > self.MAX_UPLOAD_THREADS:
                    sleep(0.5)
                    print("waiting")
            url = u'{}/{}/{}'.format(self.storage_url, self.default_container, path)
            headers['X-Object-Manifest'] = '{}/{}/{}/'.format(self._default_container, self.CHUNKS_FOLDER, path)
            headers['Content-Type'] = 'application/octet-stream'
            requests.put(url, headers = headers, data = '')
            print("Created item")
        print("Joining laties")
        for t in threads: t.join()
        print("Done joining laties")
        self._uploadqueue.clear()
    def __init__(self, parameters = {}):
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
        self._uid = parameters.get('uid', 0)
        self._gid = parameters.get('uid', 0)
        self._mode = parameters.get('mode', 0750)
        self._uploadqueue = set()
        self._uploadpartsqueue = set()
        self.stopped = False

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

    def __init__(self, client_id, client_secret, refresh_token, *args, **kwargs):
        
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        CloudFS.__init__(self, *args, **kwargs)


def upload_file(h, verb, local, directory, remote):
    if verb == 'create':
        try:
            f, d = h.list_directory(directory)
            for a in f:
                if a['name'].split('/')[-1] == remote:
                    print("File exists")
                    return
        except ValueError:
            pass
    h.write_stream(io.FileIO(local, "rb"), "{}/{}".format(directory, remote))
    h.upload_queue()
    print("Uploaded {} to {}".format(local, directory))


if __name__ == '__main__':
    from os import environ
    from sys import argv
    verb = argv[1]
    if verb not in 'create replace'.split():
        print("Usage: %s <create|replace> <(local_fn remote_folder [remote_fn])|('pipe' root_folder)>" % (argv[0],) )
        sys.exit(0)
    client_id = environ['HUBIC_CLIENT_ID']
    client_secret = environ['HUBIC_CLIENT_SECRET']
    ref_token = environ['HUBIC_REFRESH_TOKEN']
    h = Hubic(client_id, client_secret, ref_token)
    h.connect()
    if argv[2] == 'pipe':
        tgtdir = argv[3]
        for line in sys.stdin:
            line = line.replace('\n', '')
            d = tgtdir + os.path.dirname(line)
            tgt = os.path.basename(line)
            upload_file(h, 'create', line, d, tgt)
    else:
        filepath, targetfolder = argv[2:4]
        targetfile = os.path.basename(filepath) if len(argv) == 4 else argv[4]
        upload_file(h, verb, filepath, targetfolder, targetfile)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
