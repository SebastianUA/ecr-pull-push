#!/usr/bin/env python3

# Still to do:
# * Check compatibility with Python2 and Python3 during tests
# * Check if the layer already exists with a HEAD request
# * Handle Authentification

from tempfile import mkdtemp
import tarfile
import sys
import os
import hashlib
import json
from os.path import join
import shutil

try:
    from http.client import HTTPConnection, HTTPSConnection
except:
    from httplib import HTTPConnection, HTTPSConnection

def compute_digest(filename):
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return "sha256:" + sha256_hash.hexdigest()


def parse_dst(dst):
    """
    >>> parse_dst('http://registry:5000/my/repository') == {'https': False, 'host': 'registry:5000', 'path': '/v2/my/repository/'}
    True
    >>> parse_dst('http://registry:5000/my/repository/') == {'https': False, 'host': 'registry:5000', 'path': '/v2/my/repository/'}
    True
    >>> parse_dst('registry/my/repository/') == {'https': True, 'host': 'registry:5000', 'path': '/v2/my/repository/'}
    True
    >>> parse_dst('registry:5000/my/repository/') == {'https': True, 'host': 'registry:5000', 'path': '/v2/my/repository/'}
    True
    """
    if not dst.startswith("http://") and not dst.startswith('https://'):
        dst = "https://" + dst

    if dst.startswith("https://"):
        is_http = True
        dst = dst[8:]
    else:
        is_http = False
        dst = dst[7:]

    dst = dst.rstrip("/") + "/"

    p = dst.find('/', dst.find('//') + 2)
    dst = dst[:p] + "/v2" + dst[p:]

    host = dst.split('/')[0]
    if host.find(':') == -1:
        host = host + ':5000'

    return {
        "https": is_http,
        "host": host,
        "path": dst[dst.find('/'):]
    }


def perform_request(method, registry, path, body=None, headers={}):
    """
    See also: https://mail.python.org/pipermail/web-sig/2007-April/002662.html
    """
    response = None
    try:
        full_path = registry['path'] + path
        print(">  " + method + " " + registry['host'] + " " + full_path)
        h = HTTPSConnection(registry['host']) if registry['https'] else HTTPConnection(registry['host'])
        h.request(method, full_path, body, headers)
        response = h.getresponse()
    finally:
        if response != None:
            data = response.read()
            if len(data) > 0 and response.getcode() not in [201, 202]:
                print(data)
        h.close()
    print("    Return:" + str(response.status)) #response.getcode())
    return response


def upload_blob(registry, src_f):
    print("* Uploading " + src_f)
    r = perform_request('POST', registry, 'blobs/uploads/')

    if hasattr(r, 'headers'): # Python 3
        location = r.headers['Location']
    else: # Python 2
        location = [x[1] for x in r.getheaders() if x[0] == 'location'][0]

    # TODO: extract and unit test
    location_no_root = location[location.find(registry['path']) + len(registry['path']):]
    with open(src_f, "rb") as content_file:
        content = content_file.read()
    location_with_digest = location_no_root[:location_no_root.find('?')+1] + 'digest=' +compute_digest(src_f)+'&'+location_no_root[location_no_root.find('?')+1:]
    r = perform_request(
        'PUT',
        registry,
        location_with_digest,
        content,
        {'Content-Type': 'application/octet-stream', 'Content-Length': str(len(content))} # 'application/octet-stream'
    )
    # print(r.getcode())
    # print(r.getheaders())
    return

def upload_manifest(registry, manifest):
    print("* Uploading manifest")
    headers = {
        'Content-Type': 'application/vnd.docker.distribution.manifest.v2+json'
    }
    perform_request('PUT', registry, 'manifests/latest', manifest, headers)


def get_file_size(f):
    return os.path.getsize(f)

def build_manifest(config_f, layers_f):
    json_d = {}
    json_d['schemaVersion'] = 2
    json_d['mediaType'] = 'application/vnd.docker.distribution.manifest.v2+json'
    json_d['config'] = {
        'digest': compute_digest(config_f),
        'size': get_file_size(config_f),
        'mediaType': 'application/vnd.docker.container.image.v1+json'
    }
    json_d['layers'] = []
    for layer_f in layers_f:
        # TODO: check the layer is indeed compressed
        json_d['layers'].append({
            'digest': compute_digest(layer_f),
            'size': get_file_size(layer_f),
            'mediaType': "application/vnd.docker.image.rootfs.diff.tar.gzip"
        })
    return json.dumps(json_d)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("docker-push source destination")
        print("  Example: docker-push my-image http://registry:5000/my-repository")
        exit(1)

    src = sys.argv[1]
    assert os.path.isfile(src), src + " is not a file / does not exist"
    repository_url = parse_dst(sys.argv[2])
    try:
        temp_dir = mkdtemp()
        try:
            t = tarfile.TarFile(src)
        except tarfile.ReadError as e:
            print("Failed. Is " + src + " an Docker image?")
            sys.exit(1)
        t.extractall(temp_dir)
        manifest_path = os.path.join(temp_dir, "manifest.json")
        with open(manifest_path, "r") as manifest_file:
            manifest_content = manifest_file.read()
            print(manifest_content)
            manifest = json.loads(manifest_content)
            manifest = manifest[-1]
            config = manifest['Config'] if 'Config' in manifest else manifest['config']
            config_f = join(temp_dir, config)
            layers = manifest['Layers'] if 'Layers' in manifest else manifest['layers']
            layers_f = [join(temp_dir, l) for l in layers]
        manifest = build_manifest(config_f, layers_f)
        upload_blob(repository_url, config_f)
        for layer_f in layers_f:
            upload_blob(repository_url, layer_f)
        upload_manifest(repository_url, manifest)
    finally:
        shutil.rmtree(temp_dir)