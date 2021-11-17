#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import logging
import os
import shutil
import tarfile
import time
import urllib
from tempfile import mkdtemp

import boto3
import botocore
import botocore.session
import urllib3
from botocore.config import Config

# Initialize Logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.captureWarnings(True)

CACHE_DIR_ROOT = os.path.expanduser("~")
assert os.path.isdir(CACHE_DIR_ROOT)
CACHE_DIR = CACHE_DIR_ROOT + '/.docker-pull-layers-cache/'

if not os.path.exists(CACHE_DIR):
    print("Creating cache directory: " + CACHE_DIR)
    os.makedirs(CACHE_DIR)


def ec2_connector(aws_settings):
    if (aws_settings['client'] is not None) and (aws_settings['region'] is not None):
        try:
            session = botocore.session.get_session()
            access_key = session.get_credentials().access_key
            secret_key = session.get_credentials().secret_key
            session_token = session.get_credentials().token

            session = boto3.session.Session()
            ec2 = session.client(aws_access_key_id=access_key,
                                 aws_secret_access_key=secret_key,
                                 aws_session_token=session_token,
                                 service_name=aws_settings['client'],
                                 region_name=aws_settings['region'],
                                 config=Config(retries={'max_attempts': 3})
                                 )
            return ec2
        except Exception as err:
            print("Failed to create a boto3 client connection to ecr:\n", str(err))
            logger.error('ERROR: Failed to create a boto3 client connection')
            return False
    else:
        print('Please use/set [--bclient] and [--region]')
        return False


def ecr_connector(aws_settings):
    if (aws_settings['role_name'] is None or aws_settings['role_name'] == "None") \
            and (aws_settings['role_session'] is None or aws_settings['role_session'] == "None"):
        try:
            session = boto3.session.Session(profile_name=aws_settings['profile_name'])
            # Will retry any method call at most 3 time(s)
            ecr = session.client(service_name=aws_settings['client'],
                                 region_name=aws_settings['region'],
                                 config=Config(retries={'max_attempts': 3})
                                 )
            return ecr
        except Exception as err:
            print("Failed to create a boto3 client connection to ecr:\n", str(err))
            logger.error('ERROR: Failed to create a boto3 client connection to ecr')
            return False
    elif (aws_settings['profile_name'] is None or aws_settings['profile_name'] == "None") \
            and (aws_settings['role_name'] is not None or aws_settings['role_name'] != "None") \
            and (aws_settings['role_session'] is not None or aws_settings['role_session'] != "None"):
        try:
            session = boto3.session.Session()
            sts = session.client(service_name='sts',
                                 region_name=aws_settings['region'],
                                 config=Config(retries={'max_attempts': 3})
                                 )

            assumed_role_object = sts.assume_role(
                RoleArn="{0}".format(aws_settings['role_name']),
                RoleSessionName='{0}'.format(aws_settings['role_session'])
            )
            # can be used ay name, but need to add restriction for the name!
            ecr = session.client(aws_access_key_id=assumed_role_object['Credentials']['AccessKeyId'],
                                 aws_secret_access_key=assumed_role_object['Credentials']['SecretAccessKey'],
                                 aws_session_token=assumed_role_object['Credentials']['SessionToken'],
                                 service_name=aws_settings['client'],
                                 region_name=aws_settings['region'],
                                 config=Config(retries={'max_attempts': 3})
                                 )

            return ecr
        except Exception as err:
            print("Failed to create a boto3 client connection to ecr:\n", str(err))
            logger.error('ERROR: Failed to create a boto3 client connection to ecr')
            return False
    else:
        print('Please use/set [--profile-name] or [--role-name] with [--role-session]')
        return False


def get_ecr_repos(aws_settings):
    ecr = ecr_connector(aws_settings)

    if ecr:
        try:
            repos = ecr.describe_repositories()
            print(repos)

            print("The repos:\n {}!".format(repos))
        except botocore.exceptions.ClientError as err:
            error_code = str(err)
            logger.error('ERROR: {0}. Forbidden Access!'.format(error_code))
    else:
        exit(-1)

    return get_ecr_repos


def get_ecr_repo(aws_settings, ecr_repo):
    ecr_repo_status = False

    ecr = ecr_connector(aws_settings)

    if ecr:
        try:
            repo = ecr.describe_repositories(repositoryNames=[ecr_repo])
            # print("A repo {} is already exists!".format(ecr_repo))
            ecr_repo_status = repo
            return ecr_repo_status
        except botocore.exceptions.ClientError as err:
            error_code = str(err)
            logger.error('ERROR: {0}. Forbidden Access!'.format(error_code))
            ecr_repo_status = False
            return ecr_repo_status
    else:
        exit(-1)

    return ecr_repo_status


def get_authorization_token(aws_settings, ecr_repo):
    global auth_token

    ecr = ecr_connector(aws_settings)

    ecr_repo = get_ecr_repo(aws_settings, ecr_repo)
    ecr_repo_id = ecr_repo['repositories'][0]['registryId']
    if ecr:
        response = ecr.get_authorization_token(registryIds=[ecr_repo_id])
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            auth_token = response['authorizationData'][0]['authorizationToken']
            # print("Authorization token: ", auth_token)
        elif response['ResponseMetadata']['HTTPStatusCode'] == 401:
            print("You're not authorized")
            exit(1)
    else:
        exit(-1)

    return auth_token


def http_request(method='GET', url='', h=None, retries=False, timeout=30):
    if h is None:
        h = {}
    http = urllib3.PoolManager()

    response = http.request(method=method,
                            url=url,
                            headers=h,
                            retries=retries,
                            timeout=timeout)
    if response.status == 200:
        # print("response: ", response.data.decode('utf-8'))
        logger.info('INFO: Successfully.....')
        return response
    elif response.status == 307:
        # logger.error('HTTP 307 Temporary Redirect redirect status response')
        return response
    elif response.status == 401:
        logger.error('ERROR: Please authorize, the issue: \n\t {}'.format(response.data.decode('utf-8')))
        return response
    elif response.status == 404:
        logger.error('ERROR: 404 page not found')
        return response
    else:
        logger.error('FAILURE: Got an error: \n\t {}'.format(response.data.decode('utf-8')))

        return response


def urllib_request_urlopen(url):
    response = urllib.request.urlopen(url).read()

    return response


def downloading_layer(cache_dir=CACHE_DIR, layer_url=None, out_path='/', h=None):
    """
    Get a layer in a compressed format, and saves it locally (unzipped).
    The tar name is expected to contain a hash, thus to be cacheable.
    """

    if h is None:
        h = {}

    cache_name = cache_dir + layer_url.split("/")[6].replace(':', '_')
    repo_name = layer_url.split("/")[4]

    response_headers = {}
    if not os.path.exists(cache_name):
        response = http_request(method='GET', url=layer_url, h=h, retries=False, timeout=30)
        for key, val in response.headers.iteritems():
            d = {key: val}
            response_headers.update(d)

        layer_location = response_headers['Location']
        layer_location_data = urllib_request_urlopen(layer_location)

        with open(cache_name, mode='wb') as localfile:
            localfile.write(layer_location_data)
            shutil.move(cache_name, cache_name)

    os.makedirs(out_path[:out_path.rfind("/")], exist_ok=True)
    shutil.copyfile(cache_name, out_path)

    return downloading_layer


def ecr_pull(aws_settings, cname_url, ecr_repo, ecr_tag="latest", h=None):
    if h is None:
        h = {}

    ecr = ecr_connector(aws_settings)

    if ecr:
        try:
            manifests_url = cname_url + '/v2/{0}/manifests/{1}'.format(ecr_repo, ecr_tag)
            response = http_request('GET', manifests_url, h)
            web_manifest = json.loads(response.data.decode('utf-8'))
            config_digest = web_manifest['config']['digest']

            # ------------------------------------------------------------------------
            config = cname_url + '/v2/{0}/blobs/{1}'.format(ecr_repo, config_digest)
            response = http_request('GET', config, h)

            response_headers = {}
            for key, val in response.headers.iteritems():
                d = {key: val}
                response_headers.update(d)

            config_location = response_headers['Location']
            config_location_file = urllib_request_urlopen(config_location).decode('utf-8')

            config_filename = config_digest.split(':')[1] + '.json'
            with open(temp_dir + '/' + config_filename, 'w') as outfile:
                json.dump(json.loads(config_location_file), outfile)

            # ------------------------------------------------------------------------
            layer_path_l = []
            for layer in web_manifest['layers']:
                layer_url = cname_url + '/v2/{0}/blobs/{1}'.format(ecr_repo, layer['digest'])
                path = layer['digest'].split(':')[-1] + "/layer.tar"
                out_path = temp_dir + '/' + path

                downloading_layer(cache_dir=CACHE_DIR, layer_url=layer_url, out_path=out_path, h=h)
                layer_path_l.append(path)

            manifest = [{"Config": config_filename, "RepoTags": [], "Layers": layer_path_l}]
            print("config_filename: ", config_filename)
            print("manifest: ", manifest)
            with open(temp_dir + '/' + 'manifest.json', 'w') as outfile:
                json.dump(manifest, outfile)

            with tarfile.open(ecr_tag, "w") as tar_out:
                os.chdir(temp_dir)
                tar_out.add(".")

        except Exception as e:
            logger.error('ERROR: {0}'.format(str(e)))
            print(e)
            exit(1)

    else:
        print("Could not get connect to AWS ECR or get needed repository")
        exit(-1)

    return ecr_pull


def ecr_push():
    print("TBD")

    return ecr_push


def ec2_handler(aws_settings, ecr_repo):
    ecr = ec2_connector(aws_settings)

    # TBD

    return ec2_handler


if __name__ == '__main__':
    start__time = time.time()
    parser = argparse.ArgumentParser(prog='python3 script_name.py -h',
                                     usage='python3 script_name.py {ARGS}',
                                     add_help=True,
                                     prefix_chars='--/',
                                     epilog='''created by Vitalii Natarov'''
                                     )
    parser.add_argument('--version', action='version', version='v0.2.0')
    parser.add_argument('--bclient', dest='boto3_client', help='Set boto3 client', default='ecr')
    parser.add_argument('--region', dest='region', help='Set AWS region for boto3', default='us-east-1')
    parser.add_argument('--pname', '--profile', dest='profile_name', help='Set profile name of AWS',
                        default=None)
    parser.add_argument('--rname', '--role-name', dest='role_name', help='Set role ARN name',
                        default=None)
    parser.add_argument('--rsession', '--role-session', dest='role_session', help='Set role session name',
                        default=None)
    parser.add_argument('--registry-url', '--url', dest='registry_url', help='Set Registry URL',
                        default="https://docker-ecr.internal.vnatarov.io")
    parser.add_argument('--ecr-url', dest='ecr_url', help='Set URL from ECR registry',
                        default="XXXXXXXXXXXXX.dkr.ecr.us-east-1.amazonaws.com")
    parser.add_argument('--ecr-repo', '-repo', dest='ecr_repo', help='Set ECR repo name',
                        default="repo-name")
    parser.add_argument('--ecr-repo-tag', '-repo-tag', dest='ecr_repo_tag', help='Set ECR repo tag',
                        default="latest")
    parser.add_argument('--ec2', dest='aws_ec2', help='Set ec2 usage', default='False')

    results = parser.parse_args()

    boto3_client = results.boto3_client
    region = results.region
    profile_name = results.profile_name
    role_name = results.role_name
    role_session = results.role_session

    registry_url = results.registry_url
    ecr_url_host = results.ecr_url
    ecr_repo_name = results.ecr_repo
    ecr_repo_tag = results.ecr_repo_tag

    aws_ec2 = results.aws_ec2

    try:
        temp_dir = mkdtemp()

        if aws_ec2 == 'True':
            print("AWS EC2!")
            aws_auth = {
                "client": boto3_client,
                "region": region,
                "ec2_host": 'True'
            }

            ec2_handler(aws_auth)
        else:
            print("Local Usage!")
            aws_auth = {
                "client": boto3_client,
                "region": region,
                "profile_name": profile_name,
                "role_name": role_name,
                "role_session": role_session
            }

            authorization_token = get_authorization_token(aws_auth, ecr_repo_name)
            headers = {
                'Host': str(ecr_url_host),
                'Accept': 'text/plain',
                'X-Forwarded-Proto': 'https',
                'X-Forwarded-For': '127.0.0.1',
                'X-Real-IP': '66.66.66.66',
                'Authorization': 'Basic {}'.format(str(authorization_token))
            }
            ecr_pull(aws_auth, registry_url, ecr_repo_name, ecr_repo_tag, headers)
    finally:
        shutil.rmtree(temp_dir)

    end__time = round(time.time() - start__time, 2)
    print("--- %s seconds ---" % end__time)
