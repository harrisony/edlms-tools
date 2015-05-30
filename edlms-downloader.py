#!/usr/bin/env python3

import requests
import json
import argparse
import logging
import ssl
import code
import getpass

import requests_cache
requests_cache.install_cache('dev_cache')

class TlsAdapter(requests.adapters.HTTPAdapter):
    """"Transport adapter" that only connects over TLS."""

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = requests.packages.urllib3.poolmanager.PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=ssl.PROTOCOL_TLSv1_2)
class EdlmsException(Exception):
    pass

class EdlmsUser:
    def __init__(self, **kwargs):
        self._session = requests.Session()
        self._session.mount('https://', TlsAdapter())
        self._session.headers['content-type'] = 'application/json;charset=utf-8'
        if kwargs['token'] is not None:
            self.login_from_token(kwargs['token'])
        elif kwargs['username'] is not None and kwargs['password'] is not None:
            self.login(kwargs['username'], kwargs['password'])

    def login_from_token(self, token):
        self._session.headers['X-Token'] = token
        r = self._session.get('https://edlms.com/api/user', verify=False)
        if r.status_code == 200:
            self.user = r.json()['user']
            self.courses = r.json()['courses']
        else:
            raise EdlmsException(r.text)

    def login(self, login, password):
        credentials = {'login': login, 'password': password}
        r = self._session.post('https://edlms.com/api/token', data=json.dumps(credentials), verify=False)
        if r.status_code == 200:
            self._session.headers['X-Token'] = r.json()['token']
            r = self._session.get('https://edlms.com/api/user', verify=False)
            self.user = r.json()['user']
            self.courses = r.json()['courses']
        else:
            raise EdlmsException(r.text)

def shell(args):
    ed = EdlmsUser(**vars(args))
    code.interact(local=locals())

def courses(args):
    ed = EdlmsUser(**vars(args))
    sorted(ed.courses, key=lambda x: (x['year'], x['session'], x['code']), reverse=True)
    for course in ed.courses:
        print("{:<3}  {:4} {} ({}-{})".format(course['id'], course['code'], course['title'], course['year'], course['session']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='edlms-downloader')
    parser.add_argument("-u", "--username", default=None)

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-p", "--password", default=None)
    group.add_argument("-t", "--token", default=None)

    subparsers = parser.add_subparsers(dest="command", help="commands")
    subparsers.required = True

    p_courses = subparsers.add_parser("courses", help="View courses")
    p_courses.set_defaults(func=courses)

    p_shell = subparsers.add_parser("shell", help="Drop to a shell")
    p_shell.set_defaults(func=shell)

    args = parser.parse_args()

    if args.username is None and args.password is None:
        args.username = input("Username: ")
        args.password = getpass.getpass("Password: ")
    elif args.username and args.password is None:
        args.password = getpass.getpass("Password: ")
    elif args.username is None and args.password:
        parser.error("if you're going to give me a password, you'll need to give me a username")

    args.func(args)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
