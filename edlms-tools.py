#!/usr/bin/env python3

import requests
import json
import argparse
import logging
import ssl
import code
import getpass
import re
import itertools
import operator
import os
import time

HOST = 'https://edstem.com.au'

#props to http://stackoverflow.com/a/16090640
def natural_sort_key(s, _nsre=re.compile('([0-9]+)')):
    return [int(text) if text.isdigit() else text.lower() for text in re.split(_nsre, s)]
# props to https://gist.github.com/brantfaircloth/1443543
class FullPaths(argparse.Action):
    """Expand user- and relative-paths"""
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, os.path.abspath(os.path.expanduser(values)))

def is_dir(dirname):
    """Checks if a path is an actual directory"""
    if not os.path.isdir(dirname):
        msg = "{0} is not a directory".format(dirname)
        raise argparse.ArgumentTypeError(msg)
    else:
        return dirname

class EdlmsException(Exception):
    pass

class EdlmsUser(object):
    s = requests.Session()

    def __init__(self, **kwargs):
        if kwargs['token'] is not None:
            self.login_from_token(kwargs['token'])
        elif kwargs['username'] is not None and kwargs['password'] is not None:
            self.login(kwargs['username'], kwargs['password'])

    def login_from_token(self, token):
        self.s.headers.update({'x-token': token})
        r = self.s.get(HOST + '/api/user')
        if r.status_code == 200:
            self.user = r.json()['user']
            self.courses = r.json()['courses']
            self.course_hash = {str(x['id']) : x for x in self.courses}
        else:
            raise EdlmsException(r.text)

    def login(self, login, password):
        credentials = {'login': login, 'password': password}
        r = self.s.post(HOST + '/api/token', json=credentials)
        if r.status_code != 200:
            raise EdlmsException(r.text)
        self.login_from_token(r.json()['token'])

    def resources(self, course_id=None):
        if course_id is None:
            l = [self.resources(i) for i in self.course_hash.keys()]
            return [item for sublist in l for item in sublist]

        r = self.s.get(HOST + '/api/courses/{}/resources'.format(course_id))
        if r.status_code != 200:
            raise EdlmsException(r.text)
        res = r.json()['resources']

        # for x in res:
        #     x['_date'] = max(x['created_at'], x['updated_at'])

        return res

    def download_resource(self, rid, filename="{original_name:}"):
        r = self.s.post(HOST + '/api/resources/{}/download'.format(rid), stream=True, data={'_token': self.s.headers['x-token']})
        if r.status_code != 200:
            raise EdlmsException(r.text)
        resources = self.resources()
        resource = next((item for item in resources if str(item['id']) == str(rid)))
        print("{session:} {category:}  {name:}".format(**resource))
        resource['original_name'] = re.search(r'filename="(.*)";', r.headers['Content-Disposition']).group(1)
        filename = filename.format(**resource)

        with open(filename, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
                    f.flush()
            return filename

    def assignments(self, course_id):
        r = self.s.get(HOST + '/api/courses/{}/assignments'.format(course_id))
        if r.status_code != 200:
            raise EdlmsException(r.text)
        return r.json()['assignments']
    
    def challenge(self, course_id):
        r = self.s.get(HOST + '/api/challenges/{}'.format(course_id))
        if r.status_code != 200:
            raise EdlmsException(r.text)
        return r.json()['challenge']

    def challenge_submissions(self, course_id):
        r = self.s.get(HOST + '/api/user/challenges/{}/submissions'.format(course_id))
        if r.status_code != 200:
            raise EdlmsException(r.text)
        return r.json()['submissions']
    
    def challenge_submit(self, course_id, files):
        submission = {'submission': {'files': files} }
        r = self.s.post(HOST + '/api/challenges/{}/mark'.format(course_id), json=submission)
        if r.status_code != 201:
            raise EdlmsException(r.text)
        return r.json()['submission']

    @property
    def token(self):
        return self.s.headers['X-Token']

def shell(args):
    ed = EdlmsUser(**vars(args))
    code.interact(local=locals())

def token(args):
    ed = EdlmsUser(**vars(args))
    print(ed.token)

def courses(args):
    ed = EdlmsUser(**vars(args))
    sorted(ed.courses, key=lambda x: (x['year'], x['session'], x['code']), reverse=True)
    for course in ed.courses:
        print("{id:<3}  {code:4} {name:} ({year:}-{session:})".format(**course))


def main_resources(args):
    ed = EdlmsUser(**vars(args))

    if args.download:
        for resource in args.download:
            print("Saved as {}".format(ed.download_resource(resource)))
        return

    if len(args.list) == 0 :
        args.list = [str(x['id']) for x in ed.courses]
    print(args.list)

    for c in args.list:
        print(ed.course_hash[c]['name'])
        sg = ed.resources(c)

        # seems like sessions arent used anymore
        for r in sg:
            print("\t{id:<4} {category:} ({session:}) {name:}".format(**r))

def assignments(args):
    ed = EdlmsUser(**vars(args))
    if args.list is not None:
        for i in ed.assignments(args.list):
            print("{challenge_id:3}  {title:}".format(**i))
    elif args.show is not None:
        challenge = ed.challenge(args.show)
        print("{title:}\n{body_raw:}\n\n".format(**challenge))
        print("Files: {}".format(", ".join([x['name'] for x in challenge['scaffold']['files']])))
        print("Scripts:\n" + "\n".join(["{} \t {}".format(k, "&& ".join(v)) for k, v in challenge['scripts'].items()]))
    elif args.latest_submission is not None:
        submission = ed.challenge_submissions(args.latest_submission)[0]
 
        print("Submission {id:} {created_at:}\t Passed: {result[passed]:} {result[feedback]:}".format(**submission))
        print("Build Output: \n", submission['result']['build_output'])
        if submission['result']['passed'] == False and submission['result']['testcases'] is not None:
            for case in submission['result']['testcases']:
                if case['passed'] != True:
                    print("----------------------------------")
                    print("{name:} -- {feedback:}\n{command:}\nInput:\n{input:}\n\nOutput:\n{observed:}\n\nExpected:\n{expected:}\n\n{memcheck:}".format(**case))
                    print("----------------------------------")

    elif args.submit is not None:
        smission_files = list()

        for name in [i['name'] for i in ed.challenge(args.submit)['scaffold']['files']]:
            with open(os.path.join(args.path, name), 'r') as f:
                smission_files.append({'name': name, 'content': f.read()})
        submitted = ed.challenge_submit(args.submit, smission_files)
        print("Submitted: {id:}".format(**submitted))

        time.sleep(2)
        result = next((item for item in ed.challenge_submissions(args.submit) if str(item['id']) == str(submitted['id'])))
        while result['status'] != 'completed':
            print(result['status'])
            time.sleep(5)
            result = next((item for item in ed.challenge_submissions(args.submit) if str(item['id']) == str(submitted['id'])))

        args.latest_submission = args.submit
        assignments(args)

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

    p_shell = subparsers.add_parser("token", help="Print token")
    p_shell.set_defaults(func=token)
    
    s_shell = subparsers.add_parser("resources", help="Get resources")
    s_group = s_shell.add_mutually_exclusive_group()
    s_group.add_argument('-l', '--list', help="List resources for a course", nargs='*')
    s_group.add_argument('-d', '--download', nargs="+", help="Download resource with id")
    s_shell.set_defaults(func=main_resources)
    
    a_shell = subparsers.add_parser("assignments", help="View assignments")
    a_group = a_shell.add_mutually_exclusive_group()
    a_group.add_argument('-l', '--list', help="List assignments for a course")
    a_group.add_argument('--show', help="Show assignment with id")
    a_group.add_argument('--latest-submission', help="Show details of latest submission")
    sub_group = a_group.add_argument_group()
    sub_group.add_argument('--submit', help="Are you crazy? Assignment to submit")
    sub_group.add_argument('--path',  action=FullPaths, type=is_dir, default=os.getcwd())
    
    a_shell.set_defaults(func=assignments)

    args = parser.parse_args()

    netrc = requests.utils.get_netrc_auth(HOST)

    if args.username is None and args.password is None and args.token is None and netrc is None:
        args.username = input("Username: ")
        args.password = getpass.getpass("Password: ")
    elif args.username and args.password is None:
        args.password = getpass.getpass("Password: ")
    elif netrc:
        args.username, args.password = netrc
    elif args.username is None and args.password:
        parser.error("if you're going to give me a password, you'll need to give me a username")

    args.func(args)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
