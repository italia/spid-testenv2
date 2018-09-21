# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json

import exrex
from faker import Faker

from testenv import config

FAKER = Faker('it_IT')

try:
    FileNotFoundError
except NameError:
    # py2
    FileNotFoundError = IOError


class AbstractUserManager(object):
    """
    Base User manager class to handling user objects
    """

    def __init__(self, conf=None):
        self._config = conf or config.params

    def get(self, uid, pwd, sp_id):
        raise NotImplementedError

    def add(self, uid, pwd, sp_id, extra={}):
        raise NotImplementedError


class JsonUserManager(AbstractUserManager):
    """
    User manager class to handling json user objects
    """
    @property
    def _filename(self):
        return self._config.users_file_path

    def _load(self):
        try:
            with open(self._filename, 'r') as fp:
                self.users = json.loads(fp.read())
        except FileNotFoundError:
            self.users = {}
            for idx, _ in enumerate(range(10)):
                _is_even = (idx % 2 == 0)
                name = FAKER.first_name_male() if _is_even \
                    else FAKER.first_name_female()
                lastname = FAKER.last_name_male() if _is_even \
                    else FAKER.last_name_female()
                fiscal_number = exrex.getone(
                    '[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]'
                )
                self.users[FAKER.user_name() if idx > 0 else 'test'] = {
                    'attrs': {
                        'spidCode': FAKER.uuid4(),
                        'name': name,
                        'familyName': lastname,
                        'gender': 'M' if _is_even else 'F',
                        'dateOfBirth': FAKER.date(),
                        'companyName': FAKER.company(),
                        'registeredOffice': FAKER.address(),
                        'fiscalNumber': 'TINIT-{}'.format(fiscal_number),
                        'email': FAKER.email()
                    },
                    'pwd': 'test',
                    'sp': None
                }
            self._save()

    def _save(self):
        with open(self._filename, 'w') as fp:
            json.dump(self.users, fp, indent=4)

    def __init__(self, *args, **kwargs):
        super(JsonUserManager, self).__init__(*args, **kwargs)
        self._load()

    def get(self, uid, pwd, sp_id):
        for user, _attrs in self.users.items():
            if pwd == _attrs['pwd'] and user == uid:
                if _attrs['sp'] is not None and _attrs['sp'] != sp_id:
                    return None, None
                return user, self.users[user]
        return None, None

    def add(self, uid, pwd, sp_id=None, extra=None):
        if uid not in self.users:
            self.users[uid] = {
                'pwd': pwd,
                'sp': sp_id,
                'attrs': extra
            }
        self._save()

    def all(self):
        return self.users


class AutoLoginJsonUserManager(JsonUserManager):
    """
    User manager class that bypass the password check
    """

    def __init__(self, *args, **kwargs):
        super(AutoLoginJsonUserManager, self).__init__(*args, **kwargs)

    def get(self, uid, pwd, sp_id):
        for user, _attrs in self.users.items():
            if user == uid:
                if _attrs['sp'] is not None and _attrs['sp'] != sp_id:
                    return None, None
                return user, self.users[user]
        return None, None
