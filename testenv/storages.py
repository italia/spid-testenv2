# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json

import exrex
from faker import Faker
from flask_admin.contrib.sqla import ModelView
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.dialects.postgresql import JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from testenv import config, spmetadata

FAKER = Faker('it_IT')

Base = declarative_base()

try:
    FileNotFoundError
except NameError:
    # py2
    FileNotFoundError = IOError


class AbstractDBManager(object):
    TABLE = None

    def __init__(self, *args, **kwargs):
        self.engine = create_engine(self._config.db_url, echo=True)
        self.session_maker = sessionmaker(bind=self.engine)
        self.session = self.session_maker()
        Base.metadata.create_all(self.engine, tables=[self.TABLE.__table__])


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

    def all(self):
        raise NotImplementedError

    def _generate_fake_users(self):
        _users = {}
        for idx, _ in enumerate(range(10)):
            _is_even = (idx % 2 == 0)
            name = FAKER.first_name_male() if _is_even \
                else FAKER.first_name_female()
            lastname = FAKER.last_name_male() if _is_even \
                else FAKER.last_name_female()
            fiscal_number = exrex.getone(
                r'[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]'
            )
            _users[FAKER.user_name() if idx > 0 else 'test'] = {
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
        return _users


class FileUserManager(AbstractUserManager):
    """
    User manager class to handling json user objects
    """

    def __init__(self, *args, **kwargs):
        super(FileUserManager, self).__init__(*args, **kwargs)
        self._load()

    @property
    def _filename(self):
        return self._config.users_file_path

    def _load(self):
        try:
            with open(self._filename, 'r') as fp:
                self.users = json.loads(fp.read())
        except FileNotFoundError:
            self.users = self._generate_fake_users()
            self._save()

    def _save(self):
        with open(self._filename, 'w') as fp:
            json.dump(self.users, fp, indent=4)

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

    def register_admin(self, admin):
        pass


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String)
    password = Column(String)
    sp = Column(String)
    attrs = Column(JSON)


class SpMetadata(Base):
    __tablename__ = 'spmetadata'
    entity_id = Column(String, primary_key=True)
    body = Column(String)


class DbUserManager(AbstractUserManager, AbstractDBManager):

    TABLE = User

    def __init__(self, *args, **kwargs):
        AbstractUserManager.__init__(self, *args, **kwargs)
        AbstractDBManager.__init__(self, *args, **kwargs)
        self._populate_if_empty()

    def _populate_if_empty(self):
        if self.session.query(User).count() == 0:
            _users = self._generate_fake_users()
            for username, info in _users.items():
                self.add(username, info.get('pwd'), info.get('sp'), info.get('attrs'))

    def add(self, uid, pwd, sp_id=None, extra=None):
        params = dict(
            username=uid,
            password=pwd,
            sp=sp_id,
            attrs=extra
        )
        instance = self.session.query(self.TABLE).filter_by(username=params.get('username')).first()
        if instance:
            return
        user = self.TABLE(
            **params
        )
        self.session.add(user)
        self.session.commit()

    def get(self, uid, pwd, sp_id):
        instance = self.session.query(self.TABLE).filter_by(username=uid).first()
        if instance:
            if pwd == instance.password and instance.username == uid:
                if instance.sp is not None and instance.sp != sp_id:
                    return None, None
                username = instance.username
                info = {
                    'pwd': instance.password,
                    'sp': instance.sp,
                    'attrs': instance.attrs
                }
                return username, info
        return None, None

    def all(self):
        return {
            user.username: {
                'sp': user.sp,
                'pwd': user.password,
                'attrs': user.attrs
            }
            for user in self.session.query(self.TABLE).all()
        }

    def register_admin(self, admin):
        admin.add_view(ModelView(self.TABLE, self.session))


class UserManager(object):

    type_mapping = {
        'file': FileUserManager,
        'postgres': DbUserManager
    }

    @classmethod
    def factory(cls, conf=None):
        _config = conf or config.params
        manager_cls = cls.type_mapping.get(_config.storage)
        if manager_cls is None:
            raise NotImplementedError
        return manager_cls(conf=_config)


class SpMetadataModelView(ModelView):
    form_columns = ('entity_id', 'body')
    excluded_list_columns = None

    def __init__(self, model, session,
                 name=None, category=None, endpoint=None, url=None, static_folder=None,
                 menu_class_name=None, menu_icon_type=None, menu_icon_value=None, manager=None):
        self._manager = manager
        super(SpMetadataModelView, self).__init__(model, session,
                                                  name=None, category=None, endpoint=None, url=None, static_folder=None,
                                                  menu_class_name=None, menu_icon_type=None, menu_icon_value=None)

    def after_model_change(self, form, model, is_created):
        loader = spmetadata.ServiceProviderMetadataDbLoader(
            model.entity_id, spmetadata.VALIDATORS, **{'manager': self._manager})
        metadata = spmetadata.ServiceProviderMetadata(loader)
        spmetadata.registry.register(metadata)


class SpMetadataManager(AbstractDBManager):

    TABLE = SpMetadata

    def __init__(self, conf=None):
        self._config = conf or config.params
        super(SpMetadataManager, self).__init__(conf)

    def add(self, entity_id, body):
        params = dict(
            entity_id=entity_id,
            body=body
        )
        instance = self.session.query(self.TABLE).filter_by(entity_id=params.get('entity_id')).first()
        if instance:
            return
        sp_metadata = self.TABLE(
            **params
        )
        self.session.add(sp_metadata)
        self.session.commit()

    def get(self, entity_id):
        instance = self.session.query(self.TABLE).filter_by(entity_id=entity_id).first()
        if instance:
            return instance.body
        return None

    def all(self):
        res = {}
        for metadata in self.session.query(self.TABLE).all():
            res[metadata.entity_id] = metadata.body
        return res

    @property
    def ids(self):
        return self.session.query(self.TABLE).with_entities(self.TABLE.entity_id)

    def register_admin(self, admin):
        admin.add_view(SpMetadataModelView(self.TABLE, self.session, self))
