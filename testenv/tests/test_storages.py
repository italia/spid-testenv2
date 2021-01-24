# coding: utf-8
import re
import unittest

from codicefiscale import codicefiscale as fiscalcode

from testenv.storages import FileUserProvider

try:
    from unittest.mock import Mock, patch
except ImportError:
    from mock import Mock, patch


class UserProviderTestCase(unittest.TestCase):
    """Tests the abstract UserProvider"""

    # Mock FileUserProvider._save() to be sure to recreate new users every time.
    @patch("testenv.storages.FileUserProvider._save")
    def setUp(self, mock__save):
        config = Mock()
        config.users_file_path = '/dummy/users/file'

        self.provider = FileUserProvider(config)

    def test_valid_fake_users(self):
        """
        Generated users should have valid attributes according to
        https://www.agid.gov.it/sites/default/files/repository_files/regole_tecniche/tabella_attributi_idp_v1_0.pdf
        """

        for name, info in self.provider.all().items():
            attrs = info['attrs']

            user_fiscal_code = re.sub(r'^TINIT-', '', attrs['fiscalNumber'])
            self.assertTrue(
                fiscalcode.is_valid(user_fiscal_code),
                "{} is not a valid Italian fiscal code".format(user_fiscal_code)
            )
