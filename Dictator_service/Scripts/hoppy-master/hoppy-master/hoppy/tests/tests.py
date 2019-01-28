from nose.tools import raises
import unittest
import mockito

from hoppy.tests.mock import mock_hoptoad
from hoppy.error import HoptoadError
import hoppy

class HoptoadErrorTests(unittest.TestCase):
    def setUp(self):
        super(HoptoadErrorTests, self).setUp()
        mock_hoptoad()
        self.set_credentials()

    def tearDown(self):
        super(HoptoadErrorTests, self).tearDown()
        mockito.unstub()

    def set_credentials(self):
        hoppy.auth_token = '1234556asdfghjkl'
        hoppy.account = 'foobar'
        hoppy.api_key = 'zxcvasdfgjk1234'

    def unset_credentials(self):
        hoppy.auth_token = hoppy.account = hoppy.api_key = None

    @raises(hoppy.api.HoptoadApiError)
    def test_no_auth_token(self):
        mockito.unstub()
        hoppy.auth_token = None
        e = hoppy.error.HoptoadError().find(203543)

    @raises(hoppy.api.HoptoadApiError)
    def test_no_account(self):
        mockito.unstub()
        hoppy.account = None
        e = hoppy.error.HoptoadError().find(203543)

    def test_find(self):
        e = hoppy.error.HoptoadError().find(203543)
