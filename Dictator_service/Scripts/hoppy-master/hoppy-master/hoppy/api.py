from restkit import Resource
from xml.dom.minidom import parseString

from hoppy.util.xmldict import xml_to_dict

class HoptoadApiError(Exception):
    pass

class HoptoadResource(Resource):
    def __init__(self, use_ssl=False, data=None):
        from hoppy import account, auth_token
        self.auth_token = auth_token
        self.account = account
        self.host = self.base_uri(use_ssl)
        super(HoptoadResource, self).__init__(self.host, follow_redirect=True)
        if data:
            self.from_xml(data)

    def base_uri(self, use_ssl=False):
        base = 'http://%s.hoptoadapp.com' % self.account
        base = base.replace('http://', 'https://') if use_ssl else base
        return base

    def check_configuration(self):
        if not self.auth_token:
            raise HoptoadApiError('auth token cannot be blank')
        if not self.account:
            raise HoptoadApiError('account cannot be blank')

    def request(self, *args, **kwargs):
        self.check_configuration()
        response = super(HoptoadResource, self).request(
                auth_token=self.auth_token, *args, **kwargs)
        return response.body_string()

    def from_xml(self, data):
        root = parseString(data)
        self.from_dict(xml_to_dict(root))

    def from_dict(self, data):
        for key, value in data.iteritems():
            safe_key = key.replace('-', '_')
            setattr(self, safe_key, value)
