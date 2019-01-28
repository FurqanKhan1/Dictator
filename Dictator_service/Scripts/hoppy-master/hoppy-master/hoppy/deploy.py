from hoppy.api import HoptoadResource

class Deploy(HoptoadResource):
    def __init__(self, use_ssl=False):
        from hoppy import api_key
        self.api_key = api_key
        super(Deploy, self).__init__(use_ssl)

    def check_configuration(self):
        if not self.api_key:
            raise HoptoadError('API Key cannot be blank')

    def request(self, *args, **kwargs):
        response = super(Deploy, self).request(
                api_key=self.api_key, *args, **kwargs)
        return response

    def base_uri(self, use_ssl=False):
        base = 'http://hoptoadapp.com/deploys.txt'
        base = base.replace('http://', 'https://') if use_ssl else base
        return base

    def deploy(self, env, **kwargs):
        """ Optional parameters accepted by Hoptoad are:
        scm_revision
        scm_repository
        local_username
        """
        params = {}
        params['deploy[rails_env]'] = env
        for key, value in kwargs.iteritems():
            params['deploy[%s]' % key] = value
        return self.post(**params)
