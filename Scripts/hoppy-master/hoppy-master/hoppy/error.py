from hoppy.api import HoptoadResource

class HoptoadError(HoptoadResource):
    def find(self, error_id):
        return self.get(self._error_path(error_id))

    @staticmethod
    def _error_path(error_id):
        return 'errors/%d.xml' % error_id

    def request(self, *args, **kwargs):
        response = super(HoptoadError, self).request(*args, **kwargs)
        return HoptoadError(data=response)

    def from_dict(self, data):
        super(HoptoadError, self).from_dict(data['group'])
