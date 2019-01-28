from hoppy.api import HoptoadResource

class HoptoadNotice(HoptoadResource):
    def find(self, notice_id, error_id):
        return self.get(self._notice_path(notice_id, error_id))
    
    @staticmethod
    def _notice_path(notice_id, error_id):
        return 'errors/%(error_id)d/notices/%(notice_id)d.xml' % locals()

    def request(self, *args, **kwargs):
        response = super(HoptoadNotice, self).request(*args, **kwargs)
        return HoptoadNotice(data=response)
