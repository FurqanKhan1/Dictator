from mockito import when
import mockito
import restkit
import os

from hoppy.error import HoptoadError

fake_error = open(os.path.join(os.path.abspath(os.path.dirname(__file__)),
        'data', '2035230.xml')).read()

def mock_hoptoad():
    when(HoptoadError).request(
            mockito.any(), mockito.any()).thenReturn(HoptoadError(fake_error))
