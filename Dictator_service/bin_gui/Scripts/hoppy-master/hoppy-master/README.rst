hoppy
==============

.. _Hoptoad: http://hoptoadapp.com/
.. _Python: http://python.org/
.. _restkit: http://benoitc.github.com/restkit/

hoppy is a Python library for accessing the Hoptoad_ API.


Requirements
------------

hoppy requires:

* Python_ 2.6
* restkit_ >= 2.1.1
* A Hoptoad_ account


Development Requirements
-------------------------

.. _nosetests: http://somethingaboutorange.com/mrl/projects/nose/0.11.2/
.. _mockito-python: http://code.google.com/p/mockito-python/

The hoppy test suite requires:

* nosetests_ >= 0.11.2
* mockito-python_ >= 0.6.10


Installation
------------

hoppy is available on PyPi, and the recommended method of installation is pip::
    
    pip install hoppy


Usage
-----

Use hoppy to notify Hoptoad of an app deploy::

    import hoppy.deploy
    hoppy.api_key = '<project API key>'
    hoppy.deploy.Deploy().deploy(env='PRODUCTION', scm_revision='1a6a445',
            scm_repository='git@github.com:peplin/hoppy.git')

Use hoppy to retreive a specific error::

    import hoppy.error
    hoppy.account = '<your account name>'
    hoppy.auth_token = '<your personal API auth token>'
    print hoppy.error.Error().find(2035230).environment
