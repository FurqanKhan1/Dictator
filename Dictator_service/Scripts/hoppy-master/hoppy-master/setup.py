import os
from setuptools import setup, find_packages

ROOT_PATH = os.path.abspath(os.path.dirname(__file__))

execfile(os.path.join(ROOT_PATH, 'hoppy/version.py'))
long_description = open(os.path.join(ROOT_PATH, 'README.rst')).read()

classifiers = [
    'Development Status :: 4 - Beta',
    'License :: OSI Approved :: MIT License',
    'Operating System :: OS Independent',
    'Programming Language :: Python',
    'Topic :: Software Development',
]

setup(name='hoppy',
      version=__version__,
      description='Hoptoad API Library',
      long_description=long_description,
      author='Christopher Peplin',
      author_email='peplin@bueda.com',
      license='MIT',
      classifiers=classifiers,
      url='http://github.com/peplin/hoppy',
      packages=find_packages(),
      install_requires=['restkit>=2.1.1']
)
