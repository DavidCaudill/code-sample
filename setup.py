import re
from setuptools import setup

with open('requirements.txt') as handle:
    contents = handle.read().split('\n')

requires = []
links = []
regex = '.*#egg=(?P<package>[A-Za-z]+).*'
for content in contents:
    match = re.match(regex, content)
    if match:
        requires.append(match.group('package'))
        links.append(content.replace('-e ', ''))
    else:
        requires.append(content)

print('requires: {}'.format(requires))
print('links: {}'.format(links))

setup(
    name='HPaccess',
    version='1.0.0',
    author='David',
    author_email='redacted',
    package_dir={
        '': 'src/main/python'
    },
    packages=[
        'HPaccess'
    ],
    url='https://redacted',
    description='A Python utility to manage the admin account password and LDAP membership of the OA and the VCM',
    install_requires=requires,
    dependency_links=links
)
