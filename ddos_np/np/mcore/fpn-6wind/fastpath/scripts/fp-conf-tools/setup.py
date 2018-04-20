#!/usr/bin/env python
# Copyright 2014, 6WIND S.A.

from distutils.core import setup

setup(
    name='fp-conf-tools',
    version='DEVSUITE_2014_Q4',
    author='6WIND',
    author_email='info@6wind.com',
    description='Generate and analyze fast-path.env configuration file',
    long_description=open('README').read(),
    url='http://www.6wind.com/',
    license='Proprietary',

    packages=['fp_conf_tools'],
    scripts=(
        'fp-conf-tool',
    ),
)
