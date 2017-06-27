#!/usr/bin/env python
# -*- coding: utf-8 -*-#
#
#
# Copyright (C) 2017, S3IT, University of Zurich. All rights reserved.
#
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

__docformat__ = 'reStructuredText'
__author__ = ', '.join([
    'Antonio Messina <antonio.s.messina@gmail.com>',
    'Riccardo Murri <riccardo.murri@gmail.com>',
])


def to_bib(num):
    """Convert num to a reasonable power of 2.

    >>> to_bib(100)
    (100.0, 'bytes')
    >>> to_bib(1024)
    (1.0, 'KiB')
    >>> t,u = to_bib(2**20+100)
    >>> "%.2f" % t
    '1.00'
    >>> u
    'MiB'
    >>> to_bib(5*2**50)
    (5.0, 'PiB')
    >>> to_bib(-1*2**30)
    (-1.0, 'GiB')
    """
    absnum = abs(num)
    sign = -1 if num < 0 else 1
    for thr, unit in (
            (2**60, 'EiB'),
            (2**50, 'PiB'),
            (2**40, 'TiB'),
            (2**30, 'GiB'),
            (2**20, 'MiB'),
            (2**10, 'KiB'),
    ):
        if absnum >= thr:
            return (sign*float(absnum)/thr, unit)
    return (float(num), 'bytes')


def get_project_id(response):
    """
    Return the project UUID from a Neutron API response dictionary.

    Depending on server and client version and/or configuration, the project
    (formerly called: "tenant") ID is stored in attributes ``project_id`` or
    ``tenant_id``. Try both (in this order) and raise a ``KeyError`` if none is
    present in the passed dictionary.
    """
    if 'project_id' in response:
        return response['project_id']
    elif 'tenant_id' in response:
        return response['tenant_id']
    else:
        raise KeyError(
            "No `project_id` nor `tenant_id` in response `{0}`"
            .format(response))


def find_security_group_by_name(client, project_id, name):
    """
    Return dict describing the named Neutron security group.

    :raise KeyError: if no security group with the given name exists in the project.
    :raise RuntimeError: if multiple security groups match.
    """
    secgroups = find_security_groups(client, project_id, name=name)
    if not secgroups:
        raise KeyError("No security group by the name `{0}`".format(name))
    if len(secgroups) > 1:
        raise RuntimeError(
            "Multiple matches for security group '{0}': {1}"
            .format(name, [sg['id'] for sg in secgroups]))
    return secgroups[0]


def _filter_neutron_list_results(fn, objname, id_filter_fn=(lambda obj: True), **clauses):
    """
    Return matching items from a Neutron 'list' API call.

    :param fn: Neutron client ``list_*`` function to call.
    :param objname: Key identifying the root object in the JSON response.
    :param id_filter_fn: Pre-filter: clauses will be checked only for objects where this returns ``True``
    :param clauses: Any additional keyword argument will filter results by imposing that the specified key/value pair appears in the object.
    """
    response = fn()
    if objname not in response:
        raise RuntimeError(
            "Unexpected response from Neutron client's"
            " `{0}()` call: {1}".format(fn.__name__, response))
    objs = response[objname]
    if not objs:
        return []
    matching = [
        obj for obj in objs
        if id_filter_fn(obj)
        and all([obj[key] == value for key, value in clauses.iteritems()])
    ]
    return matching


def find_security_groups(client, project_id, **clauses):
    """
    Return security groups in the given project matching all the equality clauses.
    """
    def _target_project_id(obj):
        return get_project_id(obj) == project_id
    return _filter_neutron_list_results(
        client.list_security_groups, 'security_groups',
        _target_project_id, **clauses)


def find_security_group_rules(client, secgroup_id, **clauses):
    """
    Return rules in the given security group matching all the equality clauses.
    """
    def _target_project_id(obj):
        return obj['security_group_id'] == secgroup_id
    return _filter_neutron_list_results(
        client.list_security_group_rules, 'security_group_rules',
        _target_project_id, **clauses)


if __name__ == "__main__":
    import doctest
    doctest.testmod(name="utils",
                    optionflags=doctest.NORMALIZE_WHITESPACE)
