#!/usr/bin/env python
# -*- coding: utf-8 -*-#
#
#
# Copyright (C) 2016, S3IT, University of Zurich. All rights reserved.
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
__author__ = 'Antonio Messina <antonio.s.messina@gmail.com>'

from flask import redirect, current_app as app, session, Blueprint, url_for, request, render_template, abort

from functools import wraps

from scadmin.exceptions import AuthenticationRequired
from scadmin.forms import LoginForm
from scadmin import config

from keystoneauth1.identity import v3
from keystoneauth1 import session as ksession
from keystoneauth1.exceptions.http import Unauthorized, Forbidden
from keystoneclient.v3 import client as keystone_client


login_bp = Blueprint('auth', __name__)

def fill_session_data(sess):
    auth = session.get('auth', {})
    auth['token'] = sess.get_token()
    auth['user_id'] = sess.get_user_id()
    auth['project_id'] = sess.auth.project_id
    auth['project_domain_id'] = sess.auth.project_domain_id
    keystone = keystone_client.Client(session=sess)
    try:
        project = keystone.projects.get(sess.auth.project_id)
    except Forbidden:
        projects = keystone.projects.list(user=sess.get_user_id())
        for project in projects:
            if project.id == sess.auth.project_id:
                break
    auth['project_name'] = project.name
    auth['roles'] = sess.auth.auth_ref.role_names
    auth['regular_member'] = False if set(('admin', 'project_admin', 'usermanager')).intersection(auth['roles']) else True

    session['auth'] = auth

def authenticate_with_password(username, password):
    auth_data = {}
    auth = v3.Password(auth_url=config.os_auth_url,
                       username=username,
                       password=password,
                       user_domain_name=config.os_user_domain_name)
    sess = ksession.Session(auth=auth)
    keystone = keystone_client.Client(session=sess)
    projects = keystone.projects.list(user=sess.get_user_id())
    # pick one project at random
    auth = v3.Password(auth_url=config.os_auth_url,
                       username=username,
                       password=password,
                       user_domain_name=config.os_user_domain_name,
                       project_id=projects[0].id,
                       project_domain_id=projects[0].domain_id)
    app.logger.info("Correctly authenticated as {}".format(username))
    # get new scoped token
    sess = ksession.Session(auth=auth)
    fill_session_data(sess)
    app.logger.info("User {}: switching to tenant {}".format(username, sess.auth.project_id))


def get_session(project_id=None, project_domain_id=None):
    if not project_id:
        project_id = session['auth']['project_id']

    if not project_domain_id:
        project_domain_id = 'default'

    auth = v3.Token(
        auth_url=config.os_auth_url,
        token=str(session['auth']['token']),
        project_id=project_id,
        project_domain_id=project_domain_id,
    )
    sess = ksession.Session(auth=auth)
    return sess

def authenticate_with_token(project_id=None, project_domain_id='default'):
    sess = get_session(project_id, project_domain_id)
    fill_session_data(sess)
    app.logger.info("User {} authenticated on tenant {} using token".format(session['auth']['user_id'], sess.auth.project_id))


def authenticated(f):
    """Decorator"""
    @wraps(f)
    def decorated(*args, **kw):
        # Check session
        if 'auth' not in session:
            return redirect(url_for('auth.login'))
        else:
            try:
                authenticate_with_token()
            except Unauthorized:
                return redirect(url_for('auth.login'))
            return f(*args, **kw)
    return decorated

def has_role(roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kw):
            if 'auth' not in session:
                return redirect(url_for('auth.login'))
            elif not set(session['auth']['roles']).intersection(roles):
                return abort(401)
            return f(*args, **kw)
        return decorated
    return decorator

@login_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)

    if request.method == 'POST' and form.validate():
        try:
            authenticate_with_password(form.username.data, form.password.data)
        except Unauthorized:
            error="Wrong login/password combination. Please try again"
            return render_template('auth/login.html', form=form, error=error)
        return redirect(url_for('main.list_projects'))
    return render_template('auth/login.html', form=form)

@login_bp.route('/logout')
def logout():
    if 'auth' in session:
        del session['auth']
    session.clear()
    return redirect(url_for('auth.login'))
