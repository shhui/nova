# Copyright (c) 2011 Venusource, Inc.
# Copyright 2011 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import uuid

from nova import wsgi as base
from oslo.config import cfg

from auditlog.api.model import models
from auditlog.storage import impl_mongodb
from nova.openstack.common import log as logging
from nova.openstack.common import timeutils

LOG = logging.getLogger(__name__)
cfg.CONF.import_opt('auditlog_connection', 'auditlog.storage',
                    group="database")


class AuditMiddleware(base.Middleware):
    """store POST/PUT/DELETE api request for audit."""

    def __init__(self, application, audit_methods='POST, PUT, DELETE'):

        super(AuditMiddleware, self).__init__(application)
        self._audit_methods = audit_methods.split(",")
        self.client = impl_mongodb.MongoDBStorage()
        self.connection = self.client.get_connection(cfg.CONF)

    def process_request(self, req):
        _need_audit = req.method in self._audit_methods
        if _need_audit:
            id = uuid.uuid4()
            user_id = req.headers.get('X-User-Id', 'unknown')
            tenant_id = req.headers.get('X-Tenant-Id', 'unknown')
            path = req.path
            try:
                rid = models.Resource.parse_url(path).rid
            except Exception:
                rid = None
            method = req.method
            status_code = None
            begin_at = self._format_time(timeutils.utcnow())
            end_at = None
            content = req.body
            self._log = models.AuditLog(id, user_id, tenant_id, rid, path,
                                        method, status_code, begin_at, end_at,
                                        content)
        else:
            self._log = None

    def process_response(self, response):
        if self._log is not None:
            self._log.status_code = response.status_int
            end_at = self._format_time(timeutils.utcnow())
            self._log.end_at = end_at
            self._store_log(self._log)
            self._log = None
        return response

    def _store_log(self, log):
        try:
            self.connection.create_auditlog(log)
        except Exception as e:
            LOG.error("Store audit log error : %s", e)

    def _format_time(self, time):
        formated_t = timeutils.strtime(time,
                                       '%Y-%m-%d %H:%M:%S')
        end = timeutils.parse_strtime(formated_t,
                                      '%Y-%m-%d %H:%M:%S')
        return end
