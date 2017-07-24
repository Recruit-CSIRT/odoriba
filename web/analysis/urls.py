# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

# [customized] this module is for url rendering 
#              2 additional pages. see tab # ADD FUNCTION

import os.path
from django.conf.urls import patterns, url


urlpatterns = patterns(
    "",
    url(r"^$", "analysis.views.index"),
    url(r"^(?P<task_id>\d+)/$", "analysis.views.report"),
    url(r"^latest/$", "analysis.views.latest_report"),
    url(r"^remove/(?P<task_id>\d+)/$", "analysis.views.remove"),
    url(r"^chunk/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<pagenum>\d+)/$", "analysis.views.chunk"),
    url(r"^filtered/(?P<task_id>\d+)/(?P<pid>\d+)/(?P<category>\w+)/$", "analysis.views.filtered_chunk"),
    url(r"^search/(?P<task_id>\d+)/$", "analysis.views.search_behavior"),
    url(r"^search/$", "analysis.views.search"),
    url(r"^pending/$", "analysis.views.pending"),

    # ADD FUNCTION #
    url(r"^running/$", "analysis.views.running"),
    url(r"^finish/$", "analysis.views.finish"),
    ###

    url(r"^(?P<task_id>\d+)/pcapstream/(?P<conntuple>[.,\w]+)/$", "analysis.views.pcapstream"),
    url(r"^moloch"
        "/(?P<ip>[\d\.]+)?/(?P<host>[a-zA-Z0-9-\.]+)?"
        "/(?P<src_ip>[a-zA-Z0-9\.]+)?/(?P<src_port>\d+|None)?"
        "/(?P<dst_ip>[a-zA-Z0-9\.]+)?/(?P<dst_port>\d+|None)?"
        "/(?P<sid>\d+)?",
        "analysis.views.moloch"),
)

