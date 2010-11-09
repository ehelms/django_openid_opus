from django.conf.urls.defaults import *
from django.conf import settings

urlpatterns = patterns('django_openid_opus.views',
    url(r'^login/$', 'openid_login', name='openid_login_url'),
    url(r'^login/complete/$', 'openid_login_complete', name='openid_complete_url'),
    url(r'^logout/$', 'logout_view', name='openid_logout_url'),
    url(r'^test/$', 'openid_test_page', name='openid_test_page_url'),
)


if settings.DEBUG:
    urlpatterns += patterns('',
        (r'^site_media/(?P<path>.*)$', 'django.views.static.serve', 
            { 'document_root' : settings.BASE_DIR + '/django_openid_opus/media/' }),
    )
