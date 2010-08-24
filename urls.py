from django.conf.urls.defaults import *

urlpatterns = patterns('django_openid_opus.views',
    url(r'^login/$', 'openid_login', name='openid_login_url'),
    url(r'^login/complete/$', 'openid_login_complete', name='openid_complete_url'),
    url(r'^logout/$', 'logout_view', name='openid_logout_url'),
    url(r'^test/$', 'openid_test_page', name='openid_test_page_url'),
)
