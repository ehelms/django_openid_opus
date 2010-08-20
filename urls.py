from django.conf.urls.defaults import *

urlpatterns = patterns('django_openid_opus.views',
    url(r'^login/$', 'determine_login', name='login_url'),
    url(r'^openid_login/$', 'openid_login'),
    url(r'^openid_login_complete/$', 'openid_login_complete'),
    url(r'^logout/$', 'logout_view', name='logout_url'),
)
