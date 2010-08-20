from django.conf.urls.defaults import *

urlpatterns = patterns('django_openid_opus.views',
    url(r'^login/$', 'openid_login'),
    url(r'^login/complete/$', 'openid_login_complete'),
    url(r'^logout/$', 'logout_view', name='logout_url'),
)
