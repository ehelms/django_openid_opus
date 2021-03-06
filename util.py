from django.utils.html import escape
from django.http import get_host
from django.conf import settings
from django.core.urlresolvers import reverse

import time 
import base64
import urllib

from openid.extensions import ax as oidax
from openid.store import nonce as oid_nonce
from openid.store.interface import OpenIDStore
from openid.association import Association as OIDAssociation
from openid.consumer.consumer import Consumer, \
    SUCCESS, CANCEL, FAILURE, SETUP_NEEDED
from openid.yadis import xri
from openid.consumer.discover import DiscoveryFailure

from django_openid_opus.models import Association, Nonce

OPENID_AX = [{"type_uri" : "http://axschema.org/contact/email", "count" : 1, "required" : True, "alias" : "email"}]

def begin_openid(session, trust_root, openid_url, resource_redirect_url):
    redirect_to = trust_root + '/django_openid_opus/login/complete/' + '?next=' + resource_redirect_url
    
    consumer = Consumer(session, DjangoOpenIDStore())
    
    try:
        auth_request = consumer.begin(openid_url)
    except DiscoveryFailure:
        return None

    auth_request = set_attributes(auth_request)
    redirect_url = auth_request.redirectURL(trust_root, redirect_to)
    return redirect_url


def complete_openid(session, query_dict, url):
    consumer = Consumer(session, DjangoOpenIDStore())
    openid_response = consumer.complete(query_dict, url)

    if openid_response.status == SUCCESS:
        openid = from_openid_response(openid_response)
        return "SUCCESS", openid.ax.getExtensionArgs()['value.ext0.1']
    elif openid_response.status == CANCEL:
        return "CANCEL", None
    elif openid_response.status == FAILURE:
        return "FAILURE", openid_response.message
    else:
        return None, None


def set_attributes(auth_request):
    requested_attributes = OPENID_AX
    if requested_attributes:
        ax_request = oidax.FetchRequest()
        for i in requested_attributes:
            ax_request.add(oidax.AttrInfo(i['type_uri'], i['count'], i['required'], i['alias']))
        auth_request.addExtension(ax_request)
    return auth_request


def get_url_host(request):
    if request.is_secure():
        protocol = 'https'
    else:
        protocol = 'http'
    host = escape(get_host(request))
    return '%s://%s' % (protocol, host)


def get_full_url(request):
    return get_url_host(request) + request.get_full_path()


def get_return_url(host, nonce):
    url = (host + '/django_openid_opus/login/complete/').encode('utf8')     
    return url


def is_valid_next_url(request, next):
    absolute_uri = request.build_absolute_uri(next)
    return absolute_uri != next


def from_openid_response(openid_response):
    issued = int(time.time())

    openid = OpenID(openid_response.identity_url, issued, openid_response.signed_fields)

    if getattr(settings, 'OPENID_PAPE', False):
        openid.pape = oidpape.Response.fromSuccessResponse(openid_response)

    if getattr(settings, 'OPENID_SREG', False):
        openid.sreg = oidsreg.SRegResponse.fromSuccessResponse(openid_response)

    if OPENID_AX:
        openid.ax = oidax.FetchResponse.fromSuccessResponse(openid_response)

    return openid


class OpenID:
    def __init__(self, openid, issued, attrs=None, sreg=None, pape=None, ax=None):
        self.openid = openid
        self.issued = issued
        self.attrs = attrs or {}
        self.sreg = sreg or {}
        self.pape = pape or {}
        self.ax = ax or {}
        self.is_iname = (xri.identifierScheme(openid) == 'XRI')
    
    def __repr__(self):
        return '<OpenID: %s>' % self.openid
    
    def __str__(self):
        return self.openid


class DjangoOpenIDStore(OpenIDStore):
    def __init__(self):
        self.max_nonce_age = 6 * 60 * 60 # Six hours
    
    def storeAssociation(self, server_url, association):
        assoc = Association(
            server_url = server_url,
            handle = association.handle,
            secret = base64.encodestring(association.secret),
            issued = association.issued,
            lifetime = association.issued,
            assoc_type = association.assoc_type
        )
        assoc.save()
    
    def getAssociation(self, server_url, handle=None):
        assocs = []
        if handle is not None:
            assocs = Association.objects.filter(
                server_url = server_url, handle = handle
            )
        else:
            assocs = Association.objects.filter(
                server_url = server_url
            )
        if not assocs:
            return None
        associations = []
        for assoc in assocs:
            association = OIDAssociation(
                assoc.handle, base64.decodestring(assoc.secret), assoc.issued,
                assoc.lifetime, assoc.assoc_type
            )
            if association.getExpiresIn() == 0:
                self.removeAssociation(server_url, assoc.handle)
            else:
                associations.append((association.issued, association))
        if not associations:
            return None
        return associations[-1][1]
    
    def removeAssociation(self, server_url, handle):
        assocs = list(Association.objects.filter(
            server_url = server_url, handle = handle
        ))
        assocs_exist = len(assocs) > 0
        for assoc in assocs:
            assoc.delete()
        return assocs_exist
    
    def storeNonce(self, nonce):
        nonce, created = Nonce.objects.get_or_create(
            nonce = nonce, defaults={'expires': int(time.time())}
        )
    
    def useNonce(self, server_url, timestamp, salt):
        if abs(timestamp - time.time()) > oid_nonce.SKEW:
            return False
        
        try:
            nonce = Nonce( server_url=server_url, timestamp=timestamp, salt=salt)
            nonce.save()
        except:
            raise
        else:
            return 1
    
    def getAuthKey(self):
        # Use first AUTH_KEY_LEN characters of md5 hash of SECRET_KEY
        return md5.new(settings.SECRET_KEY).hexdigest()[:self.AUTH_KEY_LEN]
