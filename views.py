from django.shortcuts import render_to_response, redirect
from django.http import HttpResponse
from django.template import RequestContext
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.sites.models import Site
from django.core.urlresolvers import reverse

from opus.lib import log
log = log.getLogger()


def openid_login(request, redirect_to=None):
    openid_url = request.POST['openid_url']
    resource_redirect_url = request.POST['next']
    log.debug(resource_redirect_url)
    institution = authentication_tools.get_institution(request)
    session = request.session

    trust_root = authentication_tools.get_url_host(request)
    if not redirect_to:
        redirect_url = openid_tools.begin_openid(session, trust_root, openid_url, resource_redirect_url)
    else:
        log.debug(redirect_to)
        redirect_url = openid_tools.begin_openid(session, trust_root, openid_url, resource_redirect_url, redirect_to)

    if not redirect_url:
        return HttpResponse('The OpenID was invalid')
    else:
        return HttpResponseRedirect(redirect_url)


def openid_login_complete(request):
    institution = authentication_tools.get_institution(request)
    resource_redirect_url = request.GET['next']
    session = request.session
    
    host = authentication_tools.get_url_host(request)
    nonce = request.GET['janrain_nonce']
    if not "" == settings.OPENID_COMPLETE_URL:
        url = openid_tools.get_return_url(host, nonce, settings.OPENID_COMPLETE_URL)
    else:
        url = openid_tools.get_return_url(host, nonce)
    
    query_dict = dict([
        (k.encode('utf8'), v.encode('utf8')) for k, v in request.GET.items()])
    
    status, username = openid_tools.complete_openid(session, query_dict, url)

    if status == "SUCCESS":
        username = username
        user = authenticate(username=username)
        if user is not None:
            log.debug("Logging user in")
            login(request, user)
            authentication_tools.add_session_username(request, username.split('@')[0])
            log.debug("Redirecting to " + resource_redirect_url)
            return HttpResponseRedirect(resource_redirect_url)
        else:
            log.debug("No user found")
            return HttpResponseRedirect(settings.LOGIN_URL)   
        
    elif status == "CANCEL":
        message = "OpenID login failed due to a cancelled request.  This can be due to failure to release email address which is required by the service."
        return render_to_response('idpauth/openid.html',
        {'message' : message,
        'next' : resource_redirect_url,},
        context_instance=RequestContext(request))
    elif status == "FAILURE":
        return render_to_response('idpauth/openid.html',
        {'message' : username,
        'next' : resource_redirect_url,},
        context_instance=RequestContext(request))

    else:
        message = "An error was encountered"
        return render_to_response('idpauth/openid.html',
        {'message' : message,
        'next' : resource_redirect_url, },
        context_instance=RequestContext(request))


@login_required
def logout_view(request, template_name=None, redirect_url=None, redirect_viewname=None):
    try:
        del request.session['username']
    except KeyError:
        pass
    logout(request)
    #institution = authentication_tools.get_institution(request)
    
    if not template_name:
        template_name = 'idpauth/logout.html'

    if "next" in request.GET:
            next = request.GET['next']
    elif not redirect_url:
        if redirect_viewname != None:
            next = reverse(redirect_viewname)
        else:
            next = None
    else:
        next = redirect_url

    return render_to_response(template_name,
            {'next' : next, },
            context_instance=RequestContext(request))
