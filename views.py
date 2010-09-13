from django.shortcuts import render_to_response, redirect
from django.http import HttpResponse
from django.template import RequestContext
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.urlresolvers import reverse

from django_openid_opus.util import get_url_host, begin_openid, get_return_url, complete_openid
from django_openid_opus import util

def openid_login(request, template_name="django_openid_opus/login.html"):
    if "next" in request.REQUEST:
            next = request.REQUEST['next']
    else:
        next = "/openid/test/"

    if request.method == 'POST':
        openid_url = request.POST['openid_url']
        session = request.session

        trust_root = get_url_host(request)
        redirect_url = begin_openid(session, trust_root, openid_url, next)

        if not redirect_url:
            message = "OpenID Failure"
            return render_to_response("django_openid_opus/login.html",
                    { 'message' : message, },
                    context_instance=RequestContext(request))
        else:
            return redirect(redirect_url)
    else:
        return render_to_response("django_openid_opus/login.html",
                { "next" : next, },
                context_instance=RequestContext(request))


def openid_login_complete(request):
    if util.is_valid_next_url(request, next = request.GET['next']):
        next = request.GET['next']
    session = request.session
    
    host = get_url_host(request)
    nonce = request.GET['janrain_nonce']

    url = get_return_url(host, nonce)
    
    query_dict = dict([
        (k.encode('utf8'), v.encode('utf8')) for k, v in request.GET.items()])
    
    status, username = complete_openid(session, query_dict, url)

    if status == "SUCCESS":
        username = username
        user = authenticate(username=username)
        if user is not None:
            login(request, user)
            return redirect(next)
        else:
            return redirect(settings.LOGIN_URL)   
    elif status == "CANCEL":
        message = "OpenID login failed due to a cancelled request.  This can be due to failure to release email address which is required by the service."
        return render_to_response('django_openid_opus/login.html',
        {'message' : message,
        'next' : resource_redirect_url,},
        context_instance=RequestContext(request))
    elif status == "FAILURE":
        return render_to_response('django_openid_opus/login.html',
                {'message' : "FAILURE:" + username,
                'next' : url,},
                context_instance=RequestContext(request))
    else:
        message = "An error was encountered"
        return render_to_response('django_openid_opus/login.html',
        {'message' : message,
        'next' : resource_redirect_url, },
        context_instance=RequestContext(request))


@login_required
def logout_view(request, template_name="django_openid_opus/logout.html", redirect_url=None):
    logout(request)
    
    if "next" in request.GET:
        next = request.GET['next']
    elif not redirect_url:
        next = settings.LOGIN_URL
    else:
        next = redirect_url

    return render_to_response(template_name,
            {'next' : next, },
            context_instance=RequestContext(request))


@login_required
def openid_test_page(request):
    return render_to_response("django_openid_opus/test.html",
            context_instance=RequestContext(request))
