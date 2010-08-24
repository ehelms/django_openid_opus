from django.conf import settings

def context_processor(request):
    includes = {
            'DJANGO_OPENID_OPUS_MEDIA_PREFIX' : settings.DJANGO_OPENID_MEDIA_PREFIX,
            }

    return includes
