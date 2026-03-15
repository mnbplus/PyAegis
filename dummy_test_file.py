import os
def insecure_endpoint(request):
    user_input = request.GET.get('cmd')
    os.system(user_input)
