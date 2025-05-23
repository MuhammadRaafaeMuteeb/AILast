from django.urls import path
from .views import signup_view, signin_view, signout_view, home_view, index_view, profile_view, view_tools, submit_tool, export_tools_csv
from .import views
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns = [
    path('', index_view, name='index'),
    path('signup/', signup_view, name='signup'),
    path('signin/', signin_view, name='signin'),
    path('signout/', signout_view, name='signout'),
    path('home/', home_view, name='home'),
    path('profile/', profile_view, name='profile'),
    path('tools/', view_tools, name='view_tools'),
    path('submit/', submit_tool, name='submit_tool'),
    #path('upload-multiple-tools/', views.upload_multiple_tools, name='upload_multiple_tools'),
    path('upload-cleaned-csv/', views.upload_cleaned_csv, name='upload_cleaned_csv'),
    path('click/<int:tool_id>/', views.track_click, name='track_click'),
    path('export-tools-csv/', export_tools_csv, name='export_tools_csv'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),




    path('api/login/', obtain_auth_token),


    path('api/tools/', views.list_tools_api, name='api-list-tools'),
    path('api/tools/submit/', views.submit_tool_api, name='api-submit-tool'),
]