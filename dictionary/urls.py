from django.urls import path
from .views import signup_view, signin_view, signout_view, home_view, index_view, profile_view, view_tools, submit_tool, export_tools_csv
from .import views
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns = [
    path('api/check-login/', views.check_login_status),
    path('api/signup/', views.signup_api),
    path('api/login/', obtain_auth_token),
    path('api/logout/', views.logout_api),
    path('api/tools/', views.list_tools_api, name='api-list-tools'),
    path('api/tools/pagination', views.list_tools_pagination_api, name='api-list-tools'),
    path('api/tools/submit/', views.submit_tool_api, name='api-submit-tool'),
    path('api/tools/search/', views.search_tools_api, name='api-search-tools'),
    path('api/tools/suggestions/', views.search_suggestions_api, name='api-search-suggestions'),
    path('api/tools/category/', views.search_by_category_api, name='search-by-category'),
    path('api/tools/similar/', views.similar_tools_search_limit, name="similar-tools-search-limit"),
    

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
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard')
]
