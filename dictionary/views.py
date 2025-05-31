from django.db import IntegrityError
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from .forms import SignupForm, SigninForm, Tool
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from .forms import ToolForm
from .models import Tool
from django.contrib import messages
import csv, io
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect
from django.http import HttpResponse
from django.db.models import Count
from .models import Tool, SearchQuery
from django.shortcuts import render
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.response import Response
from .models import Tool, SearchQuery
from .serializers import ToolSerializer
from rest_framework.permissions import IsAuthenticatedOrReadOnly, IsAuthenticated, AllowAny
from rest_framework import status
from rest_framework.authentication import TokenAuthentication


from django.contrib.auth.models import User
from django.db import IntegrityError



import jwt
import requests
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.db import IntegrityError
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings
import json
from datetime import datetime, timedelta

@api_view(['POST'])
@permission_classes([AllowAny])
def google_login_api(request):
    """
    Google OAuth login endpoint
    Expects: { "credential": "google_jwt_token" }
    Returns: { "token": "your_app_jwt_token", "user": {...} }
    """
    try:
        # Get the Google credential token from request
        credential = request.data.get('credential')
        print("Here is your credentials hell", credential)
        if not credential:
            return Response({
                'error': 'Missing credential',
                'message': 'Google credential token is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Verify the Google token by calling Google's tokeninfo endpoint
        google_response = requests.get(
            f'https://oauth2.googleapis.com/tokeninfo?id_token={credential}',
            timeout=10
        )
        
        if google_response.status_code != 200:
            return Response({
                'error': 'Invalid Google token',
                'message': 'Failed to verify Google authentication'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Parse Google user data
        google_data = google_response.json()
        
        # Verify the token is for your app
        expected_client_id = getattr(settings, 'GOOGLE_CLIENT_ID', None)
        if expected_client_id and google_data.get('aud') != expected_client_id:
            return Response({
                'error': 'Invalid client',
                'message': 'Token was not issued for this application'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Extract user information
        email = google_data.get('email')
        name = google_data.get('name', '')
        google_id = google_data.get('sub')
        
        if not email or not google_id:
            return Response({
                'error': 'Incomplete Google data',
                'message': 'Could not retrieve email or user ID from Google'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if user exists by email
        try:
            user = User.objects.get(email=email)
            # User exists, update Google ID if not set
            if not hasattr(user, 'profile') or not getattr(user.profile, 'google_id', None):
                # You might want to create a UserProfile model to store google_id
                # For now, we'll just proceed with login
                pass
                
        except User.DoesNotExist:
            # Create new user
            try:
                # Generate username from email or name
                base_username = email.split('@')[0]
                username = base_username
                counter = 1
                
                # Ensure username is unique
                while User.objects.filter(username=username).exists():
                    username = f"{base_username}{counter}"
                    counter += 1
                
                # Create user with Google data
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    first_name=name.split(' ')[0] if name else '',
                    last_name=' '.join(name.split(' ')[1:]) if name and len(name.split(' ')) > 1 else ''
                )
                
                # You might want to create a UserProfile to store google_id
                # UserProfile.objects.create(user=user, google_id=google_id)
                
            except IntegrityError as e:
                return Response({
                    'error': 'User creation failed',
                    'message': 'Could not create user account'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Generate JWT token for your app (similar to your login endpoint)
        token = generate_jwt_token(user)
        
        return Response({
            'message': 'Google login successful',
            'token': token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            }
        }, status=status.HTTP_200_OK)

    except requests.RequestException:
        return Response({
            'error': 'Google verification failed',
            'message': 'Could not verify Google token'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    except Exception as e:
        # Log the error in production
        print(f"Google login error: {str(e)}")
        return Response({
            'error': 'Authentication failed',
            'message': 'An error occurred during Google authentication'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


def generate_jwt_token(user):
    """
    Generate JWT token for user - modify this to match your existing token generation
    """
    payload = {
        'user_id': user.id,
        'username': user.username,
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(days=7),  # Token expires in 7 days
        'iat': datetime.utcnow()
    }
    
    # Use your SECRET_KEY or a specific JWT secret
    secret_key = getattr(settings, 'SECRET_KEY')
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    
    return token




def track_click(request, tool_id):
    tool = get_object_or_404(Tool, id=tool_id)
    tool.click_count += 1
    tool.save()
    return redirect(tool.link)

def signup_view(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('home')  # or any page after login
    else:
        form = SignupForm()
    return render(request, 'signup.html', {'form': form})

def signin_view(request):
    if request.method == 'POST':
        form = SigninForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('home')
    else:
        form = SigninForm()
    return render(request, 'signin.html', {'form': form})

def signout_view(request):
    logout(request)
    return redirect('signin')

@login_required
def home_view(request):
    return render(request, 'home.html')

def index_view(request):
    return render(request, 'index.html')

@login_required
def submit_tool(request):
    if request.method == 'POST':
        form = ToolForm(request.POST)
        if form.is_valid():
            tool = form.save(commit=False)
            tool.submitted_by = request.user
            tool.save()
            return redirect('view_tools')
    else:
        form = ToolForm()
    return render(request, 'submit.html', {'form': form})

@login_required
def profile_view(request):
    return render(request, 'profile.html')

@login_required
def view_tools(request):
    search = request.GET.get('search', '')
    category = request.GET.get('category', '')

    tools = Tool.objects.filter(is_approved=True)

    if search:
        tools = tools.filter(name__icontains=search)
        # Track the search query
        SearchQuery.objects.create(query=search)

    if category:
        tools = tools.filter(category=category)

    # Pagination
    paginator = Paginator(tools, 12)  # Show 12 tools per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    categories = Tool.CATEGORY_CHOICES
    return render(request, 'tools.html', {
        'page_obj': page_obj,
        'search': search,
        'selected_category': category,
        'categories': categories,
    })

@login_required
def upload_cleaned_csv(request):
    if request.method == 'POST' and request.FILES.get('csv_file'):
        csv_file = request.FILES['csv_file']
        if not csv_file.name.endswith('.csv'):
            messages.error(request, 'Please upload a CSV file.')
            return redirect('upload_cleaned_csv')

        try:
            text_io = io.StringIO(csv_file.read().decode('utf-8'))
            reader = csv.DictReader(text_io)
            reader.fieldnames = [fn.strip().replace('\ufeff', '') for fn in reader.fieldnames]

            success_count = 0
            default_logo = "https://ai.openbestof.com/images/tools/mistral-ai_icon.webp"

            for row in reader:
                print("Row:", row)
                name = row.get('name', '').strip()
                link = row.get('link', '').strip()
                description = row.get('description', '').strip()
                logo_url = row.get('image_url', '').strip() or default_logo
                category = row.get('category', '')

                print(f"Parsed: name={name}, link={link}, description={description}, logo={logo_url}, Category ={category}")

                try:
                    Tool.objects.create(
                        name=name,
                        link=link,
                        description=description,
                        image_url=logo_url,
                        category = category,
                        is_approved=True
                    )
                    success_count += 1
                except Exception as e:
                    messages.warning(request, f"Error adding tool '{name}': {e}")
                    continue

            messages.success(request, f"{success_count} tools imported successfully.")
        except Exception as e:
            messages.error(request, f"Failed to read file: {e}")

        return redirect('upload_cleaned_csv')

    return render(request, 'upload_cleaned_csv.html')

def export_tools_csv(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="tools.csv"'

    writer = csv.writer(response)
    writer.writerow([
        "ID", "Name", "Link", "Image URL", "Description", "Tags", "Created At",
        "Is Approved", "Click Count", "Views", "Developer", "Submitted By", "Category"
    ])

    for tool in Tool.objects.all():
        writer.writerow([
            tool.id,
            tool.name,
            tool.link,
            tool.image_url,
            tool.description,
            tool.tags,
            tool.created_at.strftime("%Y-%m-%d %H:%M:%S") if tool.created_at else '',
            tool.is_approved,
            tool.click_count,
            tool.views,
            tool.developer,
            str(tool.submitted_by) if tool.submitted_by else '',
            tool.category,
        ])

    return response

@staff_member_required
def admin_dashboard(request):
    top_clicked_tools = Tool.objects.order_by('-click_count')[:10]
    top_search_queries = (
        SearchQuery.objects.values('query')
        .annotate(count=Count('id'))
        .order_by('-count')[:10]
    )
    return render(request, 'admin_dashboard.html', {
        'top_clicked_tools': top_clicked_tools,
        'top_search_queries': top_search_queries,
    })


@api_view(['POST'])
def signup_api(request):
    username = request.data.get('username', '').strip()
    password = request.data.get('password', '').strip()
    email = request.data.get('email', '').strip()
    if not username or not password or not email:
        return Response({
            'error': 'All fields are required',
            'message': 'Please provide username, password, and email'
        }, status=status.HTTP_400_BAD_REQUEST)
    try:
        user = User.objects.create_user(username=username, password=password, email=email)
        return Response({
            'message': 'User created successfully',
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
        }, status=status.HTTP_201_CREATED)
    except IntegrityError:
        return Response({
            'error': 'Username already exists',
            'message': 'Please choose a different username'
        }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def search_tools_api(request):
    """
    Search tools by name
    Parameters:
    - q: search query (required)
    - category: filter by category (optional)
    - limit: limit results (optional, default: 20)
    """
    search_query = request.GET.get('q', '').strip()
    category = request.GET.get('category', '').strip()
    limit = request.GET.get('limit', '20')
    if not search_query:
        return Response({
            'error': 'Search query is required',
            'message': 'Please provide a search query using the "q" parameter'
        }, status=status.HTTP_400_BAD_REQUEST)
    try:
        limit = int(limit)
        if limit <= 0 or limit > 100:  
            limit = 20
    except ValueError:
        limit = 20
    tools = Tool.objects.filter(is_approved=True)
    tools = tools.filter(name__icontains=search_query)
    if category:
        tools = tools.filter(category__iexact=category)
    tools = tools.extra(
        select={
            'exact_match': "CASE WHEN LOWER(name) = LOWER(%s) THEN 1 ELSE 0 END"
        },
        select_params=[search_query]
    ).order_by('-exact_match', '-click_count', 'name')
    tools = tools[:limit]
    try:
        SearchQuery.objects.create(query=search_query)
    except:
        pass  
    serializer = ToolSerializer(tools, many=True)
    return Response({
        'query': search_query,
        'category': category if category else None,
        'total_results': len(serializer.data),
        'results': serializer.data
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
def search_by_category_api(request):
    category = request.GET.get('category', '').strip()
    limit = int(request.GET.get('limit', 18))
    offset = int(request.GET.get('offset', 0))

    if not category:
        return Response({
            'error': 'Category is required',
            'message': 'Please provide a category using the "category" parameter'
        }, status=status.HTTP_400_BAD_REQUEST)

    tools = Tool.objects.filter(
        is_approved=True,
        category__icontains=category

    ).order_by('-click_count', 'name')[offset:offset+limit]

    serializer = ToolSerializer(tools, many=True)
    return Response({
        'category': category,
        'total_results': len(serializer.data),
        'results': serializer.data
    }, status=status.HTTP_200_OK)

@api_view(['GET'])
def similar_tools_search_limit(request):
    tag = request.GET.get('tag', '').strip()

    if not tag:
        return Response({
            'error': 'tag is required',
            'message': 'Please provide a tag using the "tag" parameter'
        }, status=status.HTTP_400_BAD_REQUEST)

    tools = Tool.objects.filter(
        is_approved=True,
        category__icontains=tag
    ).order_by('-click_count', 'name')[:4]  # ✅ Limit to 5 tools

    serializer = ToolSerializer(tools, many=True)
    return Response({
        'category': tag,
        'total_results': len(serializer.data),
        'results': serializer.data
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
def search_suggestions_api(request):
    search_query = request.GET.get('q', '').strip()
    limit = request.GET.get('limit', '10')
    if not search_query:
        return Response({
            'error': 'Search query is required',
            'message': 'Please provide a search query using the "q" parameter'
        }, status=status.HTTP_400_BAD_REQUEST)
    try:
        limit = int(limit)
        if limit <= 0 or limit > 20:
            limit = 10
    except ValueError:
        limit = 10
    tools = Tool.objects.filter(
        is_approved=True,
        description__icontains=search_query
    ).order_by('tags')[:limit]
    serializer = ToolSerializer(tools, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
def list_tools_api(request):
    tools = Tool.objects.filter(is_approved=True)
    serializer = ToolSerializer(tools, many=True)
    return Response(serializer.data)

@api_view(['GET'])
def list_tools_pagination_api(request):
    # Get limit and offset from query params or use defaults
    limit = int(request.GET.get('limit', 18))
    offset = int(request.GET.get('offset', 0))

    # Filter approved tools and apply pagination
    tools = Tool.objects.filter(is_approved=True)[offset:offset+limit]
    serializer = ToolSerializer(tools, many=True)

    return Response(serializer.data)


@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticatedOrReadOnly])
def submit_tool_api(request):
    serializer = ToolSerializer(data=request.data)
    if serializer.is_valid():
        tool = serializer.save(submitted_by=request.user)
        return Response({'message': 'Tool submitted successfully'}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def check_login_status(request):
    return Response({
        'is_logged_in': True,
        'user': {
            'id': request.user.id,
            'username': request.user.username,
            'email': request.user.email,
        }
    })


@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def logout_api(request):
    request.user.auth_token.delete()
    return Response({"message": "Logged out successfully"}, status=status.HTTP_200_OK)
