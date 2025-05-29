from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from .forms import SignupForm, SigninForm, Tool, MultipleCSVUploadForm
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
from .serializers import ToolSerializer, SearchQuerySerializer
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from rest_framework import status
from rest_framework.authentication import TokenAuthentication

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
                name = row.get('Tool Name', '').strip()
                link = row.get('Link', '').strip()
                description = row.get('Description', '').strip()
                logo_url = row.get('Logo URL', '').strip() or default_logo  # <-- fallback here

                print(f"Parsed: name={name}, link={link}, description={description}, logo={logo_url}")

                try:
                    Tool.objects.create(
                        name=name,
                        link=link,
                        description=description,
                        image_url=logo_url,
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
def search_suggestions_api(request):
    """
    Get search suggestions based on existing tool names
    Parameters:
    - q: partial search query (required)
    - limit: limit results (optional, default: 10)
    """
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

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticatedOrReadOnly])
def submit_tool_api(request):
    serializer = ToolSerializer(data=request.data)
    if serializer.is_valid():
        tool = serializer.save(submitted_by=request.user)
        return Response({'message': 'Tool submitted successfully'}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
