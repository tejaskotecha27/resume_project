# Resume Edit & Suggestion View
import requests
import PyPDF2
import docx
import os
from datetime import datetime
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import FileResponse
import io
from django.conf import settings

# Home page view
def home_view(request):
    return render(request, 'home.html')

# Helper function to extract text from a PDF file
def extract_text_from_pdf(file):
    text = ""
    reader = PyPDF2.PdfReader(file)
    for page in reader.pages:
        text += page.extract_text() or ""
    return text

# Helper function to extract text from a DOCX file
def extract_text_from_docx(file):
    doc = docx.Document(file)
    return "\n".join([para.text for para in doc.paragraphs])

from django.contrib.auth.decorators import login_required

def generate_report(analysis_result, resume_file_name, job_desc):
    """Generate a formatted text report from the analysis results."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    report = f"""RESUME ANALYSIS REPORT
Generated on: {timestamp}
Resume Analyzed: {resume_file_name}

{'='*50}

"""
    if job_desc:
        report += "ANALYSIS WITH JOB DESCRIPTION\n"
    else:
        report += "GENERAL RESUME ANALYSIS\n"
    
    report += f"{'='*50}\n\n"
    report += analysis_result
    
    return report

@login_required(login_url='login')
def analyze_resume_view(request):
    if request.method == 'POST' and request.FILES.get('resume_file'):
        resume_file = request.FILES['resume_file']
        job_desc = request.POST.get('job_desc', '').strip()

        # Extract text based on file extension
        if resume_file.name.endswith('.pdf'):
            resume_text = extract_text_from_pdf(resume_file)
        elif resume_file.name.endswith('.docx'):
            resume_text = extract_text_from_docx(resume_file)
        else:
            return render(request, 'upload.html', {'error': 'Unsupported file type.'})

        # Call Ollama for analysis, passing job description if provided
        analysis_result = call_ollama_api(resume_text, job_desc)

        # Generate the report
        report_text = generate_report(analysis_result, resume_file.name, job_desc)
        
        # Create a text file in memory
        report_file = io.StringIO()
        report_file.write(report_text)
        report_file.seek(0)

        # Convert to BytesIO for response
        report_bytes = io.BytesIO(report_file.getvalue().encode('utf-8'))
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"resume_analysis_{timestamp}.txt"

        # Store the report and filename in session for download
        request.session['report_data'] = report_text
        request.session['report_filename'] = filename

        # Render the results page with both analysis and download option
        return render(request, 'results.html', {
            'analysis': analysis_result,
            'has_report': True,
            'filename': filename
        })

    # If it's a GET request, just show the upload form
    return render(request, 'upload.html')

@login_required(login_url='login')
def download_report(request):
    """View to handle report downloads"""
    report_data = request.session.get('report_data')
    filename = request.session.get('report_filename')
    
    if not report_data or not filename:
        messages.error(request, 'No report found to download.')
        return redirect('analyze_resume')
    
    # Create the response with the report data
    report_file = io.StringIO(report_data)
    report_bytes = io.BytesIO(report_file.getvalue().encode('utf-8'))
    
    response = FileResponse(report_bytes, as_attachment=True, filename=filename)
    return response

# Login view
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, 'Invalid username or password.')
    return render(request, 'login.html')

# Logout view
def logout_view(request):
    logout(request)
    return render(request, 'logout.html')

# Register view
def register_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        if password1 != password2:
            messages.error(request, 'Passwords do not match.')
        elif User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
        elif User.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered.')
        else:
            user = User.objects.create_user(username=username, email=email, password=password1)
            login(request, user)
            return redirect('home')
    return render(request, 'register.html')

# (Add this function to the same views.py file)

def call_ollama_api(resume_text, job_desc=None):
    url = "http://localhost:11434/api/generate"
    if job_desc:
        prompt = f"""
        You are an expert ATS (Applicant Tracking System) analyzer. Perform a detailed analysis of how well the resume matches the provided job description.
        
        Structure your response in the following format:

        1. **Match Score**:
           - Provide a percentage (0-100%) indicating overall resume match with job requirements
           - Break down match scores by key requirements

        2. **Skills Analysis**:
           - List skills found in both resume and job description
           - List required skills missing from the resume
           - List additional relevant skills in resume not mentioned in job description

        3. **Experience Alignment**:
           - Analyze how well the candidate's experience matches job requirements
           - Highlight specific experiences that directly relate to job requirements
           - Identify any experience gaps

        4. **Keywords Match**:
           - List important keywords from job description found in resume
           - List critical keywords missing from resume
           - Suggestions for keyword optimization

        5. **Improvement Recommendations**:
           - Specific suggestions to better align resume with this job
           - Key areas to highlight or modify
           - Skills to add or emphasize

        6. **Overall Assessment**:
           - Clear statement if the candidate appears qualified
           - Main strengths for this specific role
           - Major gaps or concerns

        Analyze based on this data:
        ---
        **RESUME TEXT:**
        {resume_text}
        ---
        **JOB DESCRIPTION:**
        {job_desc}
        ---

        Provide a data-driven, objective analysis focusing on concrete matches and gaps between the resume and job requirements.
        """
    else:
        prompt = f"""
        You are an expert HR analyst. Analyze the following resume text and provide a professional evaluation.
        Structure your response with these sections:
        1. **Professional Summary**: A brief, powerful summary of the candidate's profile.
        2. **Key Strengths**: List the top 3-5 skills and strengths.
        3. **Areas for Improvement**: Constructive feedback on how to make the resume stronger.

        ---
        **RESUME TEXT:**
        {resume_text}
        ---
        """

    payload = {
        "model": "llama3",
        "prompt": prompt,
        "stream": False
    }
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return response.json().get('response', 'Could not get a valid response.')
    except requests.exceptions.RequestException as e:
        return f"Error connecting to Ollama: {e}. Please ensure Ollama is running."

@login_required(login_url='login')
def resume_edit_view(request):
    suggestions = None
    edit_text = None
    if request.method == 'POST' and request.FILES.get('resume_file'):
        resume_file = request.FILES['resume_file']
        if resume_file.name.endswith('.pdf'):
            resume_text = extract_text_from_pdf(resume_file)
        elif resume_file.name.endswith('.docx'):
            resume_text = extract_text_from_docx(resume_file)
        else:
            return render(request, 'resume_edit.html', {'error': 'Unsupported file type.'})

        # Call Ollama for suggestions and edits
        ollama_response = call_ollama_edit_api(resume_text)
        suggestions = ollama_response.get('suggestions', '')
        edit_text = ollama_response.get('edit_text', '')

    return render(request, 'resume_edit.html', {
        'suggestions': suggestions,
        'edit_text': edit_text,
    })

# Helper for edit API
def call_ollama_edit_api(resume_text):
    url = "http://localhost:11434/api/generate"
    prompt = f"""
    You are an expert resume editor. Analyze the following resume text and:
    1. Suggest specific improvements and edits to make the resume stronger (output as 'Suggestions').
    2. Provide a revised version of the resume text with your suggested edits (output as 'Edited Resume').

    ---
    RESUME TEXT:
    {resume_text}
    ---
    Format your response as:
    Suggestions:
    ...
    Edited Resume:
    ...
    """
    payload = {
        "model": "llama3",
        "prompt": prompt,
        "stream": False
    }
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        raw = response.json().get('response', '')
        # Parse response
        import re
        suggestions_match = re.search(r'Suggestions:\s*(.*?)(?:Edited Resume:|$)', raw, re.DOTALL | re.IGNORECASE)
        edit_match = re.search(r'Edited Resume:\s*(.*)', raw, re.DOTALL | re.IGNORECASE)
        return {
            'suggestions': suggestions_match.group(1).strip() if suggestions_match else '',
            'edit_text': edit_match.group(1).strip() if edit_match else '',
        }
    except requests.exceptions.RequestException as e:
        return {'suggestions': f'Error connecting to Ollama: {e}', 'edit_text': ''}
