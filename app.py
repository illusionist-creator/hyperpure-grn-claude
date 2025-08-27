#!/usr/bin/env python3
"""
Streamlit App for Gmail to Google Drive Automation
Updated with modern OAuth2 authentication approach
"""

import streamlit as st
import os
import json
import time
import logging
import tempfile
import ssl
import socket
import base64
import re
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
import io
from io import StringIO
import sys

# Google API imports
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseUpload

# LlamaParse import
try:
    from llama_cloud_services import LlamaExtract
    LLAMA_AVAILABLE = True
except ImportError:
    LLAMA_AVAILABLE = False

# Configure page
st.set_page_config(
    page_title="Gmail to Drive Automation",
    page_icon="📧",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better UI
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        text-align: center;
        margin-bottom: 2rem;
        color: #1f77b4;
    }
    .config-section {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin-bottom: 1rem;
    }
    .success-message {
        background-color: #d4edda;
        color: #155724;
        padding: 0.75rem;
        border-radius: 0.25rem;
        border-left: 4px solid #28a745;
        margin: 1rem 0;
    }
    .error-message {
        background-color: #f8d7da;
        color: #721c24;
        padding: 0.75rem;
        border-radius: 0.25rem;
        border-left: 4px solid #dc3545;
        margin: 1rem 0;
    }
    .warning-message {
        background-color: #fff3cd;
        color: #856404;
        padding: 0.75rem;
        border-radius: 0.25rem;
        border-left: 4px solid #ffc107;
        margin: 1rem 0;
    }
    .info-message {
        background-color: #d1ecf1;
        color: #0c5460;
        padding: 0.75rem;
        border-radius: 0.25rem;
        border-left: 4px solid #17a2b8;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'gmail_service' not in st.session_state:
    st.session_state.gmail_service = None
if 'drive_service' not in st.session_state:
    st.session_state.drive_service = None
if 'sheets_service' not in st.session_state:
    st.session_state.sheets_service = None
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'processing' not in st.session_state:
    st.session_state.processing = False
if 'auth_url' not in st.session_state:
    st.session_state.auth_url = None
if 'flow' not in st.session_state:
    st.session_state.flow = None

# App configuration - Hardcoded values
HARDCODED_CONFIG = {
    'gmail': {
        'sender': 'noreply@hyperpure.com',
        'search_term': 'Hyperpure GRN',
        'attachment_filter': 'attachment.pdf',
        'gdrive_folder_id': '1euqxO-meY4Ahszpdk3XbwlRwvkfSlY8k'
    },
    'sheets': {
        'drive_folder_id': '1aUjRMqWjVDDAsQw0TugwgmwYjxP6W7DT',
        'llama_api_key': 'llx-ZBUTlOe0JLY3ny0FSs5mSJTMgOZU7RV3x3TGyQPNQQ0XPhyO',
        'llama_agent': 'Hyperpure Agent',
        'spreadsheet_id': '1B1C2ILnIMXpEYbQzaSkhRzEP2gmgE2YLRNqoX98GwcU',
        'sheet_range': 'hyperpuregrn'
    }
}

def get_credentials_path():
    """Get credentials path based on deployment environment"""
    try:
        # Check if OAuth credentials are in Streamlit secrets
        if "web" in st.secrets or "installed" in st.secrets:
            # Create OAuth credentials from secrets
            credentials_dict = {}
            
            # Check for web type (for web applications)
            if "web" in st.secrets:
                credentials_dict["web"] = dict(st.secrets["web"])
            
            # Check for installed type (for desktop applications)
            if "installed" in st.secrets:
                credentials_dict["installed"] = dict(st.secrets["installed"])
            
            # Create temporary file with the credentials
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            json.dump(credentials_dict, temp_file, indent=2)
            temp_file.close()
            return temp_file.name
            
        # Check for the old format (direct google_credentials)
        elif "google_credentials" in st.secrets:
            credentials_dict = dict(st.secrets["google_credentials"])
            
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
            json.dump(credentials_dict, temp_file, indent=2)
            temp_file.close()
            return temp_file.name
            
    except Exception as e:
        st.error(f"Failed to load credentials from Streamlit secrets: {str(e)}")
        return None

    # Fallback to local file for development
    local_path = 'D:\\GRN\\PDF\\zhplgm\\credentials.json'
    if os.path.exists(local_path):
        return local_path
    else:
        st.error(f"Credentials file not found at: {local_path}")
        return None

def load_existing_token() -> Optional[Credentials]:
    """Load existing token from file"""
    token_file = 'token_combined.json'
    
    if os.path.exists(token_file):
        try:
            creds = Credentials.from_authorized_user_file(token_file)
            if creds and creds.valid:
                return creds
            elif creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                    # Save refreshed token
                    with open(token_file, 'w') as token:
                        token.write(creds.to_json())
                    return creds
                except Exception as e:
                    st.warning(f"Token refresh failed: {str(e)}")
                    return None
        except Exception as e:
            st.warning(f"Error loading existing token: {str(e)}")
            return None
    return None

def create_auth_flow():
    """Create OAuth2 flow with proper redirect URI"""
    credentials_path = get_credentials_path()
    if not credentials_path:
        return None
    
    try:
        scopes = [
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/drive.file',
            'https://www.googleapis.com/auth/spreadsheets'
        ]
        
        # Determine the application type from credentials
        with open(credentials_path, 'r') as f:
            creds_data = json.load(f)
        
        # Check if it's a web application
        if 'web' in creds_data:
            client_config = creds_data['web']
            # For web apps, we need to set the redirect URI properly
            if 'STREAMLIT_SHARING' in os.environ or 'STREAMLIT_CLOUD' in os.environ:
                # For Streamlit Cloud, use the actual redirect URI
                redirect_uri = f"https://{st.get_option('server.address')}/oauth2callback"
            else:
                # For local development, use localhost
                redirect_uri = f"http://localhost:{st.get_option('server.port')}/oauth2callback"
            
            # Create flow from client config
            flow = InstalledAppFlow.from_client_config(
                creds_data,  # Pass the entire credentials data
                scopes=scopes,
                redirect_uri=redirect_uri
            )
            
        # Check if it's an installed application
        elif 'installed' in creds_data:
            # For installed apps, use the standard flow
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, scopes)
            
            # Set redirect URI based on environment
            if 'STREAMLIT_SHARING' in os.environ or 'STREAMLIT_CLOUD' in os.environ:
                flow.redirect_uri = f"https://{st.get_option('server.address')}/oauth2callback"
            else:
                flow.redirect_uri = f"http://localhost:{st.get_option('server.port')}/oauth2callback"
                
        else:
            st.error("Invalid credentials format. Must be either 'web' or 'installed' type.")
            return None
        
        return flow
        
    except Exception as e:
        st.error(f"Failed to create OAuth flow: {str(e)}")
        return None
    
def authenticate_with_manual_code():
    """Alternative authentication method using manual code entry"""
    st.markdown("### Manual Authentication")
    st.info("Due to OAuth restrictions, please follow these steps to authenticate:")
    
    credentials_path = get_credentials_path()
    if not credentials_path:
        return False
    
    try:
        scopes = [
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/drive.file',
            'https://www.googleapis.com/auth/spreadsheets'
        ]
        
        # Create a flow with custom redirect
        flow = InstalledAppFlow.from_client_secrets_file(credentials_path, scopes)
        
        # Use the installed app flow which will open browser automatically
        # For Streamlit, we'll provide instructions instead
        auth_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        
        st.markdown(f"""
        **Step 1:** [Click here to authorize the application]({auth_url})
        
        **Step 2:** After authorization, you'll see a page that says "The authentication flow has completed."
        
        **Step 3:** Copy the authorization code from the URL bar (the part after 'code=') and paste it below:
        """)
        
        auth_code = st.text_input('Enter the authorization code:', type='password')
        
        if auth_code:
            try:
                # Exchange the code for credentials
                flow.fetch_token(code=auth_code)
                creds = flow.credentials
                
                # Save the credentials
                with open('token_combined.json', 'w') as token:
                    token.write(creds.to_json())
                
                return creds
            except Exception as e:
                st.error(f"Failed to exchange code for token: {str(e)}")
                return None
        
    except Exception as e:
        st.error(f"Authentication setup failed: {str(e)}")
        return None
    
    return None

def simple_authenticate():
    """Simplified authentication approach similar to the second app"""
    # First try to load existing token
    creds = load_existing_token()
    if creds:
        return creds
    
    # If no valid token, use manual authentication
    return authenticate_with_manual_code()

def authenticate_services():
    """Authenticate with Google APIs using simplified approach"""
    try:
        creds = simple_authenticate()
        
        if not creds:
            return False
        
        # Build services
        st.session_state.gmail_service = build('gmail', 'v1', credentials=creds)
        st.session_state.drive_service = build('drive', 'v3', credentials=creds)
        st.session_state.sheets_service = build('sheets', 'v4', credentials=creds)
        
        st.session_state.authenticated = True
        return True
        
    except Exception as e:
        st.error(f"Authentication failed: {str(e)}")
        return False

def sanitize_filename(filename: str) -> str:
    """Clean up filenames to be safe for all operating systems"""
    cleaned = re.sub(r'[<>:"/\\|?*]', '_', filename)
    if len(cleaned) > 100:
        name_parts = cleaned.split('.')
        if len(name_parts) > 1:
            extension = name_parts[-1]
            base_name = '.'.join(name_parts[:-1])
            cleaned = f"{base_name[:95]}.{extension}"
        else:
            cleaned = cleaned[:100]
    return cleaned

def classify_extension(filename: str) -> str:
    """Categorize file by extension"""
    if not filename or '.' not in filename:
        return "Other"
        
    ext = filename.split(".")[-1].lower()
    
    type_map = {
        "pdf": "PDFs",
        "doc": "Documents", "docx": "Documents", "txt": "Documents",
        "xls": "Spreadsheets", "xlsx": "Spreadsheets", "csv": "Spreadsheets",
        "jpg": "Images", "jpeg": "Images", "png": "Images", "gif": "Images",
        "ppt": "Presentations", "pptx": "Presentations",
        "zip": "Archives", "rar": "Archives", "7z": "Archives",
    }
    
    return type_map.get(ext, "Other")

def search_emails(sender: str, search_term: str, days_back: int, max_results: int, progress_container) -> List[Dict]:
    """Search for emails with attachments"""
    try:
        # Build search query
        query_parts = ["has:attachment"]
        
        if sender:
            query_parts.append(f'from:"{sender}"')
        
        if search_term:
            if "," in search_term:
                keywords = [k.strip() for k in search_term.split(",")]
                keyword_query = " OR ".join([f'"{k}"' for k in keywords if k])
                if keyword_query:
                    query_parts.append(f"({keyword_query})")
            else:
                query_parts.append(f'"{search_term}"')
        
        # Add date filter
        start_date = datetime.now() - timedelta(days=days_back)
        query_parts.append(f"after:{start_date.strftime('%Y/%m/%d')}")
        
        query = " ".join(query_parts)
        progress_container.info(f"Searching Gmail with query: {query}")
        
        # Execute search
        result = st.session_state.gmail_service.users().messages().list(
            userId='me', q=query, maxResults=max_results
        ).execute()
        
        messages = result.get('messages', [])
        progress_container.success(f"Found {len(messages)} emails matching criteria")
        
        return messages
        
    except Exception as e:
        progress_container.error(f"Email search failed: {str(e)}")
        return []

def create_drive_folder(folder_name: str, parent_folder_id: Optional[str] = None) -> str:
    """Create a folder in Google Drive"""
    try:
        # First check if folder already exists
        query = f"name='{folder_name}' and mimeType='application/vnd.google-apps.folder' and trashed=false"
        if parent_folder_id:
            query += f" and '{parent_folder_id}' in parents"
        
        existing = st.session_state.drive_service.files().list(q=query, fields='files(id, name)').execute()
        files = existing.get('files', [])
        
        if files:
            folder_id = files[0]['id']
            return folder_id
        
        # Create new folder
        folder_metadata = {
            'name': folder_name,
            'mimeType': 'application/vnd.google-apps.folder'
        }
        
        if parent_folder_id:
            folder_metadata['parents'] = [parent_folder_id]
        
        folder = st.session_state.drive_service.files().create(
            body=folder_metadata,
            fields='id'
        ).execute()
        
        folder_id = folder.get('id')
        return folder_id
        
    except Exception as e:
        st.error(f"Failed to create folder {folder_name}: {str(e)}")
        return ""

def upload_to_drive(file_data: bytes, filename: str, folder_id: str) -> bool:
    """Upload file to Google Drive"""
    try:
        # Check if file already exists
        query = f"name='{filename}' and '{folder_id}' in parents and trashed=false"
        existing = st.session_state.drive_service.files().list(q=query, fields='files(id, name)').execute()
        files = existing.get('files', [])
        
        if files:
            return True  # File already exists, skip
        
        file_metadata = {
            'name': filename,
            'parents': [folder_id] if folder_id else []
        }
        
        media = MediaIoBaseUpload(
            io.BytesIO(file_data),
            mimetype='application/octet-stream',
            resumable=True
        )
        
        file = st.session_state.drive_service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id'
        ).execute()
        
        return True
        
    except Exception as e:
        st.error(f"Failed to upload {filename}: {str(e)}")
        return False

def process_gmail_attachments(config: dict, progress_container) -> dict:
    """Process Gmail attachments and upload to Drive"""
    stats = {
        'total_emails': 0,
        'processed_emails': 0,
        'total_attachments': 0,
        'successful_uploads': 0,
        'failed_uploads': 0
    }
    
    try:
        # Search for emails
        emails = search_emails(
            config['sender'],
            config['search_term'],
            config['days_back'],
            config['max_results'],
            progress_container
        )
        
        stats['total_emails'] = len(emails)
        
        if not emails:
            progress_container.info("No emails found matching criteria")
            return stats
        
        # Create base folder in Drive
        base_folder_name = "Gmail_Attachments"
        base_folder_id = create_drive_folder(base_folder_name, config['gdrive_folder_id'])
        
        progress_container.info(f"Processing {len(emails)} emails...")
        
        # Create progress bar
        email_progress = st.progress(0)
        
        for i, email in enumerate(emails):
            try:
                # Update progress
                email_progress.progress((i + 1) / len(emails))
                progress_container.info(f"Processing email {i+1}/{len(emails)}")
                
                # Get full message
                message = st.session_state.gmail_service.users().messages().get(
                    userId='me', id=email['id']
                ).execute()
                
                if not message or not message.get('payload'):
                    continue
                
                # Get email details
                headers = message['payload'].get('headers', [])
                sender_info = {
                    'id': email['id'],
                    'sender': next((h['value'] for h in headers if h['name'] == "From"), "Unknown"),
                    'subject': next((h['value'] for h in headers if h['name'] == "Subject"), "(No Subject)"),
                    'date': next((h['value'] for h in headers if h['name'] == "Date"), "")
                }
                
                # Extract attachments recursively
                attachment_count = extract_attachments_from_email(
                    email['id'], message['payload'], sender_info, 
                    config['search_term'], base_folder_id, config['attachment_filter']
                )
                
                stats['total_attachments'] += attachment_count
                stats['successful_uploads'] += attachment_count
                stats['processed_emails'] += 1
                
            except Exception as e:
                progress_container.error(f"Failed to process email {email.get('id', 'unknown')}: {str(e)}")
                stats['failed_uploads'] += 1
        
        email_progress.progress(1.0)
        return stats
        
    except Exception as e:
        progress_container.error(f"Gmail processing failed: {str(e)}")
        return stats

def extract_attachments_from_email(message_id: str, payload: Dict, sender_info: Dict, 
                                 search_term: str, base_folder_id: str, attachment_filter: str) -> int:
    """Recursively extract all attachments from an email"""
    processed_count = 0
    
    # Process parts if they exist
    if "parts" in payload:
        for part in payload["parts"]:
            processed_count += extract_attachments_from_email(
                message_id, part, sender_info, search_term, base_folder_id, attachment_filter
            )
    
    # Process this part if it's an attachment
    elif payload.get("filename") and "attachmentId" in payload.get("body", {}):
        # Get filename
        filename = payload.get("filename", "")
        if not filename:
            return 0
        
        # Apply attachment filter
        if attachment_filter and filename.lower() != attachment_filter.lower():
            return 0
        
        try:
            # Clean filename
            clean_filename = sanitize_filename(filename)
            final_filename = f"{message_id}_{clean_filename}"

            # Get attachment data
            attachment_id = payload["body"].get("attachmentId")
            if not attachment_id:
                return 0
            
            att = st.session_state.gmail_service.users().messages().attachments().get(
                userId='me', messageId=message_id, id=attachment_id
            ).execute()
            
            if not att.get("data"):
                return 0
            
            # Decode file data
            file_data = base64.urlsafe_b64decode(att["data"].encode("UTF-8"))
            
            # Create folder structure
            search_folder_name = search_term if search_term else "all-attachments"
            file_type_folder = classify_extension(filename)
            
            # Create nested folder structure
            search_folder_id = create_drive_folder(search_folder_name, base_folder_id)
            type_folder_id = create_drive_folder(file_type_folder, search_folder_id)
            
            # Upload file
            success = upload_to_drive(file_data, final_filename, type_folder_id)
            
            if success:
                processed_count += 1
                
        except Exception as e:
            st.error(f"Failed to process attachment {filename}: {str(e)}")
    
    return processed_count

def main():
    """Main Streamlit app"""
    
    # Header
    st.markdown('<div class="main-header">Gmail to Drive Automation</div>', unsafe_allow_html=True)
    
    # Check authentication
    if not st.session_state.authenticated:
        st.markdown('<div class="info-message">Please authenticate with Google APIs to continue.</div>', unsafe_allow_html=True)
        
        # Check if we already have valid credentials
        creds = load_existing_token()
        if creds:
            # Build services with existing credentials
            try:
                st.session_state.gmail_service = build('gmail', 'v1', credentials=creds)
                st.session_state.drive_service = build('drive', 'v3', credentials=creds)
                st.session_state.sheets_service = build('sheets', 'v4', credentials=creds)
                st.session_state.authenticated = True
                st.rerun()
            except Exception as e:
                st.error(f"Failed to build services: {str(e)}")
        
        # Show authentication UI
        if st.button("Authenticate with Google", type="primary"):
            if authenticate_services():
                st.rerun()
        return
    
    st.markdown('<div class="success-message">✅ Successfully authenticated with Google APIs</div>', unsafe_allow_html=True)
    
    # Sidebar configuration
    st.sidebar.title("Configuration")
    
    # Display hardcoded configuration
    st.sidebar.markdown("### 📋 Fixed Configuration")
    
    with st.sidebar.expander("Gmail Settings (Read-only)", expanded=False):
        st.write(f"**Sender:** {HARDCODED_CONFIG['gmail']['sender']}")
        st.write(f"**Search Term:** {HARDCODED_CONFIG['gmail']['search_term']}")
        st.write(f"**Attachment Filter:** {HARDCODED_CONFIG['gmail']['attachment_filter']}")
        st.write(f"**Drive Folder ID:** {HARDCODED_CONFIG['gmail']['gdrive_folder_id']}")
    
    with st.sidebar.expander("Sheets Settings (Read-only)", expanded=False):
        st.write(f"**Drive Folder ID:** {HARDCODED_CONFIG['sheets']['drive_folder_id']}")
        st.write(f"**Llama Agent:** {HARDCODED_CONFIG['sheets']['llama_agent']}")
        st.write(f"**Spreadsheet ID:** {HARDCODED_CONFIG['sheets']['spreadsheet_id']}")
        st.write(f"**Sheet Range:** {HARDCODED_CONFIG['sheets']['sheet_range']}")
    
    st.sidebar.markdown("### ⚙️ Adjustable Settings")
    
    # User configurable settings
    gmail_days_back = st.sidebar.number_input(
        "Gmail: Days back to search",
        min_value=1, max_value=30, value=7,
        help="How many days back to search for emails"
    )
    
    gmail_max_results = st.sidebar.number_input(
        "Gmail: Max emails to process",
        min_value=1, max_value=1000, value=50,
        help="Maximum number of emails to process"
    )
    
    sheets_days_back = st.sidebar.number_input(
        "Sheets: Days back for PDFs",
        min_value=1, max_value=30, value=1,
        help="How many days back to fetch PDFs from Drive"
    )
    
    # Logout button
    if st.sidebar.button("🔓 Logout", type="secondary"):
        # Clear session state
        for key in ['gmail_service', 'drive_service', 'sheets_service', 'authenticated']:
            if key in st.session_state:
                del st.session_state[key]
        # Delete token file
        if os.path.exists('token_combined.json'):
            os.remove('token_combined.json')
        st.rerun()
    
    # Main content area
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 📧 Gmail to Drive")
        st.write("Fetch attachments from Gmail and upload to Google Drive")
        
        if st.button("Run Gmail to Drive", type="primary", disabled=st.session_state.processing):
            st.session_state.processing = True
            
            # Create progress container
            progress_container = st.empty()
            
            config = {
                **HARDCODED_CONFIG['gmail'],
                'days_back': gmail_days_back,
                'max_results': gmail_max_results
            }
            
            stats = process_gmail_attachments(config, progress_container)
            
            # Display results
            st.markdown("#### Results")
            col1a, col2a, col3a, col4a = st.columns(4)
            with col1a:
                st.metric("Total Emails", stats['total_emails'])
            with col2a:
                st.metric("Processed", stats['processed_emails'])
            with col3a:
                st.metric("Attachments", stats['total_attachments'])
            with col4a:
                st.metric("Uploaded", stats['successful_uploads'])
            
            st.session_state.processing = False
    
    with col2:
        st.markdown("### 📄 Drive to Sheets")
        st.write("Process PDFs from Drive using LlamaParse and save to Sheets")
        
        if not LLAMA_AVAILABLE:
            st.error("LlamaParse not available. Install with: pip install llama-cloud-services")
        
        if st.button("Run Drive to Sheets", type="primary", disabled=st.session_state.processing or not LLAMA_AVAILABLE):
            st.info("Drive to Sheets functionality would be implemented here")
            # The process_pdfs_to_sheets function would go here
    
    # Footer with updated instructions
    st.markdown("---")
    st.markdown("### 📚 Updated Setup Instructions")
    
    with st.expander("OAuth2 Setup", expanded=False):
        st.markdown("""
        **Updated OAuth2 Configuration:**
        
        1. **Google Cloud Console Setup:**
           - Go to [Google Cloud Console](https://console.cloud.google.com/)
           - Create a new project or select existing one
           - Enable Gmail API, Google Drive API, and Google Sheets API
        
        2. **OAuth2 Credentials:**
           - Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client ID"
           - Choose "Desktop Application" as application type
           - Download the JSON file and place it at the specified path
        
        3. **For Local Development:**
           - The app will automatically open your browser for authentication
           - Follow the prompts and grant permissions
           - The token will be saved for future use
        
        4. **For Streamlit Cloud:**
           - Convert your credentials JSON to Streamlit secrets format
           - The manual authentication flow will be used
        """)

if __name__ == "__main__":
    main()