import imaplib
import email
from email.policy import default
import re
from typing import List
from models.email import EmailData, EmailHeader

def extract_email_address(addr: str) -> str:
    """
    Helper function to extract just the email address from a string like 'Name <email@example.com>'.
    """
    if not addr:
        return "unknown@unknown.com"
    match = re.search(r'<([^>]+)>', addr)
    return match.group(1) if match else addr.strip()

def fetch_emails_via_imap(imap_server: str, username: str, password: str, folder: str = "inbox", limit: int = 10) -> List[EmailData]:
    """
    Connects to an IMAP server, fetches recent emails, and parses their headers and bodies 
    into a structured list of EmailData Pydantic models.
    """
    emails_data = []
    mail = None
    
    try:
        # Connect to the IMAP server over SSL
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(username, password)
        mail.select(folder)

        # Search for all emails in the selected folder
        status, messages = mail.search(None, "ALL")
        if status != "OK":
            print(f"Failed to search folder {folder} or no messages found.")
            return emails_data

        # Get the list of email IDs and take the most recent ones up to the limit
        email_ids = messages[0].split()
        latest_email_ids = email_ids[-limit:]

        # Iterate over emails in reverse order (newest first)
        for e_id in reversed(latest_email_ids):
            status, msg_data = mail.fetch(e_id, "(RFC822)")
            if status != "OK":
                continue

            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    # Parse the raw email bytes into an EmailMessage object
                    msg = email.message_from_bytes(response_part[1], policy=default)
                    
                    # Extract standard email headers
                    headers = [EmailHeader(name=k, value=str(v)) for k, v in msg.items()]
                    
                    subject = msg.get("Subject", "")
                    sender = msg.get("From", "")
                    recipient = msg.get("To", "")
                    message_id = msg.get("Message-ID", "")
                    date_ = msg.get("Date", "")
                    
                    body_text = ""
                    body_html = ""
                    
                    # Parse the email body
                    if msg.is_multipart():
                        # Iterate over email parts (e.g., text, HTML, attachments)
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            content_disposition = str(part.get("Content-Disposition"))
                            
                            # Skip attachments for plain text / HTML extraction
                            if "attachment" not in content_disposition:
                                try:
                                    payload = part.get_payload(decode=True)
                                    if payload:
                                        charset = part.get_content_charset() or 'utf-8'
                                        decoded_payload = payload.decode(charset, errors="replace")
                                        if content_type == "text/plain":
                                            body_text += decoded_payload
                                        elif content_type == "text/html":
                                            body_html += decoded_payload
                                except Exception as e:
                                    print(f"Error decoding multipart payload: {e}")
                    else:
                        # Handle non-multipart emails
                        content_type = msg.get_content_type()
                        try:
                            payload = msg.get_payload(decode=True)
                            if payload:
                                charset = msg.get_content_charset() or 'utf-8'
                                decoded_payload = payload.decode(charset, errors="replace")
                                if content_type == "text/plain":
                                    body_text = decoded_payload
                                elif content_type == "text/html":
                                    body_html = decoded_payload
                        except Exception as e:
                            print(f"Error decoding payload: {e}")
                            
                    # Construct and validate using our Pydantic model
                    email_data = EmailData(
                        message_id=message_id,
                        sender_email=extract_email_address(sender),
                        recipient_email=extract_email_address(recipient),
                        subject=subject,
                        body_text=body_text.strip(),
                        body_html=body_html.strip() if body_html else None,
                        headers=headers,
                        timestamp=date_
                    )
                    
                    emails_data.append(email_data)
                    
    except Exception as e:
        print(f"An IMAP error occurred: {e}")
        
    finally:
        # Ensure we gracefully close the connection
        if mail:
            try:
                mail.close()
                mail.logout()
            except Exception:
                pass
            
    return emails_data
