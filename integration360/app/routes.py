from flask import render_template, redirect, url_for, request, jsonify, session, flash
from flask_login import login_user, logout_user, current_user, login_required
from app import app
from app.db import connect_db
from app.forms import KnowledgeForm, LoginForm
from app.forms import TicketDetailsForm
from app.models import User
import sqlite3
import base64
import requests
from werkzeug.utils import secure_filename
from flask import abort
from flask import send_from_directory
from config import Config
from app.models import User
import io
import csv
from datetime import datetime
from flask import make_response
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from werkzeug.security import generate_password_hash, check_password_hash
import random
import datetime

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.forms import QueryForm
from dotenv import load_dotenv
import os
import psycopg2

load_dotenv()

# ✅ Login Route (Main Page)
@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('welcome_admin'))
        else:
            return redirect(url_for('welcome_user'))  # Redirect users to welcome page

    form = LoginForm()
    error = None
    success = None

    next_page = request.args.get('next')

    if form.validate_on_submit():
        conn = connect_db()
        c = conn.cursor()
        c.execute('SELECT id, username, password, role FROM users WHERE username = %s', (form.username.data,))
        user_data = c.fetchone()
        conn.close()

        if user_data and check_password_hash(user_data[2], form.password.data):
            # Password correct -> Generate OTP
            otp = str(random.randint(100000, 999999))
            otp_created_at = datetime.datetime.now()

            conn = connect_db()
            c = conn.cursor()
            c.execute('UPDATE users SET otp = %s, otp_created_at = %s WHERE id = %s', (otp, otp_created_at, user_data[0]))
            conn.commit()
            conn.close()

            # Save in session to verify later
            session['otp_user_id'] = user_data[0]

            send_email_otp(form.username.data, otp)
            flash("An OTP has been sent to your email address. Please verify.", "info")
            return redirect(url_for('verify_otp'))

        else:
            error = "Invalid username or password!"

    return render_template('login.html', form=form, error=error, success=success)



@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp_user_id' not in session:
        flash("Session expired. Please login again.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        input_otp = request.form.get('otp')

        conn = connect_db()
        c = conn.cursor()
        c.execute('SELECT id, username, role, otp, otp_created_at FROM users WHERE id = %s', (session['otp_user_id'],))
        user_data = c.fetchone()
        conn.close()

        if not user_data:
            flash("User not found. Please login again.", "danger")
            return redirect(url_for('login'))

        if user_data[3] == input_otp:
            # OTP matched
            user = User(id=user_data[0], username=user_data[1], role=user_data[2])
            login_user(user)
            session.pop('otp_user_id', None)

            flash("Login successful!", "success")
            if user.role == 'admin':
                return redirect(url_for('welcome_admin'))
            else:
                return redirect(url_for('welcome_user'))
        else:
            flash("Invalid OTP. Please try again.", "danger")

    return render_template('verify_otp.html')



# ✅ Home Page After Login
@app.route('/index')
@login_required  # ✅ Protecting the home page
def index():
    print("🔥 Current User:", current_user.role)  # Debugging line
    if current_user.role != 'admin':  # Redirect if user1 tries to access index
        #print(url_for('ticket_details'))
        return redirect(url_for('ticket_details'))
    form = KnowledgeForm()
    return render_template('welcome_admin.html', form=form)




# ✅ Logout Route (Clears Session)
@app.route('/logout')
@login_required  # ✅ Prevents logout without login
def logout():
    logout_user()
    session.clear()  # ✅ Clears token session
    return render_template('logout.html')  # ✅ Show confirmation box before redirecting


#DATABASE = os.path.join(os.getcwd(), "knowledge_crm.db")







# Modify init_db() function in routes.py
def init_db():
    with connect_db() as conn:
        c = conn.cursor()

        # New table for ticket details
        c.execute('''
            CREATE TABLE IF NOT EXISTS ticket_details (
                id SERIAL PRIMARY KEY,
                ticket_id VARCHAR UNIQUE,
                cf_merchant_id VARCHAR,
                cf_contact_number VARCHAR,
                cf_product VARCHAR,
                cf_platform VARCHAR,
                cf_platform_item VARCHAR,
                cf_checkout VARCHAR,
                cf_issue_category VARCHAR,
                cf_issue_sub_category VARCHAR,
                description_text TEXT,
                cf_agent_category VARCHAR,
                cf_agent_sub_category VARCHAR,
                submitted_by VARCHAR,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR DEFAULT 'pending'
            )
        ''')

        # Table: knowledge_entries
        c.execute('''
            CREATE TABLE IF NOT EXISTS knowledge_entries (
                id SERIAL PRIMARY KEY,
                type VARCHAR,
                category VARCHAR,
                question TEXT,
                answer TEXT,
                attachment VARCHAR,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Table: fetched_tickets
        c.execute('''
            CREATE TABLE IF NOT EXISTS fetched_tickets (
                id INTEGER PRIMARY KEY,
                cf_merchant_id VARCHAR,
                cf_contact_number VARCHAR,
                cf_product VARCHAR,
                cf_platform VARCHAR,
                cf_platform_item VARCHAR,
                cf_checkout VARCHAR,
                cf_issue_category VARCHAR,
                cf_issue_sub_category VARCHAR,
                description_text TEXT,
                cf_agent_category VARCHAR,
                cf_agent_sub_category VARCHAR,
                resolution TEXT,
                workaround TEXT,
                comments TEXT,
                status VARCHAR,
                last_fetched TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                cf_kb_required VARCHAR
            )
        ''')

        # Table: kb_submissions
        c.execute('''
            CREATE TABLE IF NOT EXISTS kb_submissions (
                id SERIAL PRIMARY KEY,
                industry VARCHAR,
                checkout_type VARCHAR,
                product_name VARCHAR,
                about_merchant TEXT,
                use_case TEXT,
                business_challenges TEXT,
                challenges TEXT,
                proposed_solution TEXT,
                impact TEXT,
                attachment VARCHAR,
                comments TEXT DEFAULT '',
                status VARCHAR DEFAULT 'pending',
                submitted_by VARCHAR,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Table: kb_approved
        c.execute('''
            CREATE TABLE IF NOT EXISTS kb_approved (
                id SERIAL PRIMARY KEY,
                industry VARCHAR,
                checkout_type VARCHAR,
                product_name VARCHAR,
                about_merchant TEXT,
                use_case TEXT,
                business_challenges TEXT,
                challenges TEXT,
                proposed_solution TEXT,
                impact TEXT,
                attachment VARCHAR,
                approved_by VARCHAR,
                approved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Table: users
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR UNIQUE NOT NULL,
                password VARCHAR NOT NULL,
                role VARCHAR NOT NULL,
                otp VARCHAR,
                otp_created_at TIMESTAMP
            )
        ''')

        # Table: query_entries
        c.execute('''
            CREATE TABLE IF NOT EXISTS query_entries (
                id SERIAL PRIMARY KEY,
                product VARCHAR,
                query TEXT,
                resolution TEXT,
                workaround TEXT,
                submitted_by VARCHAR,
                submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR DEFAULT 'pending',
                comments TEXT DEFAULT ''
            )
        ''')

        c.execute('''
                    CREATE TABLE IF NOT EXISTS user_ticket_stats (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR NOT NULL,
                    resolved INTEGER DEFAULT 0,
                    not_resolved INTEGER DEFAULT 0,
                    create_ticket INTEGER DEFAULT 0,
                    dropped INTEGER DEFAULT 0,
                    type VARCHAR NOT NULL,
                    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                  ''')

        conn.commit()



# Call init_db() when the app starts
init_db()


UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "doc", "docx", "txt"}


# Ensure the upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    print(f"🔥 Checking file extension: {ext}")  # Debugging line
    return ext in ALLOWED_EXTENSIONS





SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = 'ayush.sisodia@razorpay.com'   # your Gmail ID
SMTP_PASSWORD = 'elzsebwvqdynotzu'      # Gmail App Password (not your normal password)
FROM_EMAIL = 'ayush.sisodia@razorpay.com'


def send_email_otp(to_email, otp):
    try:
        msg = MIMEMultipart()
        msg['From'] = FROM_EMAIL
        msg['To'] = to_email
        msg['Subject'] = 'Your OTP for Login Verification'

        body = f"Your OTP is: {otp}\nPlease use this OTP to complete your login."
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()

        print(f"✅ OTP email sent successfully to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send OTP email: {e}")




@app.route('/submit_knowledge', methods=['POST'])
@login_required
def submit_knowledge():
    print("🔥 Incoming request to /submit_knowledge")  # Debugging log

    form = KnowledgeForm()

    print("📌 Raw Form Data (Before Validation):", request.form)

    if form.validate_on_submit():
        print("✅ Form validation successful")
        print("📌 Submitted Type Value:", form.type.data)  # Debugging
    else:
        print("❌ Form validation failed!")
        print("🚨 Validation errors:", form.errors)
    
    if form.validate_on_submit():
        print("✅ Form validation successful")  # Debugging log
        file_path = None

        if "attachment" in request.files:
            file = request.files["attachment"]
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                file.save(file_path)

        try:
            conn = connect_db()
            c = conn.cursor()

            print("🔥 Checking for duplicate question in DB...")
            c.execute("SELECT 1 FROM knowledge_entries WHERE question = %s", (form.question.data,))
            if c.fetchone():
                flash("⚠️ This question already exists!", "warning")
                print("⚠️ Duplicate question found!")
            else:
                print("✅ Inserting new entry into DB...")
                insert_query = '''
                    INSERT INTO knowledge_entries (type, category, question, answer, attachment)
                    VALUES (%s, %s, %s, %s, %s)
                '''
                c.execute(insert_query, (form.type.data, form.category.data, form.question.data, form.answer.data, file_path))
                conn.commit()
                flash("✅ Knowledge entry submitted successfully!", "success")
                print("🚀 Successfully inserted into DB!")
        except Exception as e:
            print(f"❌ Error inserting into DB: {str(e)}")
            flash(f"❌ Error: {str(e)}", "danger")
        finally:
            conn.close()
    
    else:
        print("❌ Form validation failed!")  # Debugging log

    
    if not form.validate_on_submit():
        print("❌ Form validation failed!")
        print("🚨 Validation errors:", form.errors)  # Print errors to the console
        flash("⚠️ Form validation failed!", "danger")
        return redirect(url_for('index'))
    
    return redirect(url_for('index'))





# New ticket submission route
@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit_ticket():
    if current_user.role != 'user':
        abort(403)

    form = TicketDetailsForm()
    if request.method == 'GET':
        success = fetch_freshdesk_tickets()
        if not success:
            print('Failed to refresh tickets from API', 'warning')
    
    print("Form submitted:", request.method)  # Debugging: Check if form is submitted
    print("Form errors:", form.errors)
    if form.validate_on_submit():
        print("Form Data:", form.data)
        try:
            conn = connect_db()
            c = conn.cursor()
            c.execute('''
                INSERT INTO ticket_details 
                (ticket_id, cf_merchant_id, cf_contact_number, cf_product, cf_platform, cf_platform_item, cf_checkout, cf_issue_category, cf_issue_sub_category, description_text, cf_agent_category, cf_agent_sub_category, submitted_by, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                form.ticket_id.data,
                form.cf_merchant_id.data,
                form.cf_contact_number.data,
                form.cf_product.data,
                form.cf_platform.data,
                form.cf_platform_item.data,
                form.cf_checkout.data,
                form.cf_issue_category.data,
                form.cf_issue_sub_category.data,
                form.description_text.data,
                form.cf_agent_category.data,
                form.cf_agent_sub_category.data,
                current_user.role,
                'pending'
            ))
            conn.commit()
            flash('KB submitted successfully!', 'success')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')
        finally:
            conn.close()
    return render_template('submit.html', form=form)




@app.route('/requests')
@login_required
def get_requests():
    if current_user.role != 'admin':
        abort(403)
    
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute('SELECT * FROM user_data')
        tickets = c.fetchall()
    except Exception as e:
        print(f"Error fetching data: {e}")
        tickets = []
    finally:
        conn.close()
    
    return render_template('requests.html', tickets=tickets)



@app.route('/tickets', methods=['GET', 'POST'])
@login_required
def ticket_details():
    form = TicketDetailsForm()

    conn = connect_db()
    c = conn.cursor()
    c.execute('SELECT id FROM fetched_tickets WHERE cf_kb_required = %s', ('Yes',))
    form.ticket_id.choices = [("", "Select a ticket")] + [(str(t[0]), str(t[0])) for t in c.fetchall()]

    conn.close()

    if form.validate_on_submit():
        try:
            conn = connect_db()
            c = conn.cursor()
            
            c.execute('''
                INSERT INTO ticket_details 
                (ticket_id, cf_merchant_id, cf_contact_number, cf_product, cf_platform, cf_platform_item, cf_checkout, cf_issue_category, cf_issue_sub_category, description_text, cf_agent_category, cf_agent_sub_category, resolution, workaround, submitted_by, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (ticket_id) DO UPDATE SET
                    cf_merchant_id = EXCLUDED.cf_merchant_id,
                    cf_contact_number = EXCLUDED.cf_contact_number,
                    cf_product = EXCLUDED.cf_product,
                    cf_platform = EXCLUDED.cf_platform,
                    cf_platform_item = EXCLUDED.cf_platform_item,
                    cf_checkout = EXCLUDED.cf_checkout,
                    cf_issue_category = EXCLUDED.cf_issue_category,
                    cf_issue_sub_category = EXCLUDED.cf_issue_sub_category,
                    description_text = EXCLUDED.description_text,
                    cf_agent_category = EXCLUDED.cf_agent_category,
                    cf_agent_sub_category = EXCLUDED.cf_agent_sub_category,
                    resolution = EXCLUDED.resolution,
                    workaround = EXCLUDED.workaround,
                    submitted_by = EXCLUDED.submitted_by,
                    status = EXCLUDED.status
            ''', (
                form.ticket_id.data,
                form.cf_merchant_id.data,
                form.cf_contact_number.data,
                form.cf_product.data,
                form.cf_platform.data,
                form.cf_platform_item.data,
                form.cf_checkout.data,
                form.cf_issue_category.data,
                form.cf_issue_sub_category.data,
                form.issue_description.data,
                form.cf_agent_category.data,
                form.cf_agent_sub_category.data,
                form.resolution.data,
                form.workaround.data,
                current_user.role,
                'pending',
            ))
            
            conn.commit()
            print('KB details submitted successfully!')
            return jsonify({'success': True, 'redirect': url_for('ticket_details')})
        except psycopg2.IntegrityError:
            return jsonify({
                'success': False, 
                'error': 'Ticket ID already exists!'
            }), 400
        except Exception as e:
            return jsonify({
                'success': False, 
                'error': str(e)
            }), 500
        finally:
            conn.close()
    
    return render_template('ticket_details.html', form=form)

@app.route('/ticket_requests')
@login_required
def ticket_requests():
    if current_user.role != 'admin':
        abort(403)
    
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute('SELECT * FROM ticket_details WHERE status = %s', ('pending',))
        tickets = c.fetchall()
    except Exception as e:
        print(f"Error fetching data: {e}")
        tickets = []
    finally:
        conn.close()
    
    return render_template('ticket_requests.html', tickets=tickets)

@app.route('/approve_ticket/<int:ticket_id>', methods=['POST'])
@login_required
def approve_ticket(ticket_id):
    if current_user.role != 'admin':
        abort(403)
    
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute('UPDATE ticket_details SET status = %s WHERE id = %s', ('approved', ticket_id))
        conn.commit()
        flash('KB approved successfully!', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return jsonify({'success': True, 'redirect': url_for('ticket_requests')})

@app.route('/decline_ticket/<int:id>', methods=['POST'])
@login_required
def decline_ticket(id):
    if current_user.role != 'admin':
        abort(403)
    
    try:
        conn = connect_db()
        c = conn.cursor()
        print(f"📌 Searching for id: {id} (type: {type(id)})")
        c.execute('SELECT * FROM ticket_details WHERE id = %s', (id,))
        ticket = c.fetchone()

        if not ticket:
            print(f"❌ Ticket with ID {id} not found in DB")
            return jsonify({'success': False, 'error': 'Ticket not found'}), 404
        
        tid = ticket[1]
        comments = request.form.get('comments', '').strip()

        print(ticket)

        # Update the ticket details instead of deleting
        c.execute('''
            UPDATE ticket_details
            SET comments = %s
            WHERE id = %s
        ''', (comments, id))

        conn.commit()
        
        # Also update the fetched_tickets table with comments
        c.execute('''
            UPDATE fetched_tickets
            SET comments = %s
            WHERE id = %s
        ''', (comments, tid))

        conn.commit()
        
        print(f"✅ Updated ticket {id} with comments: {comments}")
        return jsonify({'success': True, 'redirect': url_for('ticket_requests')})
        
    except Exception as e:
        print(f"❌ Error updating ticket: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        conn.close()
        
    

@app.route('/get_ticket_data/<int:ticket_id>')
@login_required
def get_ticket_data(ticket_id):
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute('SELECT * FROM fetched_tickets WHERE id = %s', (ticket_id,))
        ticket = c.fetchone()
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()
    
    if ticket:
        return jsonify({
            'cf_merchant_id': ticket[1],
            'cf_contact_number': ticket[2],
            'cf_product': ticket[3],
            'cf_platform': ticket[4],
            'cf_platform_item': ticket[5],
            'cf_checkout': ticket[6],
            'cf_issue_category': ticket[7],
            'cf_issue_sub_category': ticket[8],
            'issue_description': ticket[9],
            'cf_agent_category': ticket[10],
            'cf_agent_sub_category': ticket[11],
            'resolution': ticket[12],
            'workaround': ticket[13],
            'comments': ticket[14],
            'status': ticket[15]
        })
    return jsonify({'error': 'Ticket not found'}), 404

@app.route('/get_ticket_details/<int:ticket_id>')
@login_required
def get_ticket_details(ticket_id):
    if current_user.role != 'admin':
        abort(403)
    
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute('SELECT * FROM ticket_details WHERE id = %s', (ticket_id,))
        ticket = c.fetchone()
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()
    
    if ticket:
        return jsonify({
            'ticket_id': ticket[0],  # Assuming ticket ID is the first column
            'merchant_id': ticket[1],
            'contact_number': ticket[2],
            'product': ticket[3],
            'platform': ticket[4],
            'platform_item': ticket[5],
            'checkout': ticket[6],
            'issue_category': ticket[7],
            'issue_subcategory': ticket[8],
            'issue_description': ticket[9],
            'agent_category': ticket[10],
            'agent_subcategory': ticket[11],
            'resolution': ticket[12], 
            'workaround': ticket[13],
            'comments': ticket[14]
        })
    return jsonify({'error': 'Ticket not found'}), 404


def fetch_freshdesk_tickets():
    conn = None
    auth_string = os.getenv('auth_string')
    auth = base64.b64encode(auth_string.encode()).decode()
    headers = {
        "Authorization": f"Basic {auth}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(
            os.getenv('fetch_ticket_api_url'),
            headers=headers
        )
        response.raise_for_status()
        tickets = response.json().get('results', [])
        
        conn = connect_db()
        c = conn.cursor()
        
        for ticket in tickets:
            custom_fields = ticket.get('custom_fields', {})
            c.execute('''
                INSERT INTO fetched_tickets (
                    id, cf_merchant_id, cf_contact_number, cf_product, 
                    cf_platform, cf_platform_item, cf_checkout, 
                    cf_issue_category, cf_issue_sub_category, 
                    description_text, cf_agent_category, cf_agent_sub_category, status, cf_kb_required
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE 
                SET cf_merchant_id = EXCLUDED.cf_merchant_id,
                    cf_contact_number = EXCLUDED.cf_contact_number,
                    cf_product = EXCLUDED.cf_product,
                    cf_platform = EXCLUDED.cf_platform,
                    cf_platform_item = EXCLUDED.cf_platform_item,
                    cf_checkout = EXCLUDED.cf_checkout,
                    cf_issue_category = EXCLUDED.cf_issue_category,
                    cf_issue_sub_category = EXCLUDED.cf_issue_sub_category,
                    description_text = EXCLUDED.description_text,
                    cf_agent_category = EXCLUDED.cf_agent_category,
                    cf_agent_sub_category = EXCLUDED.cf_agent_sub_category,
                    status = EXCLUDED.status,
                    cf_kb_required = EXCLUDED.cf_kb_required
            ''', (
                ticket['id'],
                custom_fields.get('cf_merchant_id'),
                custom_fields.get('cf_contact_number'),
                custom_fields.get('cf_product'),
                custom_fields.get('cf_platform'),
                custom_fields.get('cf_platform_item'),
                custom_fields.get('cf_checkout'),
                custom_fields.get('cf_issue_category'),
                custom_fields.get('cf_issue_sub_category'),
                ticket.get('description_text'),
                custom_fields.get('cf_new_category'),
                custom_fields.get('cf_new_sub_category'),
                ticket.get('status'),
                custom_fields.get('cf_kb_required')
            ))

        conn.commit()
        return True
    except Exception as e:
        print(f"Error fetching tickets: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()



fetch_freshdesk_tickets()

@app.route('/get_tickets_data/<int:ticket_id>')
@login_required
def get_tickets_data(ticket_id):
    conn = connect_db()
    c = conn.cursor()
    c.execute('SELECT * FROM ticket_details WHERE id = %s', (ticket_id,))
    ticket = c.fetchone()
    conn.close()

    if ticket:
        return jsonify({
            'comments': ticket[5]  # Adjust the index based on the actual column position
        })
    return jsonify({'error': 'Ticket not found'}), 404


@app.route('/approved_tickets')
@login_required
def approved_tickets():
    status_filter = request.args.get('status_filter', 'all')
    
    conn = connect_db()
    c = conn.cursor()

    query = '''
        SELECT * FROM ticket_details 
        WHERE submitted_by = %s
    '''
    params = [current_user.role]
    
    if status_filter != 'all':
        query += ' AND status = %s'
        params.append(status_filter)
    else:
        # Show both approved and pending tickets when 'all' is selected
        query += ' AND (status = %s OR status = %s)'
        params.extend(['approved', 'pending'])
    
    # Add sorting
    query += ' ORDER BY submitted_at DESC'
    
    c.execute(query, params)

    tickets = c.fetchall()
    conn.close()
    
    return render_template('approved_tickets_user.html', tickets=tickets, status_filter=status_filter)

@app.route('/approved_tickets_admin')
@login_required
def approved_tickets_admin():
    if current_user.role != 'admin':
        abort(403)

    status_filter = request.args.get('status_filter', default='all')
    user_filter = request.args.get('user_filter', default='')

    conn = connect_db()
    c = conn.cursor()
    
    query = 'SELECT * FROM ticket_details WHERE 1=1'
    params = []
    
    if status_filter != 'all':
        query += ' AND status = %s'
        params.append(status_filter)
    
    if user_filter:
        query += ' AND submitted_by LIKE %s'
        params.append(f'%{user_filter}%')
    
    query += ' ORDER BY submitted_at DESC'
    
    c.execute(query, params)

    tickets = c.fetchall()
    conn.close()
    
    return render_template('approved_tickets.html', tickets=tickets, status_filter=status_filter, user_filter=user_filter)


@app.route('/get_tickets_details/<int:ticket_id>')
@login_required
def get_tickets_details(ticket_id):
    conn = connect_db()
    c = conn.cursor()

    # Use %s for parameterized queries with PostgreSQL
    c.execute('SELECT * FROM ticket_details WHERE id = %s', (ticket_id,))
    ticket = c.fetchone()
    conn.close()

    if ticket:
        return jsonify({
            'ticket_id': ticket[0],  
            'cf_merchant_id': ticket[1],       
            'cf_contact_number': ticket[2],     
            'cf_product': ticket[3],
            'cf_platform': ticket[4],
            'cf_platform_item': ticket[5],
            'cf_checkout': ticket[6],
            'cf_issue_category': ticket[7],
            'cf_issue_sub_category': ticket[8],
            'description_text': ticket[9],    
            'cf_agent_category': ticket[10],
            'cf_agent_sub_category': ticket[11],
            'resolution': ticket[12], 
            'workaround': ticket[13],
            'comments': ticket[14],
            'status': ticket[15],
            'submitted_by': ticket[16],
            'submitted_at': ticket[17]
        })
    return jsonify({'error': 'Ticket not found'}), 404


@app.route('/user_pending_tickets')
@login_required
def user_pending_tickets():
    if current_user.role == 'admin':
        abort(403)  # Only for regular users
    
    conn = connect_db()
    c = conn.cursor()
    
    # Get pending tickets for the current user only
    c.execute('''
        SELECT * FROM ticket_details 
        WHERE submitted_by = %s AND status = 'pending'
        ORDER BY submitted_at DESC
    ''', (current_user.role,))
    
    tickets = c.fetchall()
    conn.close()
    
    return render_template('user_pending_tickets.html', tickets=tickets)


@app.route('/update_pending_ticket', methods=['POST'])
@login_required
def update_pending_ticket():
    if current_user.role == 'admin':
        abort(403)  # Only for regular users
    
    try:
        conn = connect_db()
        c = conn.cursor()
        
        ticket_id = request.form.get('ticket_id')
        print(ticket_id)
        
        # Verify the ticket belongs to the current user and is pending
        c.execute('''
            SELECT id FROM ticket_details 
            WHERE id = %s AND submitted_by = %s AND status = 'pending'
        ''', (ticket_id, current_user.role))
        
        if not c.fetchone():
            return jsonify({'success': False, 'error': 'Ticket not found or not editable'}), 404
        
        # Update the ticket
        c.execute('''
            UPDATE ticket_details 
                SET resolution = %s,
                    workaround = %s,
                    description_text = %s
                WHERE id = %s
        ''', (
            request.form.get('resolution'),
            request.form.get('workaround'),
            request.form.get('issue_description'),
            ticket_id
        ))
        
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        conn.close()


# KB Submission Route
@app.route('/submit_kb', methods=['GET', 'POST'])
@login_required
def submit_kb():
    form = KnowledgeForm()
    if request.method == 'POST':
        try:
            file_path = None
            if 'attachment' in request.files:
                file = request.files['attachment']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(file_path)

            conn = connect_db()
            c = conn.cursor()

            product_names = request.form.getlist('product_name')
            product_names_str = ','.join(product_names)

            c.execute('''
                INSERT INTO kb_submissions 
                (industry, checkout_type, product_name, about_merchant, use_case, business_challenges, challenges, proposed_solution, impact, attachment, submitted_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                form.industry.data,
                form.checkout_type.data,
                product_names_str,
                request.form.get('about_merchant'),
                request.form.get('use_case'),
                request.form.get('business_challenges'),
                request.form.get('challenges'),
                request.form.get('proposed_solution'),
                request.form.get('impact'),  
                file_path,
                current_user.role
            ))
            conn.commit()
            return jsonify({"success": True, "message": "Case Study submitted successfully!"})
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Error: {str(e)}'
            }), 500
    
    return render_template('knowledge_form.html', form=form)


# Pending KBs for User
@app.route('/user_pending_kbs')
@login_required
def user_pending_kbs():
    # Get filter parameters from request
    status_filter = request.args.get('status_filter', 'all')
    industry_filter = request.args.get('industry_filter', 'all')
    product_filter = request.args.get('product_filter', 'all')

    conn = connect_db()
    c = conn.cursor()

    # Base query for user's KBs
    query = '''
        SELECT * FROM kb_submissions 
        WHERE submitted_by = %s
    '''
    params = [current_user.role]

    # Apply filters
    if status_filter != 'all':
        query += ' AND status = %s'
        params.append(status_filter)
    
    if industry_filter != 'all':
        query += ' AND industry = %s'
        params.append(industry_filter)
    
    if product_filter != 'all':
        query += ' AND product_name = %s'
        params.append(product_filter)

    query += ' ORDER BY submitted_at DESC'
    
    c.execute(query, params)
    kbs = c.fetchall()

    # Get distinct values for filters
    c.execute('''
        SELECT DISTINCT status FROM kb_submissions 
        WHERE submitted_by = %s AND status IS NOT NULL
    ''', (current_user.role,))
    statuses = [row[0] for row in c.fetchall()]

    c.execute('''
        SELECT DISTINCT industry FROM kb_submissions 
        WHERE submitted_by = %s AND industry IS NOT NULL
    ''', (current_user.role,))
    industries = [row[0] for row in c.fetchall()]

    c.execute('''
        SELECT DISTINCT product_name FROM kb_submissions 
        WHERE submitted_by = %s AND product_name IS NOT NULL
    ''', (current_user.role,))
    products = [row[0] for row in c.fetchall()]

    conn.close()

    return render_template('user_pending_kbs.html', 
                         kbs=kbs,
                         statuses=statuses,
                         industries=industries,
                         products=products,
                         status_filter=status_filter,
                         industry_filter=industry_filter,
                         product_filter=product_filter)


# Admin KB Approval
@app.route('/admin_pending_kbs')
@login_required
def admin_pending_kbs():
    if current_user.role != 'admin':
        abort(403)
    
    conn = connect_db()
    c = conn.cursor()
    
    # Fetch all pending KB submissions
    c.execute('SELECT * FROM kb_submissions WHERE status = %s', ('pending',))
    kbs = c.fetchall()
    
    conn.close()
    
    return render_template('admin_pending_kbs.html', kbs=kbs)


# KB Approval Handler
@app.route('/approve_kb/<int:kb_id>', methods=['POST'])
@login_required
def approve_kb(kb_id):
    if current_user.role != 'admin':
        abort(403)
    
    try:
        conn = connect_db()
        c = conn.cursor()
        comments = request.form.get('comments', '')
        
        # Get KB details
        c.execute('SELECT * FROM kb_submissions WHERE id = %s', (kb_id,))
        kb = c.fetchone()
        
        # Insert into approved table
        c.execute('''
            INSERT INTO kb_approved 
            (industry, checkout_type, product_name,
             about_merchant, use_case, business_challenges,
             challenges, proposed_solution, impact,
             attachment, approved_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            kb[1], kb[2], kb[3],  # industry, checkout_type, product_name
            kb[4], kb[5], kb[6],   # about_merchant, use_case, business_challenges
            kb[7], kb[8], kb[9],   # challenges, proposed_solution, impact
            kb[10],                 # attachment
            current_user.role
        ))
        
        # Update submission status
        c.execute('UPDATE kb_submissions SET status = %s WHERE id = %s', ('approved', kb_id))
        conn.commit()
        return jsonify({'success': True, 'message': 'Case Study approved successfully!'})
    except Exception as e:
        return jsonify({
            'success': False, 
            'error': str(e)
        }), 500
    finally:
        conn.close()


# KB Decline Handler
@app.route('/decline_kb/<int:kb_id>', methods=['POST'])
@login_required
def decline_kb(kb_id):
    if current_user.role != 'admin':
        abort(403)
    
    try:
        conn = connect_db()
        c = conn.cursor()
        comments = request.form.get('comments', '')
        
        c.execute('''
            UPDATE kb_submissions 
            SET comments = %s
            WHERE id = %s
        ''', (comments, kb_id))
        conn.commit()
        return jsonify({'success': True, 'message': 'KB returned successfully!'})
    except Exception as e:
        return jsonify({
            'success': False, 
            'error': str(e)
        }), 500
    finally:
        conn.close()

    
@app.route('/get_kb_details/<int:kb_id>')
@login_required
def get_kb_details(kb_id):
    conn = connect_db()
    c = conn.cursor()
    
    # Check which table to query based on user role
    if current_user.role == 'admin':
        c.execute('SELECT * FROM kb_submissions WHERE id = %s', (kb_id,))
    else:
        c.execute('SELECT * FROM kb_submissions WHERE id = %s AND submitted_by = %s', 
                 (kb_id, current_user.role))
    
    kb = c.fetchone()
    conn.close()
    
    if kb:
        return jsonify({
            'id': kb[0],
            'industry': kb[1],
            'checkout_type': kb[2],
            'product_name': kb[3],  
            'about_merchant': kb[4],
            'use_case': kb[5],
            'business_challenges': kb[6],
            'challenges': kb[7],
            'proposed_solution': kb[8],
            'impact': kb[9],
            'attachment': kb[10],
            'comments': kb[11],
            'status': kb[12],
            'submitted_by': kb[13],
            'submitted_at': kb[14]
        })
    return jsonify({'error': 'KB not found or unauthorized'}), 404



# Add this route to routes.py
@app.route('/welcome')
@login_required
def welcome_user():
    if current_user.role == 'admin':
        return redirect(url_for('index'))
    
    # Get pending tickets for the current user
    conn = connect_db()
    c = conn.cursor()
    c.execute('''
        SELECT * FROM ticket_details 
        WHERE submitted_by = %s AND status = 'pending'
        ORDER BY submitted_at DESC
        LIMIT 3
    ''', (current_user.role,))
    pending_tickets = c.fetchall()
    
    # Get pending KBs for the current user
    c.execute('''
        SELECT * FROM kb_submissions 
        WHERE submitted_by = %s AND status = 'pending'
        ORDER BY submitted_at DESC
        LIMIT 3
    ''', (str(current_user.id)))
    pending_kbs = c.fetchall()
    conn.close()
    
    return render_template('welcome_user.html', 
                         pending_tickets=pending_tickets, 
                         pending_kbs=pending_kbs)



# Admin Welcome Route
@app.route('/admin')
@login_required
def welcome_admin():
    if current_user.role == 'admin':
        # Get counts for admin dashboard
        conn = connect_db()
        c = conn.cursor()
        
        # Count pending tickets
        c.execute('SELECT COUNT(*) FROM ticket_details WHERE status = %s', ('pending',))
        pending_tickets_count = c.fetchone()[0]
        
        # Count pending KBs
        c.execute('SELECT COUNT(*) FROM kb_submissions WHERE status = %s', ('pending',))
        pending_kbs_count = c.fetchone()[0]
        
        conn.close()
        
        return render_template('welcome_admin.html', 
                            pending_tickets_count=pending_tickets_count,
                            pending_kbs_count=pending_kbs_count)


# Admin KB Approval Route (updated)
@app.route('/approve_kbs')
@login_required
def approve_kbs():
    if current_user.role != 'admin':
        abort(403)
    
    conn = connect_db()
    c = conn.cursor()
    
    # Get pending KBs
    c.execute('''
        SELECT * FROM kb_submissions 
        WHERE status = %s
        ORDER BY submitted_at DESC
    ''', ('pending',))
    kbs = c.fetchall()

    print(kbs)
    
    conn.close()
    
    return render_template('approve_kbs.html', kbs=kbs)


# Process KB Approval/Decline (updated)
@app.route('/process_kb/<int:kb_id>', methods=['POST'])
@login_required
def process_kb(kb_id):
    if current_user.role != 'admin':
        abort(403)
    
    action = request.form.get('action')
    comments = request.form.get('comments', '')
    
    try:
        conn = connect_db()
        c = conn.cursor()
        
        # Get KB details
        c.execute('SELECT * FROM kb_submissions WHERE id = %s', (kb_id,))
        kb = c.fetchone()
        
        if not kb:
            return jsonify({'success': False, 'error': 'KB not found'}), 404
        
        if action == 'approve':
            # Insert into approved KBs
            c.execute('''
                INSERT INTO kb_approved (
                    industry, checkout_type, product_name,
                    about_merchant, use_case, business_challenges,
                    challenges, proposed_solution, impact,
                    attachment, approved_by
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                kb[1], kb[2], kb[3],  # industry, checkout_type, product_name
                kb[4], kb[5], kb[6],   # about_merchant, use_case, business_challenges
                kb[7], kb[8], kb[9],   # challenges, proposed_solution, impact
                kb[10],                # attachment
                current_user.role
            ))

            # Update submission status
            c.execute('''
                UPDATE kb_submissions 
                SET status = %s, comments = %s
                WHERE id = %s
            ''', ('approved', comments, kb_id))
            
            message = 'KB approved successfully!'
            
        elif action == 'decline':
            # Update submission status
            c.execute('''
                UPDATE kb_submissions 
                SET status = %s, comments = %s
                WHERE id = %s
            ''', ('declined', comments, kb_id))
            
            message = 'KB declined'
        else:
            return jsonify({'success': False, 'error': 'Invalid action'}), 400
        
        conn.commit()
        return jsonify({'success': True, 'message': message})
        
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        conn.close()


# View KBs Route (updated with filters)
@app.route('/view_kbs')
@login_required
def view_kbs():
    if current_user.role != 'admin':
        abort(403)

    # Get filter parameters from request
    status_filter = request.args.get('status_filter', 'all')
    industry_filter = request.args.get('industry_filter', 'all')
    product_filter = request.args.get('product_filter', 'all')

    conn = connect_db()
    c = conn.cursor()

    # Base query
    query = '''
        SELECT ks.* 
        FROM kb_submissions ks
        WHERE 1=1
    '''
    params = []

    # Apply filters
    if status_filter != 'all':
        query += ' AND ks.status = %s'
        params.append(status_filter)
    
    if industry_filter != 'all':
        query += ' AND ks.industry = %s'
        params.append(industry_filter)
    
    if product_filter != 'all':
        # Fixed SQL query syntax for PostgreSQL
        query += " AND (',' || ks.product_name || ',' LIKE %s)"
        params.append(f'%,{product_filter},%')

    query += ' ORDER BY ks.submitted_at DESC'
    
    c.execute(query, params)
    kbs = c.fetchall()

    # Get distinct values for filters
    c.execute('SELECT DISTINCT status FROM kb_submissions WHERE status IS NOT NULL')
    statuses = [row[0] for row in c.fetchall()]

    c.execute('SELECT DISTINCT industry FROM kb_submissions WHERE industry IS NOT NULL')
    industries = [row[0] for row in c.fetchall()]

    product_choices = [choice[1] for choice in KnowledgeForm.product_name_choices if choice[0]]

    conn.close()

    return render_template('view_kbs.html', 
                         kbs=kbs,
                         statuses=statuses,
                         industries=industries,
                         products=product_choices,
                         status_filter=status_filter,
                         industry_filter=industry_filter,
                         product_filter=product_filter)


# KB Details Modal Endpoint
@app.route('/kb_details/<int:kb_id>')
@login_required
def kb_details(kb_id):
    conn = connect_db()
    c = conn.cursor()
    
    if current_user.role == 'admin':
        c.execute('''
            SELECT ks.*, u.username as submitted_by_name 
            FROM kb_submissions ks
            JOIN users u ON ks.submitted_by = u.id
            WHERE ks.id = %s
        ''', (kb_id,))
    else:
        c.execute('''
            SELECT ks.*, u.username as submitted_by_name 
            FROM kb_submissions ks
            JOIN users u ON ks.submitted_by = u.id
            WHERE ks.id = %s AND ks.submitted_by = %s
        ''', (kb_id, current_user.id))
    
    kb = c.fetchone()
    conn.close()
    
    if not kb:
        abort(404)
    
    return jsonify({
        'id': kb[0],
        'industry': kb[1],
        'checkout_type': kb[2],
        'product_name': kb[3],  # Comma-separated string of products
        'about_merchant': kb[4],
        'use_case': kb[5],
        'business_challenges': kb[6],
        'challenges': kb[7],
        'proposed_solution': kb[8],
        'impact': kb[9],
        'attachment': kb[10],
        'comments': kb[11],
        'status': kb[12],
        'submitted_by': kb[16],  # Corrected column index for the submitted_by_name (should be 16 due to the join)
        'submitted_at': kb[14],
        'processed_by': kb[13] if kb[13] else None,
        'processed_at': kb[15] if kb[15] else None  # Adjusting for correct index
    })


# Download Attachment
@app.route('/download_kb_attachment/<filename>')
@login_required
def download_kb_attachment(filename):
    try:
        # Sanitize filename to prevent path traversal attacks
        filename = secure_filename(filename)
        
        # Construct file path
        file_path = os.path.join(Config.UPLOAD_FOLDER, filename)
        
        # Check if file exists
        if not os.path.exists(file_path):
            abort(404)
        
        # Verify user has permission to access the file
        conn = connect_db()
        c = conn.cursor()
        
        c.execute('''
            SELECT 1 
            FROM kb_submissions 
            WHERE attachment LIKE %s 
            AND (submitted_by = %s OR %s = 'admin')
        ''', (f'%{filename}%', current_user.role, current_user.role))
        
        if not c.fetchone():
            abort(403)
        
        # If checks pass, send the file
        return send_from_directory(
            Config.UPLOAD_FOLDER,
            filename,
            as_attachment=True
        )
    
    except Exception as e:
        app.logger.error(f"Error downloading file: {str(e)}")
        abort(500)


@app.route('/approved_tickets_admin/search')
@login_required
def search_approved_tickets():
    if current_user.role != 'admin':
        abort(403)

    status_filter = request.args.get('status_filter', 'all')
    user_filter = request.args.get('user_filter', '')
    search_term = request.args.get('search', '')
    
    # Base query with parameter placeholders
    query = """
    SELECT * FROM ticket_details 
    WHERE status IN ('approved', 'pending')
    """
    params = []
    
    # Apply status filter
    if status_filter != 'all':
        query += " AND status = %s"
        params.append(status_filter)
    
    # Apply user filter
    if user_filter:
        query += " AND submitted_by LIKE %s"
        params.append(f'%{user_filter}%')
    
    # Apply search term across multiple fields
    if search_term:
        search_fields = [
            'ticket_id', 'cf_merchant_id', 'cf_contact_number',
            'cf_product', 'cf_platform', 'cf_platform_item',
            'cf_checkout', 'cf_issue_category', 'cf_issue_sub_category',
            'description_text', 'cf_agent_category', 'cf_agent_sub_category',
            'submitted_by', 'comments'
        ]
        search_conditions = " OR ".join([f"{field} LIKE %s" for field in search_fields])
        query += f" AND ({search_conditions})"
        params.extend([f'%{search_term}%' for _ in search_fields])
    
    # Add sorting
    query += " ORDER BY submitted_at DESC"
    
    try:
        # Execute the query with parameters
        tickets = execute_query(query, params)
        
        # Convert tickets to a list of dictionaries for JSON response
        ticket_list = []
        for ticket in tickets:
            ticket_list.append({
                'id': ticket[0],
                'ticket_id': ticket[1],
                'cf_merchant_id': ticket[2],
                'cf_contact_number': ticket[3],
                'cf_product': ticket[4],
                'cf_platform': ticket[5],
                'cf_platform_item': ticket[6],
                'cf_checkout': ticket[7],
                'cf_issue_category': ticket[8],
                'cf_issue_sub_category': ticket[9],
                'description_text': ticket[10],
                'cf_agent_category': ticket[11],
                'cf_agent_sub_category': ticket[12],
                'submitted_by': ticket[16],
                'submitted_at': ticket[17],
                'status': ticket[18],
                'comments': ticket[15]
            })
        
        return jsonify({
            'tickets': ticket_list,
            'status_filter': status_filter,
            'user_filter': user_filter,
            'search': search_term
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'success': False
        }), 500

def execute_query(query, params=(), fetch_all=True):
    try:
        # Establish the connection to PostgreSQL
        conn = psycopg2.connect(dbname='your_db', user='your_user', password='your_password', host='your_host')
        with conn.cursor() as c:
            c.execute(query, params)  # Execute the query with parameters
            
            if fetch_all:
                result = c.fetchall()  # Get all results
            else:
                result = c.fetchone()  # Get the first result
            
            return result
        
    except psycopg2.Error as e:
        print(f"Error executing query: {e}")
        raise e
    finally:
        # Ensure the connection is closed
        conn.close()


import psycopg2
from flask import jsonify, request, abort
from werkzeug.utils import secure_filename

@app.route('/update_kb/<int:kb_id>', methods=['POST'])
@login_required
def update_kb(kb_id):
    if current_user.role != 'user':
        abort(403)

    try:
        # Establish the connection to PostgreSQL
        conn = psycopg2.connect(dbname='your_db', user='your_user', password='your_password', host='your_host')
        with conn.cursor() as c:
            # Verify the KB belongs to the current user and is pending
            c.execute('''
                SELECT id FROM kb_submissions 
                WHERE id = %s AND submitted_by = %s AND status = 'pending'
            ''', (kb_id, current_user.role))
            
            if not c.fetchone():
                return jsonify({'success': False, 'error': 'KB not found or not editable'}), 404

            # Get form data
            product_names = request.form.getlist('product_name')
            product_names_str = ','.join(product_names)

            # Update KB submission
            c.execute('''
                UPDATE kb_submissions 
                SET industry = %s,
                    checkout_type = %s,
                    product_name = %s,
                    about_merchant = %s,
                    use_case = %s,
                    business_challenges = %s,
                    challenges = %s,
                    proposed_solution = %s,
                    impact = %s,
                    status = 'pending',
                    comments = ''
                WHERE id = %s
            ''', (
                request.form.get('industry'),
                request.form.get('checkout_type'),
                product_names_str,
                request.form.get('about_merchant'),
                request.form.get('use_case'),
                request.form.get('business_challenges'),
                request.form.get('challenges'),
                request.form.get('proposed_solution'),
                request.form.get('impact'),
                kb_id
            ))
            
            # Commit the changes
            conn.commit()
            return jsonify({'success': True})

    except psycopg2.Error as e:
        # Handle database error
        app.logger.error(f"Error updating KB: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        # Ensure the connection is closed
        conn.close()



import psycopg2
from flask import jsonify
from flask_login import login_required, current_user

@app.route('/get_kb_stats')
@login_required
def get_kb_stats():
    try:
        # Establish the connection to PostgreSQL
        conn = psycopg2.connect(dbname='your_db', user='your_user', password='your_password', host='your_host')
        with conn.cursor() as c:
            
            # Get total submissions count
            c.execute('SELECT COUNT(*) FROM kb_submissions WHERE submitted_by = %s', (current_user.id,))
            total = c.fetchone()[0]
            
            # Get pending count
            c.execute('SELECT COUNT(*) FROM kb_submissions WHERE submitted_by = %s AND status = %s', (current_user.id, 'pending'))
            pending = c.fetchone()[0]
            
            # Get approved count
            c.execute('SELECT COUNT(*) FROM kb_submissions WHERE submitted_by = %s AND status = %s', (current_user.id, 'approved'))
            approved = c.fetchone()[0]
            
            # Get declined count
            c.execute('SELECT COUNT(*) FROM kb_submissions WHERE submitted_by = %s AND status = %s', (current_user.id, 'declined'))
            declined = c.fetchone()[0]
            
            # Prepare the status counts dictionary
            status_counts = {
                'pending': pending,
                'approved': approved,
                'declined': declined
            }
            
            # Return the stats in JSON format
            return jsonify({
                'total': total,
                'pending': pending,
                'approved': approved,
                'declined': declined,
                'status_counts': status_counts
            })

    except psycopg2.Error as e:
        # Handle database error
        app.logger.error(f"Error fetching KB stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

    finally:
        # Ensure the connection is closed
        if conn:
            conn.close()

import psycopg2
from flask import jsonify
from flask_login import login_required, current_user

@app.route('/get_kb_filter_options')
@login_required
def get_kb_filter_options():
    try:
        # Establish the connection to PostgreSQL
        conn = psycopg2.connect(dbname='your_db', user='your_user', password='your_password', host='your_host')
        with conn.cursor() as c:
            
            # Get distinct industries
            c.execute('SELECT DISTINCT industry FROM kb_submissions WHERE submitted_by = %s AND industry IS NOT NULL', (current_user.id,))
            industries = [row[0] for row in c.fetchall()]
            
            # Get distinct products
            c.execute('SELECT DISTINCT product_name FROM kb_submissions WHERE submitted_by = %s AND product_name IS NOT NULL', (current_user.id,))
            products = [row[0] for row in c.fetchall()]
            
            # Return the results as JSON
            return jsonify({
                'industries': industries,
                'products': products
            })

    except psycopg2.Error as e:
        # Handle any PostgreSQL related errors
        app.logger.error(f"Error fetching KB filter options: {str(e)}")
        return jsonify({'error': str(e)}), 500

    finally:
        # Ensure the connection is closed
        if conn:
            conn.close()


@app.route('/filter_kbs')
@login_required
def filter_kbs():
    status_filter = request.args.get('status_filter', 'all')
    industry_filter = request.args.get('industry_filter', 'all')
    search_term = request.args.get('search', '')

    try:
        # Establish the connection to PostgreSQL
        conn = psycopg2.connect(dbname='your_db', user='your_user', password='your_password', host='your_host')
        with conn.cursor() as c:
            # Base query
            query = 'SELECT * FROM kb_submissions WHERE submitted_by = %s'
            params = [current_user.id]  # Assuming submitted_by is current_user.id

            # Apply filters
            if status_filter != 'all':
                query += ' AND status = %s'
                params.append(status_filter)

            if industry_filter != 'all':
                query += ' AND industry = %s'
                params.append(industry_filter)

            if search_term:
                search_fields = [
                    'id', 'industry', 'checkout_type', 'product_name',
                    'about_merchant', 'use_case', 'business_challenges',
                    'challenges', 'proposed_solution', 'impact', 'comments', 'status'
                ]
                search_conditions = " OR ".join([f"{field} ILIKE %s" for field in search_fields])  # Using ILIKE for case-insensitive search
                query += f" AND ({search_conditions})"
                params.extend([f'%{search_term}%' for _ in search_fields])

            query += ' ORDER BY submitted_at DESC'

            # Execute query
            c.execute(query, params)
            kbs = c.fetchall()

            # Convert to list of dicts
            kb_list = []
            for kb in kbs:
                kb_list.append({
                    'id': kb[0],
                    'industry': kb[1],
                    'checkout_type': kb[2],
                    'product_name': kb[3],
                    'about_merchant': kb[4],
                    'use_case': kb[5],
                    'business_challenges': kb[6],
                    'challenges': kb[7],
                    'proposed_solution': kb[8],
                    'impact': kb[9],
                    'attachment': kb[10],
                    'comments': kb[11],
                    'status': kb[12],
                    'submitted_by': kb[13],
                    'submitted_at': kb[14]
                })

            return jsonify({'kbs': kb_list})

    except psycopg2.Error as e:
        # Handle any PostgreSQL related errors
        app.logger.error(f"Error filtering KBs: {str(e)}")
        return jsonify({'error': str(e)}), 500

    finally:
        # Ensure the connection is closed
        if conn:
            conn.close()

@app.route('/user_pending_tickets/search')
@login_required
def search_pending_tickets():
    if current_user.role == 'admin':
        abort(403)

    status_filter = request.args.get('status_filter', 'all')
    search_term = request.args.get('search', '')

    try:
        # Establish PostgreSQL connection
        conn = psycopg2.connect(dbname='your_db', user='your_user', password='your_password', host='your_host')
        with conn.cursor() as c:
            query = '''
                SELECT * FROM ticket_details 
                WHERE submitted_by = %s AND status = 'pending'
            '''
            params = [current_user.id]  # Assuming submitted_by is current_user.id

            if search_term:
                search_fields = [
                    'ticket_id', 'cf_merchant_id', 'cf_contact_number',
                    'cf_product', 'cf_platform', 'cf_platform_item',
                    'cf_checkout', 'cf_issue_category', 'cf_issue_sub_category',
                    'description_text', 'cf_agent_category', 'cf_agent_sub_category',
                    'comments'
                ]
                search_conditions = " OR ".join([f"{field} ILIKE %s" for field in search_fields])  # Using ILIKE for case-insensitive search
                query += f" AND ({search_conditions})"
                params.extend([f'%{search_term}%' for _ in search_fields])

            query += ' ORDER BY submitted_at DESC'

            # Execute the query
            c.execute(query, params)
            tickets = c.fetchall()

            # Convert to list of dicts
            ticket_list = []
            for ticket in tickets:
                ticket_list.append({
                    'id': ticket[0],
                    'ticket_id': ticket[1],
                    'cf_merchant_id': ticket[2],
                    'cf_contact_number': ticket[3],
                    'cf_product': ticket[4],
                    'cf_platform': ticket[5],
                    'cf_platform_item': ticket[6],
                    'cf_checkout': ticket[7],
                    'cf_issue_category': ticket[8],
                    'cf_issue_sub_category': ticket[9],
                    'description_text': ticket[10],
                    'cf_agent_category': ticket[11],
                    'cf_agent_sub_category': ticket[12],
                    'submitted_by': ticket[16],
                    'submitted_at': ticket[17],
                    'status': ticket[18],
                    'comments': ticket[15]
                })

            return jsonify({'tickets': ticket_list})

    except psycopg2.Error as e:
        # Handle PostgreSQL errors
        app.logger.error(f"Error searching pending tickets: {str(e)}")
        return jsonify({'error': str(e)}), 500

    finally:
        # Ensure connection is closed
        if conn:
            conn.close()


@app.route('/approved_tickets/search')
@login_required
def search_user_tickets():
    if current_user.role == 'admin':
        abort(403)  # Only for regular users

    status_filter = request.args.get('status_filter', 'all')
    search_term = request.args.get('search', '')

    try:
        # Establish PostgreSQL connection
        conn = psycopg2.connect(dbname='your_db', user='your_user', password='your_password', host='your_host')
        with conn.cursor() as c:
            
            # Base query for user's tickets
            query = '''
                SELECT * FROM ticket_details 
                WHERE submitted_by = %s
            '''
            params = [current_user.id]  # Assuming submitted_by refers to current_user.id

            # Apply status filter
            if status_filter != 'all':
                query += ' AND status = %s'
                params.append(status_filter)
            else:
                # Show both approved and pending tickets when 'all' is selected
                query += ' AND (status = %s OR status = %s)'
                params.extend(['approved', 'pending'])

            # Apply search term across multiple fields
            if search_term:
                search_fields = [
                    'ticket_id', 'cf_merchant_id', 'cf_contact_number',
                    'cf_product', 'cf_platform', 'cf_platform_item',
                    'cf_checkout', 'cf_issue_category', 'cf_issue_sub_category',
                    'description_text', 'cf_agent_category', 'cf_agent_sub_category',
                    'comments'
                ]
                search_conditions = " OR ".join([f"{field} ILIKE %s" for field in search_fields])  # ILIKE for case-insensitive search
                query += f" AND ({search_conditions})"
                params.extend([f'%{search_term}%' for _ in search_fields])

            query += ' ORDER BY submitted_at DESC'

            # Execute the query
            c.execute(query, params)
            tickets = c.fetchall()

            # Convert to list of dicts
            ticket_list = []
            for ticket in tickets:
                ticket_list.append({
                    'id': ticket[0],
                    'ticket_id': ticket[1],
                    'cf_merchant_id': ticket[2],
                    'cf_contact_number': ticket[3],
                    'cf_product': ticket[4],
                    'cf_platform': ticket[5],
                    'cf_platform_item': ticket[6],
                    'cf_checkout': ticket[7],
                    'cf_issue_category': ticket[8],
                    'cf_issue_sub_category': ticket[9],
                    'description_text': ticket[10],
                    'cf_agent_category': ticket[11],
                    'cf_agent_sub_category': ticket[12],
                    'submitted_by': ticket[16],
                    'submitted_at': ticket[17],
                    'status': ticket[18],
                    'comments': ticket[15]
                })

            return jsonify({
                'tickets': ticket_list,
                'status_filter': status_filter,
                'search': search_term
            })

    except psycopg2.Error as e:
        # Handle PostgreSQL errors
        app.logger.error(f"Error searching user tickets: {str(e)}")
        return jsonify({'error': str(e)}), 500

    finally:
        # Ensure connection is closed
        if conn:
            conn.close()


@app.route('/leaderboard')
@login_required
def leaderboard():
    if current_user.role != 'admin':
        abort(403)
    
    try:
        # Get KB leaderboard data
        kb_leaderboard = get_leaderboard_data('kb')
        ticket_leaderboard = get_leaderboard_data('ticket')
        
        # Get available months for filter
        months = get_available_months()
        
        # Prepare chart data
        kb_chart_labels = [user['username'] for user in kb_leaderboard[:10]]  # Top 10 only for chart
        kb_chart_data_total = [user['total_submissions'] for user in kb_leaderboard[:10]]
        kb_chart_data_approved = [user['approved_submissions'] for user in kb_leaderboard[:10]]
        
        ticket_chart_labels = [user['username'] for user in ticket_leaderboard[:10]]
        ticket_chart_data_total = [user['total_submissions'] for user in ticket_leaderboard[:10]]
        ticket_chart_data_approved = [user['approved_submissions'] for user in ticket_leaderboard[:10]]
        
        return render_template('leaderboard.html',
                             kb_leaderboard=kb_leaderboard,
                             ticket_leaderboard=ticket_leaderboard,
                             months=months,
                             kb_chart_labels=kb_chart_labels,
                             kb_chart_data_total=kb_chart_data_total,
                             kb_chart_data_approved=kb_chart_data_approved,
                             ticket_chart_labels=ticket_chart_labels,
                             ticket_chart_data_total=ticket_chart_data_total,
                             ticket_chart_data_approved=ticket_chart_data_approved)

    except psycopg2.Error as e:
        app.logger.error(f"Error fetching leaderboard data: {str(e)}")
        abort(500)

@app.route('/update_leaderboard')
@login_required
def update_leaderboard():
    if current_user.role != 'admin':
        abort(403)
    
    leaderboard_type = request.args.get('type', 'kb')
    month_filter = request.args.get('month', 'all')
    
    try:
        # Get leaderboard data based on type and month filter
        leaderboard_data = get_leaderboard_data(leaderboard_type, month_filter)
        
        # Prepare response data for chart (Top 10)
        chart_labels = [user['username'] for user in leaderboard_data[:10]]
        chart_data_total = [user['total_submissions'] for user in leaderboard_data[:10]]
        chart_data_approved = [user['approved_submissions'] for user in leaderboard_data[:10]]
        
        return jsonify({
            'leaderboard': leaderboard_data,
            'chart_labels': chart_labels,
            'chart_data_total': chart_data_total,
            'chart_data_approved': chart_data_approved
        })
    
    except psycopg2.Error as e:
        # Use specific PostgreSQL error for logging/debugging
        app.logger.error(f"PostgreSQL Error: {e}")
        return jsonify({'error': 'Database error occurred.'}), 500
    
    except Exception as e:
        app.logger.error(f"General Error: {e}")
        return jsonify({'error': 'An unexpected error occurred.'}), 500


def get_leaderboard_data(leaderboard_type, month_filter='all'):
    conn = connect_db()
    c = conn.cursor()
    
    try:
        # Base query selection based on leaderboard type
        if leaderboard_type == 'kb':
            query = '''
                SELECT 
                    submitted_by AS username,
                    COUNT(*) AS total_submissions,
                    SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved_submissions,
                    ROUND(SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) * 100.0 / COUNT(*)::numeric, 1) AS acceptance_rate
                FROM kb_submissions
            '''
        else:
            query = '''
                SELECT 
                    submitted_by AS username,
                    COUNT(*) AS total_submissions,
                    SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved_submissions,
                    ROUND(SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) * 100.0 / COUNT(*)::numeric, 1) AS acceptance_rate
                FROM ticket_details
            '''
        
        # Apply the month filter condition if needed
        params = []
        if month_filter == 'current':
            query += ' WHERE TO_CHAR(submitted_at, \'YYYY-MM\') = TO_CHAR(CURRENT_DATE, \'YYYY-MM\')'
        elif month_filter != 'all':
            query += ' WHERE TO_CHAR(submitted_at, \'YYYY-MM\') = %s'
            params.append(month_filter)
        
        # Add grouping and sorting
        query += ' GROUP BY submitted_by ORDER BY total_submissions DESC, approved_submissions DESC'
        
        # Execute the query
        c.execute(query, params)
        results = c.fetchall()
        
        # Convert to list of dicts
        leaderboard = []
        for row in results:
            leaderboard.append({
                'username': row[0],
                'total_submissions': row[1],
                'approved_submissions': row[2],
                'acceptance_rate': float(row[3]) if row[3] is not None else 0.0
            })
            
        return leaderboard
        
    except Exception as e:
        app.logger.error(f"Error fetching leaderboard data: {str(e)}")
        return []  # Return empty list in case of error
        
    finally:
        conn.close()



def get_available_months():
    conn = connect_db()  # Assumes a PostgreSQL connection is returned
    c = conn.cursor()
    
    try:
        # Get distinct YYYY-MM values from both tables and combine them
        c.execute('''
            SELECT DISTINCT TO_CHAR(submitted_at, 'YYYY-MM') AS month 
            FROM kb_submissions
            UNION
            SELECT DISTINCT TO_CHAR(submitted_at, 'YYYY-MM') AS month 
            FROM ticket_details
            ORDER BY month DESC
        ''')
        
        months = [row[0] for row in c.fetchall()]
        return months
        
    except Exception as e:
        app.logger.error(f"Error fetching available months: {str(e)}")
        return []
        
    finally:
        conn.close()







@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)

        conn = connect_db()
        c = conn.cursor()
        try:
            # Use PostgreSQL-style placeholders (%s)
            c.execute('INSERT INTO users (username, password, role) VALUES (%s, %s, %s)', 
                      (username, hashed_password, username))
            conn.commit()
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for('login'))
        except IntegrityError:
            conn.rollback()  # Always rollback on exception before reuse
            flash("Username already exists!", "danger")
        finally:
            conn.close()

    return render_template('signup.html')


@app.route('/submit_query', methods=['GET', 'POST'])
@login_required
def submit_query():
    form = QueryForm()
    if form.validate_on_submit():
        conn = connect_db()
        c = conn.cursor()
        try:
            c.execute('''
                INSERT INTO query_entries (product, query, resolution, workaround, submitted_by)
                VALUES (%s, %s, %s, %s, %s)
            ''', (
                form.product.data,
                form.query.data,
                form.resolution.data,
                form.workaround.data,
                current_user.role
            ))
            conn.commit()
            flash('Query submitted successfully!', 'success')
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Error submitting query: {str(e)}")
            flash('An error occurred while submitting your query.', 'danger')
        finally:
            conn.close()
        return redirect(url_for('submit_query'))
    return render_template('submit_query.html', form=form)



@app.route('/approve_queries')
@login_required
def approve_queries():
    """Approve Queries route (admin only)."""
    if current_user.role != 'admin':
        abort(403)

    conn = connect_db()
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM query_entries WHERE status = 'pending'")
        queries = c.fetchall()
    except Exception as e:
        app.logger.error(f"Error fetching pending queries: {str(e)}")
        flash("Error loading pending queries.", "danger")
        queries = []
    finally:
        conn.close()

    return render_template('approve_queries.html', queries=queries)




@app.route('/get_query_details/<int:query_id>')
@login_required
def get_query_details(query_id):
    conn = connect_db()
    c = conn.cursor()
    try:
        c.execute('SELECT * FROM query_entries WHERE id = %s', (query_id,))
        query = c.fetchone()
    except Exception as e:
        app.logger.error(f"Error fetching query details: {str(e)}")
        return jsonify({'error': 'Database error'}), 500
    finally:
        conn.close()

    if query:
        return jsonify({
            'id': query[0],
            'product': query[1],
            'query': query[2],
            'resolution': query[3],
            'workaround': query[4],
            'submitted_by': query[5],
            'submitted_at': query[6],
            'status': query[7],
            'comments': query[8]
        })

    return jsonify({'error': 'Query not found'}), 404





@app.route('/approve_query/<int:query_id>', methods=['POST'])
@login_required
def approve_query(query_id):
    """Approve a query (admin only)."""
    if current_user.role != 'admin':
        abort(403)

    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute("UPDATE query_entries SET status = 'approved' WHERE id = %s", (query_id,))
        conn.commit()
        flash('Query approved successfully!', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error: {str(e)}', 'danger')
        return jsonify({'success': False}), 500
    finally:
        conn.close()

    return jsonify({'success': True, 'redirect': url_for('approve_queries')})




@app.route('/decline_query/<int:query_id>', methods=['POST'])
@login_required
def decline_query(query_id):
    """Decline a query (admin only)."""
    if current_user.role != 'admin':
        abort(403)

    comments = request.form.get('comments', '').strip()
    try:
        conn = connect_db()
        c = conn.cursor()
        c.execute(
            "UPDATE query_entries SET status = 'declined', comments = %s WHERE id = %s",
            (comments, query_id)
        )
        conn.commit()
        flash('Query declined successfully!', 'success')
        return jsonify({'success': True, 'redirect': url_for('approve_queries')})
    except Exception as e:
        conn.rollback()
        flash(f'Error: {str(e)}', 'danger')
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        conn.close()




@app.route('/search_queries')
@login_required
def search_queries():
    """Search queries (admin only)."""
    if current_user.role != 'admin':
        abort(403)

    status_filter = request.args.get('status_filter', 'all')
    user_filter = request.args.get('user_filter', '')
    search_term = request.args.get('search', '')

    conn = connect_db()
    c = conn.cursor()

    query = 'SELECT * FROM query_entries WHERE 1=1'
    params = []

    if status_filter != 'all':
        query += ' AND status = %s'
        params.append(status_filter)

    if user_filter:
        query += ' AND submitted_by ILIKE %s'
        params.append(f'%{user_filter}%')

    if search_term:
        search_fields = ['product', 'query', 'resolution', 'workaround', 'submitted_by']
        search_conditions = " OR ".join([f"{field} ILIKE %s" for field in search_fields])
        query += f" AND ({search_conditions})"
        params.extend([f'%{search_term}%' for _ in search_fields])

    query += ' ORDER BY submitted_at DESC'
    
    c.execute(query, params)
    queries = c.fetchall()
    conn.close()

    # Convert to list of dicts
    query_list = []
    for q in queries:
        query_list.append({
            'id': q[0],
            'product': q[1],
            'query': q[2],
            'resolution': q[3],
            'workaround': q[4],
            'submitted_by': q[5],
            'submitted_at': q[6],
            'status': q[7],
            'comments': q[8]
        })

    return jsonify({'queries': query_list})




@app.route('/query_dashboard')
@login_required
def query_dashboard():
    """Query dashboard for users."""
    status_filter = request.args.get('status_filter', 'all')
    search_term = request.args.get('search', '').lower()

    conn = connect_db()
    c = conn.cursor()

    query = "SELECT * FROM query_entries WHERE submitted_by = %s"
    params = [current_user.role]

    if status_filter != 'all':
        query += ' AND status = %s'
        params.append(status_filter)

    if search_term:
        query += ' AND (LOWER(product) LIKE %s OR LOWER(query) LIKE %s OR LOWER(resolution) LIKE %s OR LOWER(workaround) LIKE %s)'
        params.extend([f'%{search_term}%' for _ in range(4)])

    query += ' ORDER BY submitted_at DESC'
    c.execute(query, params)
    queries = c.fetchall()
    conn.close()

    # Convert to list of dicts for easier use in template
    query_list = [
        {
            'id': q[0],
            'product': q[1],
            'query': q[2],
            'resolution': q[3],
            'workaround': q[4],
            'status': q[7],
            'submitted_at':  q[6].strftime('%Y-%m-%d %H:%M:%S') if isinstance(q[6], datetime.datetime) else q[6]
        } for q in queries
    ]

    return render_template('query_dashboard_user.html', queries=query_list, status_filter=status_filter, search_term=search_term)


@app.route('/get_user_queries')
@login_required
def get_user_queries():
    """Get queries submitted by the current user."""
    conn = connect_db()
    c = conn.cursor()
    search_term = request.args.get('search', '').lower()
    status_filter = request.args.get('status_filter', 'all')

    query = "SELECT * FROM query_entries WHERE submitted_by = %s"
    params = [current_user.role]

    if status_filter != 'all':
        query += ' AND status = %s'
        params.append(status_filter)

    if search_term:
        search_fields = ['product', 'query', 'resolution', 'workaround']
        search_conditions = " OR ".join([f"LOWER({field}) LIKE %s" for field in search_fields])
        query += f" AND ({search_conditions})"
        params.extend([f'%{search_term}%' for _ in search_fields])

    query += ' ORDER BY submitted_at DESC'
    c.execute(query, params)
    queries = c.fetchall()
    conn.close()

    # Convert to list of dicts for easier use in template
    query_list = [
        {
            'id': q[0],
            'product': q[1],
            'query': q[2],
            'resolution': q[3],
            'workaround': q[4],
            'status': q[7],
            'submitted_at':  q[6].strftime('%Y-%m-%d %H:%M:%S') if isinstance(q[6], datetime.datetime) else q[6]
        } for q in queries
    ]
    return jsonify({'queries': query_list})



@app.route('/user_leaderboard')
@login_required
def user_leaderboard():

    conn = connect_db()
    c = conn.cursor()

    # Fetch total and approved query counts per user
    c.execute('''
        SELECT submitted_by,
               COUNT(*) AS total,
               SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved
        FROM query_entries
        GROUP BY submitted_by
        ORDER BY approved DESC, submitted_by ASC
    ''')

    rows = c.fetchall()
    conn.close()

    leaderboard = []
    last_score = None
    last_rank = 0
    tie_count = 0

    for index, row in enumerate(rows):
        username, total, approved = row
        approved = approved or 0  # Handle NULLs

        acceptance_rate = round((approved / total) * 100, 2) if total > 0 else 0

        if approved == last_score:
            rank = last_rank
            tie_count += 1
        else:
            rank = last_rank + tie_count + 1
            last_rank = rank
            tie_count = 0
            last_score = approved

        leaderboard.append({
            'rank': rank,
            'username': username,
            'total_submissions': total,
            'approved_submissions': approved,
            'acceptance_rate': acceptance_rate
        })

    return render_template('user_leaderboard.html', leaderboard=leaderboard)


@app.route('/ticket_dashboard')
@login_required
def ticket_dashboard():
    conn = connect_db()
    c = conn.cursor()
    c.execute('SELECT username, resolved, not_resolved, create_ticket, dropped, type, recorded_at FROM user_ticket_stats')
    stats = c.fetchall()
    conn.close()

    usernames = [row[0] for row in stats]
    resolved = [row[1] for row in stats]
    not_resolved = [row[2] for row in stats]
    create_ticket = [row[3] for row in stats]
    dropped = [row[4] for row in stats]
    recorded_at = [row[6].isoformat() if row[6] else '' for row in stats]  # Convert timestamps to ISO strings

    return render_template(
        'ticket_dashboard.html',
        usernames=usernames,
        resolved=resolved,
        not_resolved=not_resolved,
        create_ticket=create_ticket,
        dropped=dropped,
        recorded_at=recorded_at
    )
