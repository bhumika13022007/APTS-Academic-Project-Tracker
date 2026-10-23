import os, io, csv, secrets, hashlib, base64
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import click
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import inspect

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'))
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('COOKIE_SECURE', '0') == '1'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///' + os.path.join(BASE_DIR, 'apts.db'))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
limiter = Limiter(get_remote_address, app=app, default_limits=[])


def _code_cipher():
    # Encrypt invite codes at rest. Keep SECRET_KEY stable in .env so existing codes remain readable.
    key = base64.urlsafe_b64encode(hashlib.sha256(app.config['SECRET_KEY'].encode('utf-8')).digest())
    return Fernet(key)


@app.context_processor
def inject_csrf_token():
    def csrf_token():
        token = session.get('_csrf_token')
        if not token:
            token = secrets.token_urlsafe(32)
            session['_csrf_token'] = token
        return token
    return {'csrf_token': csrf_token}


@app.before_request
def protect_post_requests_with_csrf():
    if request.method == 'POST':
        supplied = request.form.get('_csrf_token', '')
        expected = session.get('_csrf_token', '')
        if not supplied or not expected or not secrets.compare_digest(supplied, expected):
            return 'Invalid or missing CSRF token. Refresh the page and try again.', 400

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    user_code = db.Column(db.String(40), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class RegistrationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code_hash = db.Column(db.String(64), unique=True, nullable=False)
    encrypted_code = db.Column(db.Text, nullable=True)

    @property
    def display_code(self):
        if not self.encrypted_code:
            return None
        try:
            return _code_cipher().decrypt(self.encrypted_code.encode('utf-8')).decode('utf-8')
        except (InvalidToken, ValueError, TypeError):
            return None
    role = db.Column(db.String(20), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    used_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    creator = db.relationship('User', foreign_keys=[created_by])
    user = db.relationship('User', foreign_keys=[used_by])


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(180), nullable=False)
    description = db.Column(db.Text, default='')
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    teacher = db.relationship('User', foreign_keys=[teacher_id])
    student = db.relationship('User', foreign_keys=[student_id])

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    title = db.Column(db.String(180), nullable=False)
    description = db.Column(db.Text, default='')
    deadline = db.Column(db.DateTime, nullable=False)
    max_marks = db.Column(db.Integer, default=10)
    position = db.Column(db.Integer, default=1)
    project = db.relationship('Project', backref=db.backref('tasks', lazy=True, cascade='all, delete-orphan'))

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    github_url = db.Column(db.String(500), default='')
    notes = db.Column(db.Text, default='')
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    marks = db.Column(db.Integer, nullable=True)
    feedback = db.Column(db.Text, default='')
    status = db.Column(db.String(30), default='Submitted')
    task = db.relationship('Task', backref=db.backref('submissions', lazy=True, cascade='all, delete-orphan'))
    student = db.relationship('User', foreign_keys=[student_id])

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    body = db.Column(db.Text, nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.relationship('User')
    project = db.relationship('Project', backref=db.backref('messages', lazy=True, cascade='all, delete-orphan'))

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(250), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def current_user():
    if 'user_id' not in session: return None
    return db.session.get(User, session['user_id'])

def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                flash('Please log in first.', 'error'); return redirect(url_for('login'))
            if user.role not in roles:
                flash('You do not have permission to access that page.', 'error'); return redirect(url_for('dashboard'))
            return fn(*args, **kwargs)
        return wrapped
    return decorator

def log_action(action):
    db.session.add(AuditLog(user_id=session.get('user_id'), action=action))
    db.session.commit()

def project_visible(project, user):
    return (
        user.role == 'admin'
        or project.teacher_id == user.id
        or (user.role == 'student' and project.student_id is None)
        or project.student_id == user.id
    )
def parse_deadline(value):
    try: return datetime.strptime(value, '%Y-%m-%dT%H:%M')
    except (TypeError, ValueError): return None

@app.route('/')
def index():
    return redirect(url_for('dashboard') if current_user() else url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit('10 per hour', methods=['POST'])
def register():
    # Public registration is limited to Student and Teacher; Admin signup is disabled.
    if request.method == 'POST':
        name = request.form.get('full_name', '').strip()
        code = request.form.get('user_code', '').strip().upper()
        email = request.form.get('email', '').strip().lower()
        role = request.form.get('role', '').strip().lower()
        registration_code = request.form.get('registration_code', '').strip()
        password = request.form.get('password', '')

        if role not in ('teacher', 'student'):
            flash('Public registration is available only for Student and Teacher accounts.', 'error')
        elif not name or not code or not email or not registration_code or len(password) < 12:
            flash('Complete all fields. Password must be at least 12 characters.', 'error')
        elif User.query.filter((User.user_code == code) | (User.email == email)).first():
            flash('This ID or email is already registered.', 'error')
        else:
            code_hash = hashlib.sha256(registration_code.encode('utf-8')).hexdigest()
            invitation = RegistrationCode.query.filter_by(code_hash=code_hash, role=role, used_at=None).first()
            if not invitation or invitation.expires_at < datetime.utcnow():
                flash('Invalid, expired, already-used, or wrong-role registration code.', 'error')
            else:
                user = User(full_name=name, user_code=code, email=email, role=role,
                            password_hash=generate_password_hash(password))
                db.session.add(user)
                db.session.flush()
                invitation.used_at = datetime.utcnow()
                invitation.used_by = user.id
                invitation.encrypted_code = None
                db.session.add(AuditLog(user_id=user.id, action=f'Registered {role} account using invitation code'))
                db.session.commit()
                flash('Registration successful. You can now log in.', 'success')
                return redirect(url_for('login'))
    return render_template('auth.html', mode='register')


@app.route('/login', methods=['GET','POST'])
@limiter.limit('5 per minute', methods=['POST'])
def login():
    if request.method == 'POST':
        code = request.form.get('user_code','').strip().upper()
        password = request.form.get('password','')
        role = request.form.get('role','')
        user = User.query.filter_by(user_code=code, role=role).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear(); session['user_id'] = user.id
            log_action('Logged in')
            return redirect(url_for('dashboard'))
        flash('Incorrect ID, role, or password.', 'error')
    return render_template('auth.html', mode='login')

@app.route('/logout', methods=['POST'])
def logout():
    if current_user(): log_action('Logged out')
    session.clear(); return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    user = current_user()

    if not user:
        return redirect(url_for('login'))

    if user.role == 'teacher':
        projects = Project.query.filter_by(
            teacher_id=user.id
        ).order_by(Project.created_at.desc()).all()

    elif user.role == 'student':
        from sqlalchemy import or_

        projects = Project.query.filter(
            or_(
                Project.student_id == user.id,
                Project.student_id.is_(None)
            )
        ).order_by(Project.created_at.desc()).all()

    else:
        projects = Project.query.order_by(
            Project.created_at.desc()
        ).all()

    users = (
        User.query.order_by(User.created_at.desc()).all()
        if user.role == 'admin' else []
    )

    all_submissions = (
        Submission.query.order_by(Submission.submitted_at.desc()).all()
        if user.role in ('teacher', 'admin') else []
    )

    registration_codes = (
        RegistrationCode.query.filter_by(used_at=None)
        .order_by(RegistrationCode.created_at.desc()).all()
        if user.role == 'admin' else []
    )

    return render_template(
        'dashboard.html',
        user=user,
        projects=projects,
        users=users,
        submissions=all_submissions,
        registration_codes=registration_codes,
        now=datetime.utcnow()
    )

@app.route('/admin/registration-codes', methods=['POST'])
@role_required('admin')
def create_registration_code():
    role = request.form.get('role', '').strip().lower()
    try:
        days = int(request.form.get('expires_days', '7'))
    except ValueError:
        days = 7
    if role not in ('student', 'teacher'):
        flash('Registration codes can only be created for Students or Teachers.', 'error')
    else:
        days = max(1, min(days, 30))
        raw_code = 'APTS-' + secrets.token_urlsafe(9).replace('-', '').replace('_', '').upper()
        code_hash = hashlib.sha256(raw_code.encode('utf-8')).hexdigest()
        invite = RegistrationCode(code_hash=code_hash, encrypted_code=_code_cipher().encrypt(raw_code.encode('utf-8')).decode('utf-8'),
                                  role=role, created_by=current_user().id,
                                  expires_at=datetime.utcnow() + timedelta(days=days))
        db.session.add(invite)
        db.session.add(AuditLog(user_id=current_user().id, action=f'Generated {role} registration code (expires in {days} days)'))
        db.session.commit()
        flash(f'Copy this {role.title()} registration code now (shown once): {raw_code}', 'success')
    return redirect(url_for('dashboard') + '#registration-codes')


@app.route('/admin/create-admin', methods=['POST'])
@role_required('admin')
def create_admin_account():
    name = request.form.get('full_name', '').strip()
    code = request.form.get('user_code', '').strip().upper()
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    if not name or not code or not email or len(password) < 12:
        flash('Complete all fields. Admin password must be at least 12 characters.', 'error')
    elif User.query.filter((User.user_code == code) | (User.email == email)).first():
        flash('This ID or email is already registered.', 'error')
    else:
        new_admin = User(full_name=name, user_code=code, email=email, role='admin',
                         password_hash=generate_password_hash(password))
        db.session.add(new_admin)
        db.session.flush()
        db.session.add(AuditLog(user_id=current_user().id, action=f'Created admin account {code}'))
        db.session.commit()
        flash('Admin account created successfully.', 'success')
    return redirect(url_for('dashboard') + '#admin-accounts')


@app.route('/projects/create', methods=['POST'])
@role_required('teacher')
def create_project():
    title=request.form.get('title','').strip(); description=request.form.get('description','').strip()
    student_code=request.form.get('student_code','').strip().upper()
    student=User.query.filter_by(user_code=student_code, role='student').first() if student_code else None
    if not title: flash('Project title is required.', 'error')
    elif student_code and not student: flash('Student ID not found. Leave blank to create an unassigned project.', 'error')
    else:
        project=Project(title=title, description=description, teacher_id=current_user().id, student_id=student.id if student else None)
        db.session.add(project); db.session.commit(); log_action(f'Created project #{project.id}: {title}')
        flash('Project created. Now add its tasks.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/projects/<int:project_id>/tasks', methods=['POST'])
@role_required('teacher')
def add_task(project_id):
    project=db.session.get(Project, project_id)
    if not project or project.teacher_id != current_user().id:
        flash('Project not found or not owned by you.', 'error'); return redirect(url_for('dashboard'))
    title=request.form.get('title','').strip(); deadline=parse_deadline(request.form.get('deadline'))
    try: marks=max(1,min(100,int(request.form.get('max_marks','10'))))
    except ValueError: marks=10
    if not title or not deadline: flash('Task title and valid deadline are required.', 'error')
    else:
        task=Task(project_id=project.id,title=title,description=request.form.get('description','').strip(),deadline=deadline,max_marks=marks,position=len(project.tasks)+1)
        db.session.add(task); db.session.commit(); log_action(f'Created task #{task.id} for project #{project.id}')
        flash('Task added successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/tasks/<int:task_id>/submit', methods=['POST'])
@role_required('student')
def submit_task(task_id):
    task=db.session.get(Task, task_id); user=current_user()
    if (
    not task
    or (
        task.project.student_id is not None
        and task.project.student_id != user.id
    )
):
        flash('Task not found or not assigned to you.', 'error'); return redirect(url_for('dashboard'))
    if datetime.utcnow() > task.deadline:
        flash('Deadline has passed. Submission is closed.', 'error'); return redirect(url_for('dashboard'))
    existing=Submission.query.filter_by(task_id=task.id, student_id=user.id).first()
    if existing:
        flash('You have already submitted this task.', 'error'); return redirect(url_for('dashboard'))
    url=request.form.get('github_url','').strip()
    if url and not (url.startswith('https://') or url.startswith('http://')):
        flash('Enter a valid URL beginning with http:// or https://.', 'error'); return redirect(url_for('dashboard'))
    sub=Submission(task_id=task.id,student_id=user.id,github_url=url,notes=request.form.get('notes','').strip(),status='On Time')
    db.session.add(sub); db.session.commit(); log_action(f'Submitted task #{task.id}')
    flash('Task submitted successfully.', 'success'); return redirect(url_for('dashboard'))

@app.route('/submissions/<int:submission_id>/grade', methods=['POST'])
@role_required('teacher','admin')
def grade_submission(submission_id):
    sub=db.session.get(Submission, submission_id); user=current_user()
    if not sub or (user.role == 'teacher' and sub.task.project.teacher_id != user.id):
        flash('Submission not found or not permitted.', 'error'); return redirect(url_for('dashboard'))
    try: marks=int(request.form.get('marks','0'))
    except ValueError: marks=-1
    if marks < 0 or marks > sub.task.max_marks:
        flash(f'Marks must be between 0 and {sub.task.max_marks}.', 'error')
    else:
        sub.marks=marks; sub.feedback=request.form.get('feedback','').strip(); db.session.commit(); log_action(f'Graded submission #{sub.id}')
        flash('Grade and feedback saved.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/projects/<int:project_id>/messages', methods=['POST'])
@role_required('teacher','student','admin')
def send_message(project_id):
    project=db.session.get(Project,project_id); user=current_user(); body=request.form.get('body','').strip()
    if not project or not project_visible(project,user): flash('Project not found or not permitted.', 'error')
    elif not body: flash('Message cannot be empty.', 'error')
    else:
        db.session.add(Message(project_id=project.id,sender_id=user.id,body=body)); db.session.commit(); log_action(f'Sent message on project #{project.id}'); flash('Message sent.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/reports/submissions.csv')
@role_required('teacher','admin')
def export_csv():
    user=current_user(); output=io.StringIO(); writer=csv.writer(output)
    writer.writerow(['Project','Task','Student ID','Student Name','Submitted At','Status','Marks','Max Marks','Feedback','GitHub URL'])
    subs=Submission.query.order_by(Submission.submitted_at.desc()).all()
    for s in subs:
        if user.role == 'teacher' and s.task.project.teacher_id != user.id: continue
        writer.writerow([s.task.project.title,s.task.title,s.student.user_code,s.student.full_name,s.submitted_at.strftime('%Y-%m-%d %H:%M'),s.status,s.marks if s.marks is not None else '',s.task.max_marks,s.feedback,s.github_url])
    data=io.BytesIO(output.getvalue().encode('utf-8-sig'))
    return send_file(data,mimetype='text/csv',as_attachment=True,download_name='apts_submissions_report.csv')

@app.route('/reports/submissions.pdf')
@role_required('teacher','admin')
def export_pdf():
    from reportlab.lib.pagesizes import landscape, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    user=current_user(); buffer=io.BytesIO(); doc=SimpleDocTemplate(buffer,pagesize=landscape(A4))
    styles=getSampleStyleSheet(); story=[Paragraph('Academic Project Tracker - Submissions Report',styles['Title']),Spacer(1,12)]
    rows=[['Project','Task','Student','Submitted','Status','Marks','Feedback']]
    for s in Submission.query.order_by(Submission.submitted_at.desc()).all():
        if user.role == 'teacher' and s.task.project.teacher_id != user.id: continue
        rows.append([s.task.project.title,s.task.title,s.student.user_code,s.submitted_at.strftime('%d-%m-%Y'),s.status,f'{s.marks}/{s.task.max_marks}' if s.marks is not None else '-',(s.feedback or '')[:70]])
    table=Table(rows,repeatRows=1,colWidths=[115,115,65,65,60,50,180])
    table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#173b67')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('GRID',(0,0),(-1,-1),0.4,colors.grey),('VALIGN',(0,0),(-1,-1),'TOP'),('FONTSIZE',(0,0),(-1,-1),8),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#f1f5f9')])]))
    story.append(table); doc.build(story); buffer.seek(0)
    return send_file(buffer,mimetype='application/pdf',as_attachment=True,download_name='apts_submissions_report.pdf')

@app.cli.command('create-admin')
def create_admin_command():
    """Create the initial Admin account securely from the local terminal."""
    with app.app_context():
        if User.query.filter_by(role='admin').first():
            click.echo('An Admin account already exists. Sign in as Admin to create additional Admins from the dashboard.')
            return
        click.echo('Create the initial APTS Admin account. This command is local-terminal only.')
        name = click.prompt('Full name').strip()
        user_code = click.prompt('Admin ID').strip().upper()
        email = click.prompt('Admin email').strip().lower()
        password = click.prompt('Password (minimum 12 characters)', hide_input=True, confirmation_prompt=True)
        if len(password) < 12:
            raise click.ClickException('Password must be at least 12 characters.')
        if User.query.filter((User.user_code == user_code) | (User.email == email)).first():
            raise click.ClickException('That ID or email is already registered.')
        admin = User(full_name=name, user_code=user_code, email=email, role='admin',
                     password_hash=generate_password_hash(password))
        db.session.add(admin)
        db.session.flush()
        db.session.add(AuditLog(user_id=admin.id, action='Created initial Admin account via local CLI'))
        db.session.commit()
        click.echo(f'Admin account created for {user_code}. You can now log in.')


@app.cli.command('list-admins')
def list_admins_command():
    """List Admin IDs in the database used by this app (no passwords shown)."""
    with app.app_context():
        admins = User.query.filter_by(role='admin').order_by(User.id.asc()).all()
        click.echo(f"Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
        if not admins:
            click.echo('No Admin accounts found in this database. Run: python -m flask --app app create-admin')
            return
        for admin in admins:
            click.echo(f"ID: {admin.user_code} | Email: {admin.email} | Name: {admin.full_name}")


@app.cli.command('reset-admin-password')
def reset_admin_password_command():
    """Reset an existing Admin password from the local terminal."""
    with app.app_context():
        click.echo(f"Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
        user_code = click.prompt('Existing Admin ID').strip().upper()
        admin = User.query.filter_by(user_code=user_code, role='admin').first()
        if not admin:
            raise click.ClickException('No Admin with that ID exists in this database. Check the folder/database, or run create-admin if none exists.')
        password = click.prompt('New password (minimum 12 characters)', hide_input=True, confirmation_prompt=True)
        if len(password) < 12:
            raise click.ClickException('Password must be at least 12 characters.')
        admin.password_hash = generate_password_hash(password)
        db.session.add(AuditLog(user_id=admin.id, action='Admin password reset via local CLI'))
        db.session.commit()
        click.echo(f'Password reset successfully for Admin ID {admin.user_code}. Try logging in with this ID and the new password.')


@app.route('/health')
def health(): return jsonify(status='ok', app='Academic Project Tracker and Grading System')

with app.app_context():
    db.create_all()
    # Lightweight migration for existing SQLite databases created before encrypted_code existed.
    columns = {column['name'] for column in inspect(db.engine).get_columns('registration_code')}
    if 'encrypted_code' not in columns:
        with db.engine.begin() as connection:
            connection.exec_driver_sql('ALTER TABLE registration_code ADD COLUMN encrypted_code TEXT')
            # Legacy codes cannot be displayed again; invalidate them and issue fresh codes.
            connection.exec_driver_sql('UPDATE registration_code SET used_at = CURRENT_TIMESTAMP WHERE used_at IS NULL AND encrypted_code IS NULL')

if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG', '0') == '1')
