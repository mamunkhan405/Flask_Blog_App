from flask import Flask, render_template, url_for, flash, redirect, request, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import SQLAlchemyError
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, SelectField, DateTimeField, HiddenField, EmailField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
import os
import secrets
from PIL import Image, UnidentifiedImageError as PillowUnidentifiedImageError # Import with alias
from datetime import datetime
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from functools import wraps
from slugify import slugify
from markupsafe import Markup
from flask_wtf.csrf import generate_csrf

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Add template context processor for csrf_token
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=lambda: generate_csrf())

# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    # New profile fields
    bio = db.Column(db.String(500))
    location = db.Column(db.String(100))
    website = db.Column(db.String(200))
    twitter = db.Column(db.String(100))
    github = db.Column(db.String(100))
    joined_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    posts = db.relationship('Post', backref='author', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)
    comments = db.relationship('Comment', back_populates='author', lazy=True)
    
    # Updated followers relationship
    followers = db.Table('followers',
        db.Column('follower_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
        db.Column('followed_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
    )
    
    following = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers_list', lazy='dynamic'), lazy='dynamic'
    )

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"

    def follow(self, user):
        if not self.is_following(user):
            self.following.append(user)
            db.session.commit()

    def unfollow(self, user):
        if self.is_following(user):
            self.following.remove(user)
            db.session.commit()

    def is_following(self, user):
        return self.following.filter(
            User.followers.c.followed_id == user.id).count() > 0

# Category model
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    slug = db.Column(db.String(50), unique=True)

    def __repr__(self):
        return f"Category('{self.name}')"

# Tag model and post-tag relationship
post_tags = db.Table('post_tags',
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'), primary_key=True),
    db.Column('tag_id', db.Integer, db.ForeignKey('tag.id'), primary_key=True)
)

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    slug = db.Column(db.String(50), unique=True)
    posts = db.relationship('Post', secondary=post_tags, backref=db.backref('tags', lazy='dynamic'))

    def __repr__(self):
        return f"Tag('{self.name}')"

# Newsletter model
class Newsletter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    subscribed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    confirmation_token = db.Column(db.String(100), unique=True, nullable=True)
    is_confirmed = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"Newsletter('{self.email}', '{self.subscribed_at}')"

# Post model
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    image_file = db.Column(db.String(20), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)
    category = db.relationship('Category', backref=db.backref('posts', lazy=True))
    views = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='published')  # published, draft, scheduled
    publish_date = db.Column(db.DateTime)
    likes = db.relationship('Like', backref='post', lazy=True)
    comments = db.relationship('Comment', back_populates='post', lazy=True)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"

    @property
    def like_count(self):
        return len(self.likes)

    def is_liked_by(self, user):
        return Like.query.filter_by(user_id=user.id, post_id=self.id).first() is not None

# Like model
class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"Like('{self.user_id}', '{self.post_id}')"

# Comment model
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    
    # Update relationships to use back_populates
    author = db.relationship('User', back_populates='comments')
    post = db.relationship('Post', back_populates='comments')
    parent = db.relationship('Comment', remote_side=[id], backref=db.backref('replies', lazy=True))
    
    def __repr__(self):
        return f"Comment('{self.content[:20]}...', '{self.created_at}')"

# Notification model
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    parent_comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    content = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('notifications', lazy=True))
    sender = db.relationship('User', foreign_keys=[sender_id])
    post = db.relationship('Post', backref=db.backref('notifications', lazy=True))
    comment = db.relationship('Comment', foreign_keys=[comment_id], backref=db.backref('notifications', lazy=True))
    parent_comment = db.relationship('Comment', foreign_keys=[parent_comment_id])
    
    def __repr__(self):
        return f"Notification('{self.content}', '{self.created_at}')"

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', 
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UpdateProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    bio = TextAreaField('Bio', validators=[Length(max=500)])
    location = StringField('Location', validators=[Length(max=100)])
    website = StringField('Website', validators=[Length(max=200)])
    twitter = StringField('Twitter Username', validators=[Length(max=100)])
    github = StringField('GitHub Username', validators=[Length(max=100)])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    def __init__(self, original_username, original_email, *args, **kwargs):
        super(UpdateProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email

    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != self.original_email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    category = SelectField('Category', coerce=int, validators=[DataRequired()])
    tags = StringField('Tags (comma separated)', validators=[Optional()])
    status = SelectField('Status', choices=[
        ('published', 'Publish Now'),
        ('draft', 'Save as Draft'),
        ('scheduled', 'Schedule')
    ])
    publish_date = DateTimeField('Publish Date', format='%Y-%m-%d %H:%M', validators=[Optional()])
    picture = FileField('Add Image (Optional)', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif'])])
    submit = SubmitField('Post')

    def __init__(self, *args, **kwargs):
        super(PostForm, self).__init__(*args, **kwargs)
        self.category.choices = [(c.id, c.name) for c in Category.query.order_by('name')]

class CommentForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])
    parent_id = HiddenField('Parent Comment ID')
    submit = SubmitField('Post Comment')

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    
    # Resize the image
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    
    return picture_fn

def save_post_image(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/post_pics', picture_fn)
    
    output_size = (800, 800)
    try:
        i = Image.open(form_picture)
    except PillowUnidentifiedImageError: # More specific error for invalid image format
        return None, "Invalid image file: The provided file is not a recognized image format."
    except IOError:
        return None, "Invalid image file: Could not open or read the image."
    except Exception as e: # Catch other Pillow related errors during open
        app.logger.error(f"Pillow Image.open error: {e}")
        return None, "An error occurred while trying to open the image."

    try:
        i.thumbnail(output_size)
    except Exception as e:
        app.logger.error(f"Pillow thumbnail error: {e}")
        return None, "Failed to resize image. The image might be corrupted or in an unsupported format."

    try:
        i.save(picture_path)
    except Exception as e:
        app.logger.error(f"Pillow save error: {e}")
        return None, "Failed to save image. Please try again later."

    return picture_fn, None

def get_sidebar_data():
    total_posts = Post.query.filter_by(status='published').count()
    user_post_count = Post.query.filter_by(author=current_user, status='published').count() if current_user.is_authenticated else 0
    categories = Category.query.order_by(Category.name).all()
    popular_posts = Post.query.filter_by(status='published').order_by(Post.views.desc()).limit(5).all()
    popular_tags = db.session.query(Tag, db.func.count(post_tags.c.post_id).label('post_count'))\
        .join(post_tags)\
        .group_by(Tag)\
        .order_by(db.text('post_count DESC'))\
        .limit(10).all()
    # Get all tags for the sidebar
    all_tags = Tag.query.all()
    return {
        'total_posts': total_posts,
        'user_post_count': user_post_count,
        'categories': categories,
        'popular_posts': popular_posts,
        'popular_tags': popular_tags,
        'tags': all_tags  # Add all tags to the context
    }

@app.route("/")
@app.route("/home")
def home():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template('home.html', posts=posts, title='Home', **get_sidebar_data())

@app.route("/about")
def about():
    return render_template('about.html', title="About", **get_sidebar_data())

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form, **get_sidebar_data())

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form, **get_sidebar_data())

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateProfileForm(current_user.username, current_user.email)
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.bio = form.bio.data
        current_user.location = form.location.data
        current_user.website = form.website.data
        current_user.twitter = form.twitter.data
        current_user.github = form.github.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.bio.data = current_user.bio
        form.location.data = current_user.location
        form.website.data = current_user.website
        form.twitter.data = current_user.twitter
        form.github.data = current_user.github
    return render_template('account.html', title='Account', form=form)

@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        image_filename_to_save = None
        if form.picture.data:
            saved_image_info = save_post_image(form.picture.data)
            if saved_image_info[0]: # Filename is present, success
                image_filename_to_save = saved_image_info[0]
            else: # Error occurred
                flash(f"Image upload failed: {saved_image_info[1]}", 'danger')
                return render_template('create_post.html', title='New Post', form=form, legend='New Post', **get_sidebar_data())
        
        post = Post(
            title=form.title.data,
            content=form.content.data,
            author=current_user,
            image_file=image_filename_to_save, # Use the potentially updated filename
            category_id=form.category.data,
            status=form.status.data
        )
            content=form.content.data,
            author=current_user,
            image_file=image_file,
            category_id=form.category.data,
            status=form.status.data
        )
        
        if form.status.data == 'scheduled' and form.publish_date.data:
            post.publish_date = form.publish_date.data
        
        # Handle tags
        if form.tags.data:
            tag_names = [t.strip() for t in form.tags.data.split(',')]
            for tag_name in tag_names:
                tag = Tag.query.filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(name=tag_name)
                    tag.slug = slugify(tag_name)
                    db.session.add(tag)
                post.tags.append(tag)
        
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title='New Post', form=form, legend='New Post')

@app.route("/post/<int:post_id>")
def post(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        if post.status != 'published' and (not current_user.is_authenticated or 
            (current_user != post.author and not current_user.is_admin)):
            abort(403)
        
        # Increment view count
        post.views += 1
        db.session.commit()
        
        form = CommentForm()
        return render_template('post.html', 
                             title=post.title, 
                             post=post, 
                             form=form,
                             **get_sidebar_data())
    except SQLAlchemyError as db_err:
        app.logger.error(f"Database error displaying post {post_id}: {db_err}")
        db.session.rollback() # Rollback the session in case of db error
        flash('A database error occurred while trying to load the post. Please try again later.', 'danger')
        return redirect(url_for('home'))
    except Exception as e:
        # Log the specific post_id and exception for better debugging
        app.logger.error(f"Unexpected error displaying post {post_id}: {e}", exc_info=True)
        flash('An unexpected error occurred while loading the post. Please try again later.', 'danger')
        return redirect(url_for('home'))

@app.route("/post/<int:post_id>/comment", methods=['POST'])
@login_required
def add_comment(post_id):
    post = Post.query.get_or_404(post_id)
    form = CommentForm() # request.form is automatically passed by Flask-WTF
    if form.validate_on_submit():
        parent_id_val = form.parent_id.data
        # Ensure parent_id is an integer if provided, otherwise None
        parent_id = int(parent_id_val) if parent_id_val and parent_id_val.isdigit() else None

        comment = Comment(
            content=form.content.data,
            user_id=current_user.id,
            post_id=post.id,
            parent_id=parent_id
        )
        db.session.add(comment)
        db.session.commit()
        flash('Your comment has been posted!', 'success')
    else:
        # Flash form-specific errors or a generic one
        if form.errors:
            for field, error_list in form.errors.items():
                for error in error_list:
                    flash(f"Error in {getattr(form, field).label.text if hasattr(getattr(form, field), 'label') else field}: {error}", 'danger')
        else:
            flash('Error posting comment. Please check your input.', 'danger')

    return redirect(url_for('post', post_id=post.id, _anchor='comments-section')) # Redirect to the comments section


@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        if form.picture.data:
            saved_image_info = save_post_image(form.picture.data)
            if saved_image_info[0]: # Filename is present, success
                # Delete old image if it exists and new one is successfully saved
                if post.image_file:
                    old_image_path = os.path.join(app.root_path, 'static/post_pics', post.image_file)
                    if os.path.exists(old_image_path):
                        try:
                            os.remove(old_image_path)
                        except Exception as e:
                            app.logger.error(f"Error deleting old post image {post.image_file}: {e}")
                post.image_file = saved_image_info[0]
            else: # Error occurred during new image save
                flash(f"Image upload failed: {saved_image_info[1]}", 'danger')
                # It's important to repopulate choices or any dynamic data if re-rendering
                form.category.choices = [(c.id, c.name) for c in Category.query.order_by('name')]
                return render_template('create_post.html', title='Update Post', form=form, legend='Update Post', **get_sidebar_data())

        post.title = form.title.data
        post.content = form.content.data
        post.category_id = form.category.data
        
        # Handle tags
        # Clear existing tags
        post.tags = []
        if form.tags.data:
            tag_names = [t.strip() for t in form.tags.data.split(',')]
            for tag_name in tag_names:
                tag = Tag.query.filter_by(name=tag_name).first()
                if not tag:
                    tag = Tag(name=tag_name)
                    tag.slug = slugify(tag_name)
                    db.session.add(tag)
                post.tags.append(tag)
        
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
        form.category.data = post.category_id
        form.status.data = post.status # Ensure status is pre-filled
        form.publish_date.data = post.publish_date if post.publish_date else None # Ensure publish_date is pre-filled
        # Set existing tags
        form.tags.data = ', '.join([tag.name for tag in post.tags])
    # Ensure choices are populated for GET request as well
    form.category.choices = [(c.id, c.name) for c in Category.query.order_by('name')]
    return render_template('create_post.html', title='Update Post',
                         form=form, legend='Update Post', **get_sidebar_data())

@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Custom admin index view with authentication
class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

    @expose('/')
    def index(self):
        stats = {
            'total_posts': Post.query.count(),
            'total_users': User.query.count(),
            'total_comments': Comment.query.count(),
            'total_subscribers': Newsletter.query.filter_by(is_confirmed=True).count()
        }
        recent_posts = Post.query.order_by(Post.date_posted.desc()).limit(10).all()
        return self.render('admin/dashboard.html', stats=stats, recent_posts=recent_posts)

# Custom ModelView with authentication
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        flash('You need to be an administrator to access this page.', 'danger')
        return redirect(url_for('login'))

    def _handle_view(self, name, **kwargs):
        if not self.is_accessible():
            return self.inaccessible_callback(name, **kwargs)

    # Add default list template
    list_template = 'admin/model/list.html'
    # Add default edit template
    edit_template = 'admin/model/edit.html'
    # Add default create template
    create_template = 'admin/model/create.html'

# Admin User Form
class UserAdminForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[Optional(), Length(min=6)])
    about_me = TextAreaField('About Me')
    is_admin = BooleanField('Admin')
    is_active = BooleanField('Active')

class UserAdminView(SecureModelView):
    column_list = ['username', 'email', 'is_admin', 'joined_at']
    column_searchable_list = ['username', 'email']
    column_filters = ['is_admin']
    form = UserAdminForm
    column_labels = {
        'username': 'Username',
        'email': 'Email',
        'is_admin': 'Admin',
        'joined_at': 'Joined At',
        'about_me': 'About Me'
    }
    
    def on_model_change(self, form, model, is_created):
        if is_created:
            model.set_password('default123')  # Set a default password for new users
        elif form.password.data:
            model.set_password(form.password.data)

class PostAdminForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=200)])
    content = TextAreaField('Content', validators=[DataRequired()])
    category_id = SelectField('Category', coerce=int)
    status = SelectField('Status', choices=[
        ('published', 'Published'),
        ('draft', 'Draft'),
        ('scheduled', 'Scheduled')
    ])
    author = SelectField('Author', coerce=int)
    
class PostAdminView(SecureModelView):
    column_list = ['title', 'author', 'category', 'status', 'content', 'views', 'date_posted']
    column_filters = ['status', 'author', 'category']
    column_labels = {
        'date_posted': 'Created At',
        'status': 'Status'
    }
    form = PostAdminForm

    def create_form(self):
        form = super(PostAdminView, self).create_form()
        form.category_id.choices = [(c.id, c.name) for c in Category.query.order_by('name')]
        form.author.choices = [(u.id, u.username) for u in User.query.order_by('username')]
        return form

    def edit_form(self, obj):
        form = super(PostAdminView, self).edit_form(obj)
        form.category_id.choices = [(c.id, c.name) for c in Category.query.order_by('name')]
        form.author.choices = [(u.id, u.username) for u in User.query.order_by('username')]
        return form

    def on_model_change(self, form, model, is_created):
        if is_created:
            model.author = current_user

class CategoryAdminForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description')

class CategoryAdminView(SecureModelView):
    column_list = ['name', 'description', 'posts']
    column_searchable_list = ['name', 'description']
    form = CategoryAdminForm
    column_labels = {
        'name': 'Name',
        'description': 'Description',
        'posts': 'Posts'
    }
    
    def on_model_change(self, form, model, is_created):
        model.slug = slugify(model.name)

class CommentAdminForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])

class CommentAdminView(SecureModelView):
    column_list = ['content', 'created_at', 'post', 'author']
    column_filters = ['content', 'created_at', 'post', 'author']
    column_searchable_list = ['content']
    column_labels = {
        'created_at': 'Date Posted'
    }
    form_columns = ['content', 'post', 'author']

class TagAdminForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=50)])
    description = TextAreaField('Description')

class TagAdminView(SecureModelView):
    column_list = ['name', 'description', 'slug']
    column_filters = ['name']
    column_searchable_list = ['name', 'description']
    form = TagAdminForm

    def on_model_change(self, form, model, is_created):
        if not model.slug:
            model.slug = slugify(model.name)

class NewsletterAdminForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    is_confirmed = BooleanField('Confirmed')
    token = StringField('Token', render_kw={'readonly': True})

class NewsletterAdminView(SecureModelView):
    column_list = ['email', 'is_confirmed', 'created_at']
    column_searchable_list = ['email']
    column_filters = ['is_confirmed', 'created_at']
    form = NewsletterAdminForm
    column_labels = {
        'email': 'Email Address',
        'is_confirmed': 'Confirmed',
        'created_at': 'Subscribed On'
    }
    column_formatters = {
        'created_at': lambda v, c, m, p: m.created_at.strftime('%Y-%m-%d %H:%M:%S')
    }

    def on_model_change(self, form, model, is_created):
        if is_created:
            model.token = secrets.token_urlsafe(32)

# Create admin interface
admin = Admin(
    app, 
    name='Flask Blog Admin', 
    template_mode='bootstrap4',
    index_view=MyAdminIndexView()
)
admin.add_view(UserAdminView(User, db.session, name='Users'))
admin.add_view(PostAdminView(Post, db.session, name='Posts'))
admin.add_view(CategoryAdminView(Category, db.session, name='Categories'))
admin.add_view(CommentAdminView(Comment, db.session, name='Comments'))
admin.add_view(TagAdminView(Tag, db.session, name='Tags'))
admin.add_view(NewsletterAdminView(Newsletter, db.session, name='Newsletter'))

@app.route("/make_admin/<int:user_id>")
@admin_required
def make_admin(user_id):
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    flash(f'User {user.username} has been made an admin!', 'success')
    return redirect(url_for('home'))

# Add category routes
@app.route("/category/<int:category_id>")
def category_posts(category_id):
    page = request.args.get('page', 1, type=int)
    category = Category.query.get_or_404(category_id)
    posts = Post.query.filter_by(category=category)\
        .order_by(Post.date_posted.desc())\
        .paginate(page=page, per_page=5)
    return render_template('category_posts.html', 
                         posts=posts, 
                         category=category, 
                         title=f"Posts in {category.name}",
                         **get_sidebar_data())

@app.route("/user/<string:username>")
def user_profile(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user)\
        .order_by(Post.date_posted.desc())\
        .paginate(page=page, per_page=5)
    
    # Get user's comments and likes
    comments = Comment.query.filter_by(user_id=user.id).order_by(Comment.created_at.desc()).all()
    likes = Like.query.filter_by(user_id=user.id).all()
    
    return render_template('user_profile.html', 
                          user=user, 
                          posts=posts, 
                          comments=comments,
                          likes=likes,
                          title=f"{user.username}'s Profile",
                          **get_sidebar_data())

@app.route("/follow/<string:username>")
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash(f'User {username} not found.', 'danger')
        return redirect(url_for('home'))
    if user == current_user:
        flash('You cannot follow yourself!', 'danger')
        return redirect(url_for('user_profile', username=username))
    current_user.follow(user)
    db.session.commit()
    flash(f'You are now following {username}!', 'success')
    return redirect(url_for('user_profile', username=username))

@app.route("/unfollow/<string:username>")
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash(f'User {username} not found.', 'danger')
        return redirect(url_for('home'))
    if user == current_user:
        flash('You cannot unfollow yourself!', 'danger')
        return redirect(url_for('user_profile', username=username))
    current_user.unfollow(user)
    db.session.commit()
    flash(f'You have unfollowed {username}.', 'success')
    return redirect(url_for('user_profile', username=username))

# Search form
class SearchForm(FlaskForm):
    q = StringField('Search', validators=[DataRequired()])
    submit = SubmitField('Search')

# Newsletter form
class NewsletterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    name = StringField('Name (Optional)', validators=[Optional(), Length(max=100)])
    submit = SubmitField('Subscribe')

    def validate_email(self, email):
        subscriber = Newsletter.query.filter_by(email=email.data).first()
        if subscriber:
            raise ValidationError('This email is already subscribed to our newsletter.')

# Search route
@app.route("/search")
def search():
    page = request.args.get('page', 1, type=int)
    query = request.args.get('q', '')
    
    if not query:
        return redirect(url_for('home'))
    
    # Search in posts
    posts = Post.query.filter(
        db.or_(
            Post.title.ilike(f'%{query}%'),
            Post.content.ilike(f'%{query}%')
        )
    ).filter_by(status='published').order_by(Post.date_posted.desc())
    
    # Search in tags
    tag_posts = Post.query.join(post_tags).join(Tag).filter(
        Tag.name.ilike(f'%{query}%')
    ).filter_by(status='published')
    
    # Combine results
    posts = posts.union(tag_posts).paginate(page=page, per_page=5)
    
    return render_template('search_results.html', 
                         posts=posts, 
                         query=query, 
                         title=f'Search Results for "{query}"',
                         **get_sidebar_data())

# Tag route
@app.route("/tag/<string:tag_name>")
def tag_posts(tag_name):
    page = request.args.get('page', 1, type=int)
    tag = Tag.query.filter_by(name=tag_name).first_or_404()
    posts = Post.query.join(post_tags).join(Tag).filter(
        Tag.id == tag.id,
        Post.status == 'published'
    ).order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template('tag_posts.html', 
                         posts=posts, 
                         tag=tag, 
                         title=f'Posts tagged with "{tag.name}"',
                         **get_sidebar_data())

# Newsletter routes
@app.route("/newsletter/subscribe", methods=['GET', 'POST'])
def subscribe_newsletter():
    form = NewsletterForm()
    if form.validate_on_submit():
        # Generate confirmation token
        token = secrets.token_urlsafe(32)
        
        # Create new subscriber
        subscriber = Newsletter(
            email=form.email.data,
            name=form.name.data,
            confirmation_token=token
        )
        db.session.add(subscriber)
        db.session.commit()
        
        # In a real application, you would send an email with the confirmation link
        # For this demo, we'll just confirm automatically
        subscriber.is_confirmed = True
        db.session.commit()
        
        flash('Thank you for subscribing to our newsletter!', 'success')
        return redirect(url_for('home'))
    
    return render_template('newsletter_subscribe.html', 
                         title='Subscribe to Newsletter', 
                         form=form,
                         **get_sidebar_data())

@app.route("/newsletter/confirm/<string:token>")
def confirm_newsletter(token):
    subscriber = Newsletter.query.filter_by(confirmation_token=token).first_or_404()
    subscriber.is_confirmed = True
    subscriber.confirmation_token = None
    db.session.commit()
    flash('Your newsletter subscription has been confirmed!', 'success')
    return redirect(url_for('home'))

@app.route("/newsletter/unsubscribe/<string:token>")
def unsubscribe_newsletter(token):
    subscriber = Newsletter.query.filter_by(confirmation_token=token).first_or_404()
    subscriber.is_active = False
    db.session.commit()
    flash('You have been unsubscribed from our newsletter.', 'info')
    return redirect(url_for('home'))

@app.route("/notifications")
@login_required
def notifications():
    page = request.args.get('page', 1, type=int)
    notifications = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc())\
        .paginate(page=page, per_page=10)
    
    # Mark all notifications as read
    unread_notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
    for notification in unread_notifications:
        notification.is_read = True
    db.session.commit()
    
    return render_template('notifications.html', 
                          notifications=notifications, 
                          title='Notifications',
                          **get_sidebar_data())

@app.route("/notifications/count")
@login_required
def notification_count():
    count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    return jsonify({'count': count})

@app.route("/comment/<int:comment_id>/edit", methods=['GET', 'POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    
    # Check if the current user is the author of the comment
    if comment.author != current_user:
        abort(403)
    
    form = CommentForm()
    if form.validate_on_submit():
        comment.content = form.content.data
        db.session.commit()
        flash('Your comment has been updated!', 'success')
        return redirect(url_for('post', post_id=comment.post_id))
    elif request.method == 'GET':
        form.content.data = comment.content
    
    return render_template('edit_comment.html', 
                          title='Edit Comment', 
                          form=form, 
                          comment=comment,
                          **get_sidebar_data())

@app.route("/comment/<int:comment_id>/delete", methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    
    # Check if the current user is the author of the comment
    if comment.author != current_user:
        abort(403)
    
    post_id = comment.post_id
    db.session.delete(comment)
    db.session.commit()
    flash('Your comment has been deleted!', 'success')
    return redirect(url_for('post', post_id=post_id))

# Create database tables
with app.app_context():
    db.create_all()
    
    # Create default categories if they don't exist
    categories = [
        Category(name='Technology', description='Posts about technology and programming'),
        Category(name='Lifestyle', description='Posts about daily life and experiences'),
        Category(name='Travel', description='Posts about travel and adventures'),
        Category(name='Food', description='Posts about cooking and dining'),
        Category(name='Other', description='Miscellaneous posts')
    ]
    
    for category in categories:
        if not Category.query.filter_by(name=category.name).first():
            db.session.add(category)
    
    # Create admin user if it doesn't exist
    admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com') # Use environment variable or default
    admin_password_plain = os.environ.get('ADMIN_PASSWORD', 'admin123') # Use environment variable or default

    if not User.query.filter_by(email=admin_email).first():
        admin_password = generate_password_hash(admin_password_plain, method='pbkdf2:sha256')
        admin = User(
            username='admin',
            email=admin_email,
            password=admin_password,
            is_admin=True
        )
        db.session.add(admin)
        print("Admin user created successfully!")
    else:
        print("Admin user already exists!")

    # Create default tags
    default_tags = ['Python', 'Flask', 'Web Development', 'Programming', 'Technology']
    for tag_name in default_tags:
        if not Tag.query.filter_by(name=tag_name).first():
            tag = Tag(name=tag_name)
            tag.slug = slugify(tag_name)
            db.session.add(tag)
    
    db.session.commit()

if __name__ == "__main__":
    app.run(debug=True)