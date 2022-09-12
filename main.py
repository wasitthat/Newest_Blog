from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy import ForeignKey
import os
is_admin = False
app = Flask(__name__)

ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


login_manager = LoginManager()
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL_ONE', 'sqlite:///blog.db')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    users=relationship('User', back_populates='works')
    comments = relationship('Comment', back_populates='blog_posts')

#db.create_all()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    works = relationship("BlogPost", back_populates="users")
    comments = relationship('Comment', back_populates='users')
    name = db.Column(db.String(250), nullable=False)
    email=db.Column(db.String(250), unique=True, nullable=False)
    password=db.Column(db.String(250), nullable=False)



class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    users=relationship("User", back_populates="comments")
    blog_posts = relationship("BlogPost", back_populates="comments")
    post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
#db.drop_all()
db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        password = generate_password_hash(form.password.data, method = "pbkdf2:sha256", salt_length=8)
        if User.query.filter_by(email=form.email.data).first():
            flash('Login with that email.')
            return render_template('login.html',form=form, current_user=current_user)
        user=User()
        user.name=form.name.data
        user.email=form.email.data
        user.password=password
        db.session.add(user)
        db.session.commit()
        return render_template('index.html', all_posts=BlogPost.query.all(), current_user=current_user)
    if form.errors:
        for each in form.errors:
            print('each: ')
            print(each)
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # fill out form and verify password match with db
        user = User.query.filter_by(email = form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return render_template('index.html', all_posts = BlogPost.query.all(), current_user=current_user)
            else:
                flash('Incorrect password or email')
        else:
            flash('No account exists for that login information.')
    return render_template("login.html", current_user=current_user, form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    form = CommentForm()
    if form.validate_on_submit():
        comment=Comment()
        comment.text = form.comment.data
        comment.user_id = current_user.id
        print(comment.post_id)
        comment.post_id = post_id
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id, current_user=current_user ))
    requested_post = BlogPost.query.get(post_id)
    all_comments = Comment.query.all()
    return render_template("post.html", form=form, post=requested_post, current_user=current_user, all_comments=all_comments)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)



def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


@app.route("/new-post", methods=['POST', 'GET'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            author_id = current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)

@app.route("/edit-post/<int:post_id>")
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id, current_user=current_user))
    return render_template("make-post.html", form=edit_form, current_user=current_user)

@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    comments = Comment.query.all()
    for each in comments:
        print(each.id)
        if each.post_id == post_id:
            print(each.post_id)
            comment_to_delete = Comment.query.get(each.id)
            db.session.delete(comment_to_delete)
            db.session.commit()
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
