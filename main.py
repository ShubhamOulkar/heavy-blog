from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date, datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import LoginForm, RegisterForm, CreatePostForm, CommentForm, EditPostForm, ForgetPass
import smtplib
import random
from letter_numbers import letters, numbers
import os


my_email = 'oulkarshubhu@gmail.com'
password = os.environ.get('password')
passcode_send = ''
email = ''

year = datetime.now().year

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CONFIGURE TABLE
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")
    updated_date = db.Column(db.String(250))


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    comment_author = relationship("User", back_populates="comments")
    text = db.Column(db.Text, nullable=False)
    comment_date = db.Column(db.String(250), nullable=False)


with app.app_context():
    db.create_all()


# def admin_only(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         if current_user.id != 1:
#             return abort(403)
#         return f(*args, **kwargs)
#     return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user, year=year)



@app.route('/welcome', methods=['GET', 'POST'])
def welcome():
    all_post = BlogPost.query.all()
    return render_template('welcome.html', current_user=current_user, year=year, list_post = all_post)



@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            print(User.query.filter_by(email=form.email.data).first())
            #User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("welcome"))

    return render_template("register.html", form=form, current_user=current_user, year=year)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('welcome'))
    return render_template("login.html", form=form, current_user=current_user, year=year)


@app.route("/forgetpass", methods=["GET", "POST"])
def forgetpass():
    form = ForgetPass()
    if form.validate_on_submit():
        global email
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if not user:
            flash("That email is not registerd, please try valid email.")
            return redirect(url_for('forgetpass'))
        else:
            global passcode_send
            words = random.sample(letters,3)
            numb = random.sample(numbers, 3)
            passcode_send = words + numb
            random.shuffle(passcode_send)
            passcode_send = ''.join(passcode_send)
            flash("Verification code is send to your email.")
            with smtplib.SMTP('smtp.gmail.com') as connections:
                connections.starttls()
                connections.login(user=my_email, password=password)
                connections.sendmail(from_addr=my_email,
                                    to_addrs=email,
                                    msg=f"Subject: Heavy Blogs Verification Code  \n\n Your Verification Code: {passcode_send}")
            return render_template('verify.html',year=year)
    if request.method == 'POST':
            passcode_receive = request.form.get('passcode')
            if passcode_send == passcode_receive:
                flash("Verified")
                return render_template('resetpassword.html', email = email, verified = True)
            else:
                flash('Can not verify, try again.')  
                return redirect(url_for('forgetpass'))  
    
    return render_template('forgetpass.html', form=form, year=year)


@app.route('/resetpassword/<verified>', methods=["GET", "POST"])
def resetpassword(verified):
    if verified :
        if request.method == 'POST':
            if request.form.get('newpassword') == request.form.get('confirmpassword'):
                flash('We successfully reset your password.')
                hash_and_salted_password = generate_password_hash(
                    request.form.get('confirmpassword'),
                    method='pbkdf2:sha256',
                    salt_length=8
                ) 
                user = User.query.filter_by(email = request.form.get('email')).first()
                print(user)
                user.email = email
                user.password = hash_and_salted_password
                db.session.commit()  
                return redirect(url_for('login'))  
    else:
        flash('Please Varify Your account')
        return redirect(url_for('forgetpass'))
    return render_template('resetpassword.html') 
    


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    
    requested_post = BlogPost.query.get(post_id)

    if request.method == "POST":
        data = request.form
        new_comment = Comment(
            text= data['comment'],
            comment_author=current_user,
            parent_post=requested_post,
            comment_date = date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_comment)
        db.session.commit()

    return render_template("post.html", post=requested_post, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user, year=year)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        data = request.form
        email= f'Subject: Mail from my web \n\nName: {data["name"]} \nemail: {data["email"]} \ncontact no.: {data["phone"]} \nMessage: {data["message"]}'
        with smtplib.SMTP('smtp.gmail.com') as connections:
            connections.starttls()
            connections.login(user=my_email, password=password)
            connections.sendmail(from_addr=my_email,
                                 to_addrs=my_email,
                                 msg= email)
        return render_template("contact.html", msg_sent=True, year=year)
    return render_template("contact.html", year=year, msg_sent=False)


@app.route("/new-post", methods=["GET", "POST"])
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))

    return render_template("make-post.html", form=form, current_user=current_user, year=year)




@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = EditPostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user,
        body=post.body,
        updated_date = post.updated_date

    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        post.updated_date = edit_form.updated_date.data.strftime("%B %d, %Y")
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user, year=year)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))



if __name__ == "__main__":
    app.run(debug=True)
