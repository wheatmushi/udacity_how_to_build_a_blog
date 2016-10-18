import webapp2
import re
import jinja2
import os
import string
import random
import hashlib
import json
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)
PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return PASS_RE.match(password)
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email)

def make_salt():
    return ''.join(random.choice(string.letters) for x in range(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    return make_pw_hash(name, pw, h[-5:]) == h

def valid_cookies(user_id):
    if user_id:
        username = user_id.split('|')[0]
        user = User.by_name(name=username)
        if user and user_id.split('|')[1] == user.password.split('|')[0]:
            return True
    return False

def get_username_from_cookies(user_id):
    if valid_cookies(user_id):
        user = User.by_name(name= user_id.split('|')[0])
        return user.username
    else:
        return None

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = False)

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('username =', name).get()
        return u

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    username = db.StringProperty(required=True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Signup(Handler):
    params = {'username':'', 'email':'', 'err_username':'', 'err_password':'','err_verify':'','err_email':''}

    def get(self):
        user_id = self.request.cookies.get('user_id')
        if valid_cookies(user_id):
                self.redirect('/blog/welcome')
        else:
            self.render('signup-page.html', params = self.params)

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        self.params['username'] = username
        self.params['email'] = email

        user = User.by_name(name=username)

        if not valid_username(username):
            self.params['err_username'] = 'not valid username'
            have_error = True
        if not valid_password(password):
            self.params['err_password'] = 'not valid pass'
            have_error = True
        elif password != verify:
            self.params['err_verify'] = 'pass did\'t match'
            have_error = True
        if not valid_email(email):
            self.params['err_email'] = 'not valid email'
            have_error = True

        if have_error:
            self.render('signup-page.html', params = self.params)
        else:
            if not user:
                pass_hashed = make_pw_hash(username, password)
                new_user = User(username=username, password=pass_hashed, email=email)
                new_user.put()
                self.response.headers.add_header('Set-Cookie', str('user_id=%s|%s' % (username, pass_hashed.split('|')[0])))
                self.redirect('/blog/welcome')
            else:
                self.params['err_username'] = 'username already taken'
                self.render('signup-page.html', params = self.params)

class Welcome(Handler):
    def get(self):
        user_id = self.request.cookies.get('user_id')
        if valid_cookies(user_id):
            self.render('welcome-page.html', username = user_id.split('|')[0])
        else:
            self.redirect('/blog/login')

class Login(Handler):
    params = {'username':'', 'error':''}

    def get(self):
        user_id = self.request.cookies.get('user_id')
        if valid_cookies(user_id):
                self.redirect('/blog/welcome')
        else:
            self.render('login-page.html', params = self.params)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        self.params['username']=username
        user = User.by_name(name=username)

        if user and valid_pw(username, password, user.password):
            self.response.headers.add_header('Set-Cookie', str('user_id=%s|%s' % (username, user.password.split('|')[0])))
            self.redirect('/blog/welcome')
        else:
            self.params['error']='incorrect data'
            self.render('login-page.html', params = self.params)


class BlogMainPage(Handler):
    def get(self):
        user_id = self.request.cookies.get('user_id')
        if not valid_cookies(user_id):
            self.redirect('/blog/login')
        query = db.GqlQuery('select * from Post order by created desc')
        self.render('main-page.html', query=query)

class NewPost(Handler):
    def render_form(self, subject='', content = '', error = ''):
        self.render('post-form.html', subject = subject, content = content, error = error)

    def get(self):
        user_id = self.request.cookies.get('user_id')
        if not valid_cookies(user_id):
            self.redirect('/blog/login')
        self.render_form()

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')
        user_id = self.request.cookies.get('user_id')
        username = get_username_from_cookies(user_id)
        if subject and content and username:
            new_post = Post(subject = subject, content = content, username = username)
            new_post.put()
            self.redirect('/blog/' + str(new_post.key().id()))
        else:
            error = 'some fields/cookies r empty'
            self.render_form(subject, content, error)

class SinglePost(Handler):
    def get(self, post_id):
        subject = Post.get_by_id(int(post_id)).subject
        content = Post.get_by_id(int(post_id)).content
        self.render('single-post.html', subject = subject, content = content)

class SingePostJson(Handler):
    def get(self, post_id):



class Loguot(Handler):
    def get(self):
        self.response.set_cookie('user_id', '', path='/blog/')
        self.redirect('/blog/signup')

app = webapp2.WSGIApplication([
    ('/blog/signup',    Signup),
    ('/blog/welcome',   Welcome),
    ('/blog/login',     Login),
    ('/blog',           BlogMainPage),
    ('/blog/.json',    BlogMainPageJson),
    ('/blog/newpost',   NewPost),
    ('/blog/(\d+)',     SinglePost),
    ('/blog/(\d+).json',SinglePostJson),
    ('/blog/logout',    Loguot)
], debug=True)
