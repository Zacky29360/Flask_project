from flask import Blueprint, render_template, request, flash, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, current_user
from .models import User
from . import db

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['POST', 'GET'])
def login():    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password): #ubah user.password jadi User.password
                flash('Logged In successfully', category='success')
                login_user(user, remember=True)
                return redirect(url_for("views.home"))
            else:
                flash('Incorrect Password, try again!', category='error')
        else:
            flash('Email does not exist!', category='error')
            
    return render_template("login.html", user=current_user)

@auth.route('/sign-up', methods=['POST', 'GET'])
def sign_up():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        
        user = User.query.filter_by(email=email).first()
        if len(username) < 3:
            flash('Username must be greater than 2 character!', category='error')
        elif len(email) < 3:
            flash('Email must be greater than 2 character!', category='error')
        elif user:
            flash('Email already exist!', category='error')
        elif len(password1) < 5:
            flash('Password must be greater than 4 character!', category='error')
        elif password1 != password2:
            flash('Password don\'t match!', category='error')
        else:
            new_user = User(username=username, email=email, password=generate_password_hash(password1, method='pbkdf2:sha256'))           
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account successfully created', category='success')
            
            return redirect(url_for("views.home"))
        
    return render_template("sign_up.html", user=current_user)