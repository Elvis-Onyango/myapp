from flask import Flask,flash, render_template,url_for,request,redirect, jsonify,session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_bcrypt import check_password_hash
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from sqlalchemy.exc import IntegrityError



app = Flask(__name__,template_folder='templates',static_folder='static')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '@onyango123'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
  id = db.Column(db.Integer, primary_key = True)
  name = db.Column(db.String(50), nullable=False, unique=True)
  email = db.Column(db.String(50), nullable=False, unique=True)
  password = db.Column(db.String(50), nullable=False, unique=True)
  date = db.Column(db.DateTime, default=datetime.utcnow)

  def __init__(self, name, email, password):
      self.name = name
      self.email = email
      self.password = password

def set_password(self, password):
    self.password = bcrypt.generate_password_hash(password).decode('utf-8')

@app.route('/')
def index():
  return render_template('index.html')

@app.route('/main')
def main():
  return render_template('main.html')

@app.route('/about')
def about():
  return render_template('about.html')

@app.route('/help')
def help():
  return render_template('help.html')


@app.route('/contact')
def contact():
  return render_template('contact.html')

@app.route('/article')
def article():
  return render_template('articles.html')

@app.route('/register_file')
def register_file():
  return render_template('register.html')
@app.route('/login_file')
def login_file():
  return render_template('login.html')


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        name = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(name=name, email=email, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash("User registered successfully.", 'success')
            return redirect(url_for('login'))
        except IntegrityError as e:
            db.session.rollback()
            print(f"Error: {e}")
            flash("User with the same email already exists", 'danger')

        return redirect(url_for('register')) 
    else:
        return render_template('register.html')  


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            flash('Login successful!', 'success')
            return redirect(url_for('main'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
            return redirect(url_for('index'))
    else:
        return render_template('login.html')  
      
@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/items')
def items():
    items = User.query.all() 
    return render_template('items.html', items=items)

if __name__ =='__main__':
  with app.app_context():
    db.create_all()
  app.run(debug = True,host='0.0.0.0',port = 80)
