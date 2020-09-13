from flask import Flask, url_for, request, session, redirect, jsonify
from flask_pymongo import PyMongo
from functools import wraps
from bson import json_util
from flask_bcrypt import Bcrypt
import dns
import json

app = Flask(__name__)
app.secret_key = 'okeechobee'
app.config['MONGO_URI'] = 'mongodb+srv://admin:password!@cluster0.2d4yb.mongodb.net/hacker-news?retryWrites=true&w=majority'
mongo = PyMongo(app)
bcrypt = Bcrypt(app)

def checkLoggedIn():
    def check(func):
        @wraps(func)
        def inner(*args, **kwargs):
            if 'username' in session:
                return func(*args, **kwargs)
            else:
                return jsonify({"error":"please login before accessing this page"})
        return inner
    return check               
          
@app.route('/home', methods = ['POST', 'GET'])
def index():
    if 'username' in session:
        return jsonify({'status': session['username']})
    return jsonify({'status': 'load home page'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return jsonify({'status': 'logged in' })
    if request.method == 'POST':
        users = mongo.db.users
        login_user = users.find_one({'username' : request.form['username']})
        if login_user:
            pw_hash = bcrypt.check_password_hash(login_user['password'],request.form['password'])
            if pw_hash:
                session['username'] = request.form['username']
                return jsonify({ 'status' : 'login Successful'})
            else:
                return jsonify({'status': 'incorrect password'})
        return jsonify({'status': 'username does not exist' })
    return jsonify({'status' : 'load login page' })

@app.route('/signUp', methods=['POST', 'GET'])
def signup():
    session.pop('username', None)
    if request.method == 'POST':
        users = mongo.db.users
        existing_user = users.find_one({'username':request.form['username']})
        if existing_user is None:
            hashpass = bcrypt.generate_password_hash(request.form['password'])
            users.insert({
                    'username' : request.form['username'],
                    'password' : hashpass}
                    )
            session['username'] = request.form['username']
            return jsonify({'status' : 'registration successful'})
        return jsonify({'status' : 'username already exists'})
    return jsonify({ 'status': 'load registration page' })

@app.route('/submit', methods = ["POST", "GET"])
@checkLoggedIn()
def submit():
    if request.method == "POST":
        if 'username' in session:
            text = request.form['text']
            author = session['username']
            url = request.form['url']
            name = request.form['name']
            comment_id = request.form['id']
            mongo.db.comments.insert({'id': comment_id, 'author': author, 'name':name, 'url': url, 'text': text })
            return jsonify({'status': 'your comment has been recorded'})
        return jsonify({'status': 'you must login to submit'})
    return jsonify({'status': 'load comment submit page'})

@app.route('/comments', methods = ["GET", "POST"])
def comment():
    comments = mongo.db.comments
    if request.method == "POST":
        if request.form['action'] == 'delete':
            comments.delete_one({'id': request.form['id']})
            return jsonify({'status': 'comment'  + str(request.form['id']) +  " successfully deleted"})
        else:
            new_text = request.form['text']
            comments.update_one({'id': request.form['id']},{'$set':{'text': new_text} })
            return jsonify({'status': 'your comment was updated'})
    com = comments.find()
    response = []
    for c in com:
        c['_id'] = str(c['_id'])
        response.append(c)
    return jsonify(response)


@app.route('/logout',methods=['GET'])
@checkLoggedIn()
def logout():
    session.pop('username')
    return jsonify({'status':'logout'})

if __name__ == '__main__':
    app.run(debug=True)