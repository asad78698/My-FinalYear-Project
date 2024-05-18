from flask import Flask, render_template, url_for, request, flash, redirect, session
from sqlinjection import scan_sql_injection
from urllib.parse import unquote 
from apiendpoint import analyze_endpoints
from openredirect import is_open_redirect
from crosssitescriptting import crosssitescripting_result
from securityheaders import check_http_security_headers
from securitymisconfig import check_security_misconfiguration
from tls import check_tls_security
from pymongo import  MongoClient
from datetime import datetime

client = MongoClient('localhost', 27017)
db = client['fyp']
userCollection = db['users']

app = Flask(__name__)
app.secret_key = '589714'

nouser = 'Account Does Not Exist'

@app.route('/')

def index():
    return render_template('frontpage.html')


@app.route('/loginpage', methods=['GET', 'POST'])
def loginpage():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if userCollection.find_one({'username': username, 'password': password}):
            session['loggedin'] = True
            session['username'] = username
            session['password'] = password
        
            return redirect(url_for('sql'))
        
        else:
           error = 'Account Does Not Exist'

    return render_template('newlogin.html', error = error )

@app.route('/logout')
def logout():   
    session.pop('loggedin', None)
    return redirect(url_for('loginpage'))


@app.route('/signuppage', methods=['GET', 'POST'])
def signup():
    alreadyEmail = 'Email already exists'
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']
        if userCollection.find_one({'email': email}):  # Check if email already exists
            return alreadyEmail
        else:
         userCollection.insert_one({
            'username': username,
            'email': email,
            'password': password,
            'confirm': confirm,
            'url': []
        })
        return redirect(url_for('confirmaccount'))

    return render_template('newregister.html')

@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    global nouser
    if request.method == 'POST':
        email = request.form['email']
        oldpassword = request.form['oldpassword']
        newpassword = request.form['newpassword']
        user = userCollection.find_one({'email': email, 'password': oldpassword})
        if user:
            userCollection.update_one({'email': email}, {'$set': {'password': newpassword, 'confirm': newpassword}})
            return redirect(url_for('loginpage'))
        else:
            return render_template('restpassword.html', error = nouser)
    
    return render_template('restpassword.html')
            

@app.route('/profile')
def profile():
    if session.get('loggedin'):
        user_data = userCollection.find_one({'username': session['username']})
        urls = user_data.get('url', [])  # Get all URLs associated with the username
        return render_template('profile.html', username=session['username'], email=user_data['email'], urls=urls)
    else:
        return redirect(url_for('loginpage'))

@app.route('/confirmaccount')
def confirmaccount():
    return render_template('confrimaccount.html')


@app.route('/sqlinjection')
def sql():
 if session.get('loggedin'):
  return render_template('sqlinjection.html', username=session['username']) 
 else:
  return redirect(url_for('loginpage'))

@app.route('/getinputsql', methods=['POST'])
def getinput():
    ip_address = request.remote_addr
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            userCollection.update_one({'username': session['username']}, {'$push': {'url': "Scanned For SQL Injection : " +user_input+ " at " + str(datetime.now())+ " from Ip Address : " + ip_address}})
            user_input = unquote(user_input.replace('%22', ''))
            resultforms = scan_sql_injection(user_input)
            
            return render_template('sqlinjection.html', result1=resultforms, username=session['username']) 
        else:
            return "NO INPUT RECEIVED", 404

@app.route('/apiendipoint')
def apiendipoint():
    if session.get('loggedin'):
        return render_template('apiendpoint.html', username=session['username'])
    else:
        return redirect(url_for('loginpage'))

@app.route('/getinputapi', methods=['POST'])
def getinputapi():
    ip_address = request.remote_addr
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            userCollection.update_one({'username': session['username']}, {'$push': {'url': "Scanned For Api Endpoints : " +user_input+ " at " + str(datetime.now()) + " from Ip Address : " + ip_address}})
            user_input = unquote(user_input.replace('%22', ''))
            apiresult = analyze_endpoints(user_input)
            return render_template('apiendpoint.html', resultapi=apiresult, username=session['username'])
        else:
            return "No Input Provides.", 404


@app.route('/openredirect')
def openredirect():
    if session.get('loggedin'):
        return render_template('openredirect.html', username=session['username'])
    else:
        return redirect(url_for('loginpage'))

@app.route('/getinputopenredirect', methods=['POST'])
def getinputopenredirect():
    ip_address = request.remote_addr
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            userCollection.update_one({'username': session['username']}, {'$push': {'url': "Scanned For Open Redirects : " +user_input+ " at " + str(datetime.now()) + " from Ip Address : " + ip_address}})
            openredirectresult = is_open_redirect(user_input)
            return render_template('openredirect.html', resultopenredirect=openredirectresult , username=session['username'])
        else:
            return "No Input Provides.", 404

@app.route('/crosssitescripting')
def crosssitescripting():
    if session.get('loggedin'):
        return render_template('crosssitescriptting.html', username=session['username'])
    else:
        return redirect(url_for('loginpage'))

@app.route('/getinputcrosssitescriptting', methods=['POST'])
def getinputcrosssitescriptting():
    ip_address = request.remote_addr
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            userCollection.update_one({'username': session['username']}, {'$push': {'url': "Scanned For Cross Site : " +user_input+ " at " + str(datetime.now()) + " from Ip Address : " + ip_address}})
            crosssites_result = crosssitescripting_result(user_input)
            return render_template('crosssitescriptting.html', result_crosssite=crosssites_result , username=session['username'])
        else:
            return "No Input Provides.", 404


@app.route('/securityheaders')
def securityheaders():
    if session.get('loggedin'):
        return render_template('securityheaders.html', username=session['username'])
    else:
        return redirect(url_for('loginpage'))

@app.route('/getinput_SecurityHeaders', methods = ['POST'])
def getinput_SecurityHeaders():
     ip_address = request.remote_addr
     if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            userCollection.update_one({'username': session['username']}, {'$push': {'url': "Scanned For Security Headers: " +user_input + " at " + str(datetime.now()) + " from Ip Address : " + ip_address}})
            headers_results = check_http_security_headers(user_input)
            return render_template('securityheaders.html', result_headers = headers_results , username=session['username'])
        else:
            return "No Input Provides.", 404

@app.route('/securitymisconfig')
def securitymisconfig():
    if session.get('loggedin'):
        return render_template('securitymisconfig.html', username=session['username'])
    else:
        return redirect(url_for('loginpage'))

@app.route('/securitymisconfiginput', methods = ['POST'])
def securitymisconfiginput():
    ip_address = request.remote_addr
    if request.method == 'POST':
     user_input = request.form.get('url')
     if(user_input):
         userCollection.update_one({'username': session['username']}, {'$push': {'url': "Scanned For Security Misconfig: " +user_input + " at " + str(datetime.now()) + " from Ip Address : " + ip_address}})
         securitymisconfig_result = check_security_misconfiguration(user_input)
         return render_template('securitymisconfig.html', result_securitymisconfig=securitymisconfig_result , username=session['username'])
     else:
         return ' No Input Found', 404
     
    
@app.route('/tls')
def tls():
    if session.get('loggedin'):
        return render_template('tls.html', username=session['username'])
    else:
        return redirect(url_for('loginpage'))

@app.route('/tlsinput',  methods = ['POST'])
def tlsinput():
    ip_address = request.remote_addr
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            userCollection.update_one({'username': session['username']}, {'$push': {'url': "Scanned For Tls : " +user_input+ " at " + str(datetime.now()) + " from Ip Address : " + ip_address}})
            tls_result = check_tls_security(user_input)
            return render_template('tls.html', result_tls = tls_result , username=session['username'])
    else:
         return ' No Input Found', 404



@app.route('/userguide')
def userguide():
    return render_template('usergenerated.html')

if __name__ == "__main__":
     app.run(debug=True)
