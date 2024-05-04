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
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']
        userCollection.insert_one({
            'username': username,
            'email': email,
            'password': password,
            'confirm': confirm
        })
        return redirect(url_for('loginpage'))

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
            


@app.route('/sqlinjection')
def sql():
 if session.get('loggedin'):
  return render_template('sqlinjection.html', username=session['username']) 
 else:
  return redirect(url_for('loginpage'))

@app.route('/getinputsql', methods=['POST'])
def getinput():
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
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
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
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
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
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
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
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
     if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
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
    if request.method == 'POST':
     user_input = request.form.get('url')
     if(user_input):
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
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            tls_result = check_tls_security(user_input)
            return render_template('tls.html', result_tls = tls_result , username=session['username'])
    else:
         return ' No Input Found', 404


if __name__ == "__main__":
     app.run(debug=True)
