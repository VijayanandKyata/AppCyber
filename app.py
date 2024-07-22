from flask import Flask, flash, request, redirect, url_for, render_template
import urllib.request
import os
from werkzeug.utils import secure_filename
import cv2
import pickle
import imutils
import sklearn
from flask import Flask, render_template, request, redirect, url_for,session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import re
from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
from sklearn.metrics import confusion_matrix
warnings.filterwarnings('ignore')

from feature import *
from sqlalchemy import func
from sqlalchemy import or_


# Configuring Flask
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = "secret key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///breach.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False




#importing required libraries
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn import metrics 
import warnings
warnings.filterwarnings('ignore')
import pickle
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import plotly.graph_objects as go

def train():
    # Loading data into dataframe
    data = pd.read_csv("phishing.csv")
    data = data.drop(['Index'],axis = 1)
    X = data.drop(["class"],axis =1)
    y = data["class"]
    
    # Splitting the dataset into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size = 0.2, random_state = 42)
    
    # Random Forest Classifier Model
    forest = RandomForestClassifier(n_estimators=10) 
    forest.fit(X_train,y_train)
    
    # Predictions
    y_train_forest = forest.predict(X_train)
    y_test_forest = forest.predict(X_test)
    
    # Evaluation Metrics
    acc_train_forest = metrics.accuracy_score(y_train,y_train_forest)
    acc_test_forest = metrics.accuracy_score(y_test,y_test_forest)
    f1_score_train_forest = metrics.f1_score(y_train,y_train_forest)
    f1_score_test_forest = metrics.f1_score(y_test,y_test_forest)
    recall_score_train_forest = metrics.recall_score(y_train,y_train_forest)
    recall_score_test_forest = metrics.recall_score(y_test,y_test_forest)
    
    # Printing the evaluation metrics
    print("Random Forest : Accuracy on training Data: {:.3f}".format(acc_train_forest))
    print("Random Forest : Accuracy on test Data: {:.3f}".format(acc_test_forest))
    print("Random Forest : f1_score on training Data: {:.3f}".format(f1_score_train_forest))
    print("Random Forest : f1_score on test Data: {:.3f}".format(f1_score_test_forest))
    print("Random Forest : Recall on training Data: {:.3f}".format(recall_score_train_forest))
    print("Random Forest : Recall on test Data: {:.3f}".format(recall_score_test_forest))
    
    # Saving the trained model
    pickle.dump(forest, open('models/model.pkl', 'wb'))
    
    # Confusion Matrix
    confusion_matrix_data = confusion_matrix(y_test, y_test_forest)
    
    # Plot Confusion Matrix using Seaborn
    plt.figure(figsize=(8, 6))
    sns.heatmap(confusion_matrix_data, annot=True, cmap='viridis', fmt='g')
    plt.title('Confusion Matrix')
    plt.xlabel('Predicted label')
    plt.ylabel('True label')
    
    # Save the confusion matrix plot as an image
    plt.savefig('static/confusion_matrix.png')
    
    # Writing evaluation metrics to results.csv
    results = pd.DataFrame({'Metric': ['Accuracy', 'F1 Score', 'Recall'],
                            'Training': [acc_train_forest, f1_score_train_forest, recall_score_train_forest],
                            'Test': [acc_test_forest, f1_score_test_forest, recall_score_test_forest]})
    return results





def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


########################### Routing Functions ########################################

@app.route('/')
def home():
    return render_template('homepage.html')




@app.route('/services')
def services():
    return render_template('services.html')



@app.route('/contact')
def contact():
    return render_template('contact.html')




@app.route('/adddata')
def adddata():
    return render_template('adddata.html')


@app.route('/about')
def about():
    return render_template('about.html')


# No caching at all for API endpoints.
@app.after_request
def add_header(response):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1'
    response.headers['Cache-Control'] = 'public, max-age=0'
    return response




# file = open("pickle/model4.pkl","rb")
# gbc = pickle.load(file)
# file.close()



db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Breach(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    entity = db.Column(db.String(255))
    year = db.Column(db.Integer)
    records = db.Column(db.String(255))
    organization_type = db.Column(db.String(255))
    methods = db.Column(db.String(255))
    url = db.Column(db.String(2048))
    time = db.Column(db.String(255))
    attacktype = db.Column(db.String(255))

    def __repr__(self):
        return f"<Breach(entity='{self.entity}', year='{self.year}', records='{self.records}', organization_type='{self.organization_type}', methods='{self.methods}', url='{self.url}', time='{self.time}', type='{self.attacktype}')>"

    
    # def __repr__(self):
    #     return f'<User {self.username}>'
# @app.before_first_request
# def create_tables():
#     db.create_all()


@app.route('/urlhome')
def urlhome():
    return render_template('urlhome.html')


@app.route('/urlsignup', methods=['GET', 'POST'])
def urlsignup():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'confirm_password' in request.form:
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        account = User.query.filter_by(username=username).first()
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must not contain any special characters!'
        elif not username or not password or not confirm_password:
            msg = 'Please fill out the form !'
        elif password != confirm_password:
            msg = 'Passwords do not match.'
        else:
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            msg = 'You have successfully registered!'
            # return render_template('signup.html', msg=msg)
    elif request.method == 'POST':
        msg = 'Please fill out the form !'
        return redirect(url_for('urllogin'))
    return render_template('urlsignup.html',msg=msg)

@app.route('/urllogin', methods=['GET', 'POST'])
def urllogin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        session['logged_in'] = True
        session['username'] = username
        global user
        user = User.query.filter_by(username=username).first()
        if not user or user.password != password:
            error = 'Invalid username or password.'
            return render_template('urllogin.html', error=error)
        #return redirect(url_for('upload'))
        return render_template('urlpredict.html')
    return render_template('urllogin.html')

file = open("models/modelr.pkl","rb")
gbc = pickle.load(file)
file.close()



@app.route("/predict", methods=["GET", "POST"])
def predict():
    if request.method == "POST":

        url = request.form["url"]
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1,30) 

        y_pred =gbc.predict(x)[0]
        #1 is safe       
        #-1 is unsafe
        y_pro_phishing = gbc.predict_proba(x)[0,0]
        y_pro_non_phishing = gbc.predict_proba(x)[0,1]
        # if(y_pred ==1 ):
        pred = "It is {0:.2f} % safe to go ".format(y_pro_phishing*100)
        return render_template('urlpredict.html',xx =round(y_pro_non_phishing,2),url=url )
    return render_template("urlpredict.html", xx =-1)



@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return render_template("login.html") 
 
@app.route('/process', methods=['POST'])
def process_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    if file:
        # Save the file to the upload folder
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # Read the uploaded CSV file
        df = pd.read_csv(file_path)

        # Render the template with the entire DataFrame
        return render_template('displaycsv.html', data=df)

# Route to display the training page
@app.route('/train', methods=['GET', 'POST'])
def train_page():
    
        # Call the train function
    results=train()
    results.to_csv('results.csv')
        # Load results from results.csv
    results_df = pd.read_csv('results.csv')
        # Render the training page with the results
    return render_template('training.html', results=results.to_dict(orient='records'))
    #return render_template('training.html', results=None)

@app.route('/cm')
def cm():
    return render_template('cm.html')

# Function to read performance metrics from results.csv
def read_performance_data():
    # Read the CSV file into a DataFrame
    df = pd.read_csv('results.csv')
    # Extract the performance metrics data
    performance_data = {
        'labels': df['Metric'].tolist(),
        'training': df['Training'].tolist(),
        'test': df['Test'].tolist()
    }
    return performance_data

@app.route('/pag')
def performance_analysis_graph():
    # Call the function to read performance data from results.csv
    performance_data = read_performance_data()
    return render_template('pag.html', performance_data=performance_data)


@app.route('/landing')
def landing():
    return render_template('landing.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error=''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        session['logged_in'] = True
        session['username'] = username
        global user
        user = User.query.filter_by(username=username).first()
        if not user or user.password != password:
            error = 'Invalid username or password.'
            return render_template('login.html', error=error)
        #return redirect(url_for('upload'))
        return render_template('dataadd.html')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    msg = ''
    c=0
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'cpassword' in request.form:
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['cpassword']
        account = User.query.filter_by(username=username).first()
        if account:
            msg = 'Account already exists !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = 'Username must not contain any special characters!'
        elif not username or not password or not confirm_password:
            msg = 'Please fill out the form !'
        elif password != confirm_password:
            msg = 'Passwords do not match.'
        else:
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            c=1
            msg = 'You have successfully registered!'
            #return render_template('signup.html', msg=msg)
    elif request.method == 'POST':
        msg = 'Please fill out the form !'
        return redirect(url_for('signup'))
    if c==1:
        return render_template('login.html')
    return render_template('signup.html',error=msg)

def determine_attack_type(txt):  # Changed from "text" to "txt"
        attack1 = ['IPid', 'FDDI', 'x25', 'rangingdistance']
        attack2 = ['tcpchecksum', 'mtcp', 'controlflags', 'tcpoffset', 'tcpport']
        attack3 = ['ICMPID', 'udptraffic', 'udpunicorn', 'datagramid', 'NTP', 'RIP', 'TFTP']
        attack4 = ['GETID', 'POSTID', 'openBSD', 'appid', 'sessionid', 'transid', 'physicalid']
        attack5 = ['SYN', 'ACK', 'synpacket', 'sycookies']
        attack6 = ['serverattack', 'serverid', 'blockbankwidth']
        attack7 = ['monlist', 'getmonlist', 'NTPserver']
        attack8 = ['portid', 'FTPID', 'tryion', 'fragflag']
        attack9 = ['malwareid', 'gethttpid', 'httpid']

        attacks = [attack1, attack2, attack3, attack4, attack5, attack6, attack7, attack8, attack9]

        count = [sum(1 for f in re.findall(r"[\w']+", txt) if f in attack) for attack in attacks]
        max_count = max(count)
        
        if max_count == 0:
            return "Unmalware"

        attack_names = [
            "Man-in-the-middle (MitM) attack",
            "Phishing and spear phishing attacks",
            "Drive-by attack",
            "Password attack",
            "SQL injection attack",
            "Cross-site scripting (XSS) attack",
            "Eavesdropping attack",
            "Birthday attack",
            "Teardrop attack"
        ]

        return attack_names[count.index(max_count)]


@app.route('/uploaddata', methods=['POST','GET'])
def upload():
    entity = request.form['entity']
    year = int(request.form['year'])
    records = request.form['records']
    organization_type = request.form['organization_type']
    methods = request.form['methods']
    url = request.form['url']
    time = request.form['time']
    attacktype = determine_attack_type(request.form['url'])

    record = Breach(
        entity=entity,
        year=year,
        records=records,
        organization_type=organization_type,
        methods=methods,
        url=url,
        time=time,
        attacktype=attacktype
    )
    db.session.add(record)
    db.session.commit()

    return render_template('dataadd.html')

@app.route('/viewdata')
def viewdata():
    records = Breach.query.all()
    return render_template("viewdata.html", records=records)

@app.route('/unmalware')
def unmalware():
    unmalware_data = Breach.query.filter_by(attacktype='Unmalware').all()
    return render_template('unmalware.html', records=unmalware_data)



@app.route('/malware')
def malware():
    att = [
            "Man-in-the-middle (MitM) attack",
            "Phishing and spear phishing attacks",
            "Drive-by attack",
            "Password attack",
            "SQL injection attack",
            "Cross-site scripting (XSS) attack",
            "Eavesdropping attack",
            "Birthday attack",
            "Teardrop attack"
        ]
    malware_data = Breach.query.filter(Breach.attacktype.in_(att)).all()
    return render_template('malware.html', md=malware_data)

@app.route("/graph")
def graph():
    # Query to get the count of each attack type
    attack_counts = db.session.query(Breach.attacktype, func.count(Breach.attacktype)).group_by(Breach.attacktype).all()
    
    # Convert the attack_counts data into a list of tuples
    attack_counts_list = [(attack_type, count) for attack_type, count in attack_counts]
    
    return render_template("graphical.html", attack_counts=attack_counts_list)

@app.route('/pie')
def pie():
    # Query to get the count of each attack type
    attack_counts = db.session.query(Breach.attacktype, func.count(Breach.attacktype)).group_by(Breach.attacktype).all()
    
    # Convert the attack_counts data into a list of tuples
    attack_counts_list = [(attack_type, count) for attack_type, count in attack_counts]
    
    return render_template('pie.html', attack_counts=attack_counts_list)

@app.route('/barline')
def barline():
    # Query to get the count of each attack type
    attack_counts = db.session.query(Breach.attacktype, func.count(Breach.attacktype)).group_by(Breach.attacktype).all()
    
    # Convert the attack_counts data into a list of tuples
    attack_counts_list = [(attack_type, count) for attack_type, count in attack_counts]
    
    return render_template('barline.html', attack_counts=attack_counts_list)


@app.route('/yearly')
def yearly():
    # Query to get the count of attacks for each year
    yearly_attack_counts = db.session.query(Breach.year, func.count(Breach.year)).group_by(Breach.year).all()
    
    # Convert the yearly_attack_counts data into a list of tuples
    yearly_attack_counts_list = [(year, count) for year, count in yearly_attack_counts]
    
    return render_template('yearly.html', yearly_attack_counts=yearly_attack_counts_list)



@app.route('/yearlyspline')
def yearlyspline():
    # Query to get the count of attacks for each year
    yearly_attack_counts = db.session.query(Breach.year, func.count(Breach.year)).group_by(Breach.year).all()
    
    # Convert the yearly_attack_counts data into a list of tuples
    yearly_attack_counts_list = [(year, count) for year, count in yearly_attack_counts]
    
    return render_template('yearlyspline.html', yearly_attack_counts=yearly_attack_counts_list)

@app.route('/yearlycolumn')
def yearlycolumn():
    # Query to get the count of attacks for each year
    yearly_attack_counts = db.session.query(Breach.year, func.count(Breach.year)).group_by(Breach.year).all()
    
    # Convert the yearly_attack_counts data into a list of tuples
    yearly_attack_counts_list = [(year, count) for year, count in yearly_attack_counts]
    
    return render_template('yearlycolumn.html', yearly_attack_counts=yearly_attack_counts_list)


@app.route('/attackcount')
def attackcount():
    # Query to get the count of each attack type and method
    attack_counts = db.session.query(Breach.attacktype, Breach.methods, func.count(Breach.methods)).group_by(Breach.attacktype, Breach.methods).all()
    return render_template('attackcount.html', attack_counts=attack_counts)



if __name__ == '__main__':
    app.run(debug=True)
