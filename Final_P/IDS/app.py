
from flask import Flask, redirect,render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

from sqlalchemy import null

app = Flask(__name__)
app.secret_key="any key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost:3306/projDB'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


#create user 

class Users(db.Model):
    id= db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(200),nullable=False)
    email=db.Column(db.String(200),nullable=False,unique=True)
    password=db.Column(db.String(200),nullable=False)
    datecreated=db.Column(db.DateTime,default=datetime.utcnow)

#create a msg
    def __repr__(self) -> str:
        return super().__repr__()
  
    
    # view all
@app.route('/',methods=['POST','GET'])
def index():
    if session.get('sessionName') ==None:
        return redirect('login')
    else:
        return render_template('index.html') 
 



@app.route('/register',methods=['POST','GET'])
def register():
    if request.method =='POST':
        username =   request.form['username']
        password =   request.form['password']
        email =   request.form['email']
        newUser= Users(username = username,password=password,email=email)
        try:
            db.session.add(newUser)
            db.session.commit()
            return redirect('/')
        except:
            session['error'] = "Email alredy exist !"
            return redirect('register')
            # return render_template('exist.html')


    else:
         
        return render_template('register.html')



@app.route('/login',methods=['POST','GET'])
def login():
    if request.method =='POST':
        email =  request.form['email']
        password =   request.form['password']
        user= Users.query.filter_by(email=email).first()
        if(user.email==email and user.password==password):
            session['sessionName']=True
            return redirect(url_for('index'))
        else:
            session['msg'] = "Somthing went wrong please try again !"
            return redirect('login')
    else:
         
        return render_template('login.html')


  
@app.route('/dashboard',methods=['POST','GET'])
def dashboard():
    return render_template('dashboard.html')

  
@app.route('/logout',methods=['POST','GET'])
def logout():
    session.clear()
    return redirect(url_for('index'))

      
 

if __name__ == "__main__":
    app.run(host="0.0.0.0",debug=True)