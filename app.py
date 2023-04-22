import os
from flask import Flask,jsonify
from flask import render_template, url_for, redirect
from flask import request, session,flash
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource,Api
from flask_login import UserMixin,login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,IntegerField
from wtforms.validators import InputRequired,Length,ValidationError,DataRequired,EqualTo
from flask_bcrypt import Bcrypt,check_password_hash,generate_password_hash
from datetime import datetime
from sqlalchemy import ForeignKey
current_dir = os.path.abspath(os.path.dirname(__file__))






app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']="sqlite:///"+os.path.join(current_dir,"data_2.sqlite3")
app.config['SECRET_KEY']="thisisasecret"
db = SQLAlchemy()
db.init_app(app)
api = Api(app)
app.app_context().push()
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login'



@login_manager.user_loader
def load_user(id):
    account_type = session.get('account_type')
    if account_type == 'admin':
        return admin.query.get(id)
    elif account_type == 'user':
        return user.query.get(id)
    else:
        return None

from functools import wraps
from flask import session, abort

class RegisterForm(FlaskForm):
    User_Name = StringField(validators = [
                            InputRequired()],render_kw={"placeholder":"Enter your Name"})
    id = StringField(validators=[
                           InputRequired()], render_kw={"placeholder": "user_id"})

    password = PasswordField(validators=[
                             InputRequired()], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_user_id(self,id):
        existing_user_user_id = user.query.filter_by(
            id=id.data).first()
        if existing_user_user_id:
            raise ValidationError(
                'That user_id already exists. Please choose a different one.')


class AdminRegisterForm(FlaskForm):
    User_Name = StringField(validators = [
                            InputRequired()],render_kw={"placeholder":"Enter your Name"})
    id = StringField(validators=[
                           InputRequired()], render_kw={"placeholder": "user_id"})

    password = PasswordField(validators=[
                             InputRequired()], render_kw={"placeholder": "Password"})
    theatre_id = StringField(validators=[
        InputRequired()],render_kw={"placeholder": "theatre_code"}
    )
    

    submit = SubmitField('Register')

    def validate_user_id(self,id):
        existing_admin_user_id = admin.query.filter_by(id=id.data).first()
        if existing_admin_user_id:
            raise ValidationError(
                'That user_id already exists. Please choose a different one.')
    

class LoginForm(FlaskForm):
    id = StringField(validators=[
                           InputRequired()], render_kw={"placeholder": "user_id"})

    password = PasswordField(validators=[
                             InputRequired()], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')

class UserLoginForm(LoginForm):
    def validate_id(self, id):
        user_obj = user.query.filter_by(id=id.data).first()
        if not user_obj:
            print("Invalid User")
            raise ValidationError('Invalid username or password')
        if not check_password_hash(user_obj.password, self.password.data):
            print("Invalid Pass")
            raise ValidationError('Invalid username or password')
class AdminLoginForm(LoginForm):
    def validate_username(self, username):
        admin_obj = admin.query.filter_by(User_Name=username.data).first()
        if not admin_obj:
            raise ValidationError('Invalid username or password')
        if not check_password_hash(admin_obj.password, self.password.data):
            raise ValidationError('Invalid username or password')
    

class TheatreForm(FlaskForm):
    theatre_id = StringField('Theatre ID', validators=[DataRequired(), Length(min=3, max=20)])
    theatre_name = StringField('Theatre Name', validators=[DataRequired(), Length(min=3, max=80)])
    show_id = IntegerField('Show ID', validators=[DataRequired()])
    seats = IntegerField('Number of Seats', validators=[DataRequired()])
    submit = SubmitField('Create Theatre')
    


class user(db.Model,UserMixin):
    __tablename__ = 'User'
    User_Name = db.Column(db.String(20))
    password = db.Column(db.String(80))
    id = db.Column(db.String(20),unique = True, primary_key = True)
    Join_Date =  db.Column(db.DateTime, default=datetime.utcnow)

    def isadmin(self):
        return False

class admin(db.Model,UserMixin):
    __tablename__ = "Admin"
    User_Name = db.Column(db.String(20))
    password = db.Column(db.String(80))
    id = db.Column(db.String(20),unique = True, primary_key = True)
    Join_Date =  db.Column(db.DateTime, default=datetime.utcnow)
    theatre_id = db.Column(db.Integer,db.ForeignKey("Theatre.theatre_id"))

    def isadmin(self):
        return True
    

class theatre(db.Model,UserMixin):
    __tablename__ = "Theatre"
    theatre_id = db.Column(db.Integer, autoincrement=True, unique=True, primary_key=True)
    theatre_name = db.Column(db.String(80))
    show_id = db.Column(db.Integer)
    seats = db.Column(db.Integer)
    admin_id = db.Column(db.String(20),db.ForeignKey("Admin.id"))
    

class show(db.Model,UserMixin):
    __tablename__ = "Show"
    show_id = db.Column(db.Integer,autoincrement=True, primary_key=True)
    show_name = db.Column(db.String(50))
    show_time = db.Column(db.DateTime,default=datetime.utcnow)
    seats = db.Column(db.Integer, default=0)
    price = db.Column(db.Integer)
    theatre_id = db.Column(db.Integer, db.ForeignKey("Theatre.theatre_id"))

class ticket(db.Model):
    __tablename__ = "Ticket"
    ticket_id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    User_Name = db.Column(db.String(20), db.ForeignKey("User.User_Name"))
    Show_id = db.Column(db.Integer, db.ForeignKey("Show.show_id"))
    theatre_name = db.Column(db.String(80), db.ForeignKey("Theatre.theatre_name"))
    show_name = db.Column(db.String, db.ForeignKey("Show.show_name"))
    show_time = db.Column(db.DateTime, db.ForeignKey("Show.show_time"))



@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('user_login'))


@app.route('/register_user', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf8')
        new_user = user(id=form.id.data, password=hashed_password,User_Name = form.User_Name.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('user_login'))

    return render_template('register.html', form=form)
    

@app.route('/register_admin', methods=['GET', 'POST'])
def register_admin():
    form = AdminRegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf8')
        new_user = admin(id=form.id.data, password=hashed_password,User_Name = form.User_Name.data,theatre_id = form.theatre_id.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('admin_login'))

    return render_template('admin_register.html', form=form)
@app.route('/register_theatre', methods=['GET', 'POST'])
@login_required
def register_theatre():
    form = TheatreForm()
    if form.validate_on_submit():
        # Create a new theatre using form data and the current user's ID
        new_theatre = theatre(theatre_id=form.theatre_id.data, theatre_name=form.theatre_name.data,
                              show_id=form.show_id.data, seats=form.seats.data, admin_id=current_user.id)
        db.session.add(new_theatre)
        db.session.commit()
        flash('New theatre created!', 'success')
        return redirect(url_for('admin_dash'))
    return render_template('register_theatre.html', title='Register Theatre', form=form)





# user login route




@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    form = UserLoginForm()
    print("user is Here")
    if form.validate_on_submit():
        print("it")
        user_ = user.query.filter_by(id=form.id.data).first()
        if user_ and bcrypt.check_password_hash(user_.password, form.password.data):
            login_user(user_)
            print("Goes")
            flash('You have been logged in!', 'success')
            
            session['account_type'] = 'user'
            return redirect(url_for('base'))
        else:
        
            print('Login unsuccessful. Please check your username and password.', 'danger')

    return render_template('login.html', form=form)

# admin login route
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    print("pASS 1")
    if form.validate_on_submit():
        print(form.id.data)
        admin_ = admin.query.filter_by(id=form.id.data).first()
        print("Found User")
        print(admin_)
        if admin_:
            print("OK here")
            if bcrypt.check_password_hash(admin_.password, form.password.data):
                '''login_user(admin_)
                print(login_user(admin_))
                session['account_type'] = 'admin'
                print("Finally here")
                flash('You have been logged in!', 'success')'''
                session['account_type'] = 'admin'
            # Log the user in using the admin login manager
                login_user(admin_, remember=request.form.get('remember'))
                return redirect(url_for('admin_dash'))
        else:
            print("pass 2")
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    return render_template('admin_login.html', form=form)

@app.route('/user_dashboard', methods=['GET', 'POST'])
@login_required
def user_dashboard():
    print(current_user)
    return("User Logged in")

@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    return("ad Logged in")


from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, DateTimeField, SubmitField
from wtforms.validators import DataRequired, Length
from datetime import datetime
from flask_login import login_required


class ShowCreate(FlaskForm):
    show_name = StringField('Show Name', validators=[DataRequired(), Length(min=3, max=50)])
    show_time = DateTimeField('Show Time', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    seats = IntegerField('Number of Seats', default=0)
    price = IntegerField('Price', validators=[DataRequired()])
    submit = SubmitField('Create Show')

@app.route('/create_show', methods=['GET', 'POST'])
@login_required
def create_show():
    form = ShowCreate()
    theatre_id = current_user.theatre_id
    print("Step 1")
    print(theatre_id)
    print(form.validate_on_submit())
    if form.validate_on_submit():
        print("ok")
    else:
        print(form.errors)
    if form.validate_on_submit():
        
        new_show = show(show_name=form.show_name.data, show_time=form.show_time.data, seats=form.seats.data,
                        price=form.price.data, theatre_id=theatre_id)
        db.session.add(new_show)
        db.session.commit()
        flash('Show created successfully!', 'success')
        return redirect(url_for('admin_dash'))

    return render_template('create_show.html', theatre_id = theatre_id,form=form)

@app.route("/",methods = ["GET","POST"])
def base():
    post = show.query.all()
    print(post)
    return render_template("home_layout.html",post = post)
@app.route('/search', methods=['POST'])
@app.route('/search')
def search():
    search_query = request.args.get('q')
    results = []
    if search_query:
        theatre_results = theatre.query.filter(theatre.theatre_name.ilike(f'%{search_query}%')).all()
        show_results = show.query.filter(show.show_name.ilike(f'%{search_query}%')).all()
        results = theatre_results + show_results
    return render_template('search.html', results=results)



    

@app.route("/layout",methods = ["GET","POST"])
def show_list():
    query = request.form.get('query')
    shows = show.query.filter(show.show_name.ilike(f'%{query}%')).all()
    theatres = theatre.query.filter(theatre.theatre_name.ilike(f'%{query}%')).all()
    #return render_template('search.html', shows=shows, theatres=theatres, query=query)
    return render_template("layout.html",shows=shows, theatres=theatres, query=query)

    '''uery = request.form.get('query')
    shows = show.query.filter(show.show_name.ilike(f'%{query}%')).all()
    theatres = theatre.query.filter(theatre.theatre_name.ilike(f'%{query}%')).all()
    return render_template('search.html', shows=shows, theatres=theatres, query=query)'''

class ticketform(FlaskForm):
    show_name = StringField('Show Name', validators=[DataRequired(), Length(min=3, max=50)])
    show_time = DateTimeField('Show Time', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    
    submit = SubmitField('Create Show')
# Flask route to book a ticket


@app.route('/book_ticket/<int:show_id>/<string:show_time>/<int:theatre_id>', methods=['GET', 'POST'])
@login_required
def book_ticket(show_id, show_time, theatre_id):
    # Check if the show exists
    theatre_name = theatre.query.filter_by(theatre_id=theatre_id).first()
    #show_ = show.query.filter_by(show_id=show_id, show_time=datetime.strptime(show_time, '%Y-%m-%d %H:%M:%S'), theatre_name=theatre.query.filter_by(theatre_name=theatre_name).first().theatre_id).first()
    # Retrieve the theatre_id for the given theatre_name
    theatre_obj = theatre.query.filter_by(theatre_id=theatre_id).first()
    theatre_id_ = theatre_obj.theatre_id
    print(show_id)
# Use the retrieved theatre_id as a literal value in the show query
    show_ = show.query.filter_by(show_id=show_id, 
                             show_time=datetime.strptime(show_time, '%Y-%m-%d %H:%M:%S'), 
                             theatre_id=theatre_id_).first()
    print(show_)
    if not show_:
        flash('Invalid show!')
        return redirect(url_for('base'))

    # Check if the user has already booked a ticket for this show
    if ticket.query.filter_by(User_Name=current_user.User_Name, Show_id=show_id, show_time=show.show_time).first():
        flash('You have already booked a ticket for this show!')
        return redirect(url_for('base'))
    if show_.seats > 0:
        show.seats -= 1
        db.session.commit()
    print(show_.seats)

    print(show_id)
    #show_ = show.query.filter_by(show_id=show.show_id).first()
    print(show_)
    show_name = show_.show_name
    show_time_obj = datetime.strptime(show_time, '%Y-%m-%d %H:%M:%S')
    theatre_obj = theatre.query.filter_by(theatre_id=theatre_id).first()
    theatre_name = theatre_obj.theatre_name

    # Book the ticket
    ticket_ = ticket(User_Name=current_user.User_Name, Show_id=show_id, theatre_name=theatre_name,show_time = show_time_obj,show_name = show_name)
    
    print("show",show.seats)
    db.session.add(ticket_)
    db.session.commit()
    return render_template("book_ticket.html")

@app.route('/dashboard',methods = ['GET','POST'])
@login_required
def dashboard():
    user_= current_user.User_Name
    ticket_list = ticket.query.filter_by(User_Name=user_).all()
    return (render_template("dashboard.html",ticket_list = ticket_list))

@app.route('/delete_ticket/<int:ticket_id>', methods=['GET','POST','DELETE'])
def delete_ticket(ticket_id):
    ticket_ = ticket.query.get_or_404(ticket_id)
    show.seats -= 1
    
    db.session.delete(ticket_)
    db.session.commit()
    return redirect(url_for('base'))

@app.route('/admin_dash',methods = ['GET','POST'])
@login_required
def admin_dash():
    tid = current_user.theatre_id
    theatre_list=theatre.query.filter_by(admin_id = current_user.id)
    show_list = show.query.filter_by(theatre_id = tid)
    return(render_template("admin_dash.html",theatre_list = theatre_list,show_list = show_list))

from flask import request




# Update a show
@app.route('/show/<int:show_id>', methods=['GET', 'POST', 'PUT'])
def update_show(show_id):
    show_ = show.query.get(show_id)
    print(show_)
    if not show_:
        # Show not found, return error message or redirect to a 404 page
        return 'Show not found'

    if request.method == 'POST' or request.method == 'PUT':
        # Update show fields with form data
        print("Here")
        show_.show_name = request.form['show_name']
        show_time_str = request.form['show_time']
        show.show_time = datetime.strptime(show_time_str, '%Y-%m-%dT%H:%M')
        show_.seats = request.form['seats']
        show_.price = request.form['price']
        db.session.commit()
        return redirect(url_for('admin_dash'))

    # Render the show details template with the current show object
    return render_template('show_details.html', show=show_)

'''@app.route('/show/<int:show_id>', methods=['GET','POST','PUT'])
def update_show(show_id):
    print("123")
    show_ = show.query.filter_by(show_id=show_id).first()
    if show_:
        # Update show fields
        show_.show_name = request.form['show_name']
        show_time_str = request.form['show_time']
        show.show_time = datetime.strptime(show_time_str, '%Y-%m-%dT%H:%M')

        show_.seats = request.form['seats']
        show_.price = request.form['price']
        db.session.commit()
        return 'Show details updated successfully'
    else:
        return 'Show not found'''

# Delete a show
@app.route('/show_del/<int:show_id>',  methods=['GET','POST','DELETE'])
def delete_show(show_id):
    show_ = show.query.filter_by(show_id=show_id).first()
    print("Hi")
    if show_:
        db.session.delete(show_)
        db.session.commit()
        return redirect(url_for('admin_dash'))
    else:
        return 'Show not found'




if __name__=="__main__":
    db.create_all()
    app.run(debug = True)
