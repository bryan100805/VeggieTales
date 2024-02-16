from application import app, bcrypt, login_manager, mail
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
from application.forms import PredictionForm, RegistrationForm, LoginForm, PasswordResetRequestForm, PasswordResetForm, SearchHistoryForm
from application.models import Entry, User
from application import db
from flask import render_template, request, flash, url_for, redirect, jsonify
from flask_cors import CORS, cross_origin
from PIL import Image
import numpy as np
import json, requests, base64, datetime, os, pytz
from io import BytesIO
from functools import reduce

veggie_classnames = ["Bean", "Bitter Gourd", "Bottle Gourd", "Brinjal", "Broccoli", "Cabbage", "Capsicum", "Carrot", "Cauliflower", "Cucumber", "Papaya"
                     "Potato", "Pumpkin", "Radish", "Tomato"]

# Preprocess the image for prediction
def preprocess_img(file, size):
    # Convert the image to gray scale as the model was trained on gray scale images
    img = Image.open(file).convert('L')
    # Resize the image to pixels specified
    img = img.resize((size, size))
    # Use BytesIO to convert the image to bytes
    bytesio = BytesIO()
    img.save(bytesio, format="JPEG")
    byte_img = bytesio.getvalue()
    # Rescale the image to 0-1 for the model
    img = np.array(img)
    return img, byte_img

# Add entry to database
def add_entry(new_entry):
    try:
        # Add user id to entry
        new_entry.user_id = current_user.id
        db.session.add(new_entry)
        db.session.commit()
        return new_entry.id
    except Exception as error:
        db.session.rollback()
        flash(error,"danger")

# Retrieve all entries from database
def get_entries():
    try:
        # Retrieve all entries from database
        entries = db.session.execute(db.select(Entry).filter(Entry.user_id==current_user.id).order_by(Entry.id)).scalars()
        return entries
    except Exception as error:
        db.session.rollback()
        flash(error,"danger") 
        return []

# Customised filter for entries
def get_entries_by_filter(where):
    try:
        # Retrieve all entries from database
        entries = db.session.execute(db.select(Entry).filter(where).order_by(Entry.id)).scalars()
        return entries
    except Exception as error:
        db.session.rollback()
        flash(error,"danger") 
        return []
    
# Remove entry from database based on id
def remove_entry(id):
    try: 
        # Retrieve entry from database
        entry = db.get_or_404(Entry, id) 
        db.session.delete(entry) 
        db.session.commit()
    except Exception as error:
        db.session.rollback()
        flash(error,"danger") 
        return 0
    
# Send password reset email
def send_password_reset_email(user):
    token = user.get_reset_password_token()
    msg = Message("Password Reset Request", recipients=[user.email], sender="daaa2b01.2214449.tanwentaobryan@gmail.com")
    msg.body = f'''
    Hi, {user.username}!

    To reset your password, visit the following link:
    {url_for("reset_password", token=token, _external=True)}

    VeggieTales thanks you for using our service!

    If you did not make this request then simply ignore this email and no changes will be made.
    '''
    mail.send(msg)

# Define user loader callback for Flask-login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route("/prediction")
@login_required
def index_page():
    form1 = PredictionForm()
    return render_template("index.html", form =form1, title="Vegetable Prediction", entries=get_entries())

@app.route("/predict", methods=["GET", "POST"])
@cross_origin(origin='localhost',headers=['Content- Type','Authorization'])
def predict():
    form = PredictionForm()
    if request.method == "POST":
        if form.validate_on_submit():
            selected_model = form.model.data
            if selected_model == 'veggie_cnn_31x31':
                size = 31
                url = "https://veggietales-cnn.onrender.com/v1/models/veggie_cnn_31x31:predict"
            
            else:
                size = 128
                url = "https://veggietales-cnn.onrender.com/v1/models/veggie_cnn_128x128:predict"
            
            image, image_in_bytes = preprocess_img(form.file_upload.data, size)
            # Reshape the image to the format the model expects to have a single channel
            image = image.reshape((1, size, size, 1))
            # Send POST API request to server
            data = json.dumps({"signature_name": "serving_default", "instances": image.tolist()})
            headers = {"content-type": "application/json"}
            json_response = requests.post(url, data=data, headers=headers)
            # Parse response
            predictions = json.loads(json_response.text)['predictions']
            predictions_class_index = np.argmax(predictions[0])
            # Predicted class
            predicted_class = veggie_classnames[predictions_class_index]
            # Probabilty of prediction
            prob_score = predictions[0][predictions_class_index]*100
            prob_score = round(prob_score, 2)

            # Singapore timezone timestamp
            timezone = pytz.timezone("Asia/Singapore")
            current_time = datetime.datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(timezone)

            new_entry = Entry(image = image_in_bytes, DL_model = selected_model, prediction = predicted_class, probability = prob_score, predicted_on = current_time)
            add_entry(new_entry)

            flash(f"Prediction: {predicted_class} with Probability: {prob_score}%", "success")

        else:
            flash(f"Error: Unable to proceed with prediction", "danger")
    return render_template("index.html", form=form, title="Vegetable Prediction", index=True, entries=get_entries())

@app.route("/history")
@login_required
def history_page():
    search_history_form = SearchHistoryForm()

    entries = get_entries()
    # Encode image to base64 for display
    entries = [
        {"id":entry.id,
        "image": base64.b64encode(entry.image).decode('utf-8'),
        "DL_model": entry.DL_model,
        "prediction": entry.prediction,
        "probability": entry.probability,
        "predicted_on": entry.predicted_on.strftime("%d %b %Y %H:%M"),
        "user_id": entry.user_id
        }
        for entry in entries
    ]

    return render_template("history.html", title="Prediction History", search_history_form=search_history_form, entries=entries)

##### Next few routes to dynamically filter history records everytime a filter is being added #####
# Returns entries everytime each search or filter is listed
@app.route("/filterHistories", methods=["GET", "POST"])
def filterHistories():
    search_history_form = SearchHistoryForm()
    data = {
        "user_id": current_user.id,
    }

    response = getEntries(data)
    response = response.json
    entries = response["entries"]

    if request.method == "POST":
        ## Convert all the empty arrays or None string to None object

        timestamp_filter = search_history_form.filter_by_timestamp.data
        # Convert 'None' to None since the default value is 'None'
        if timestamp_filter == "None":
            timestamp_filter = None

        probability_filter = search_history_form.filter_by_probability.data
        if probability_filter == "None":
            probability_filter = None

        search_bar = search_history_form.search_bar.data

        model_filter = search_history_form.filter_by_model.data
        if model_filter == []:
            model_filter = None

        prediction_filter = search_history_form.filter_by_prediction.data
        if prediction_filter == []:
            prediction_filter = None

        data = {
            "user_id": current_user.id,
            "timestamp_filter": timestamp_filter,
            "probability_filter": probability_filter,
            "model_filter": model_filter,
            "prediction_filter": prediction_filter,
            "search_bar": search_bar
        }

        response = filter_entries(data)
        response = response.json
        entries = response["entries"]

    return render_template("history.html", title="Prediction History", search_history_form=search_history_form, entries=entries)

# Retrieve the entries in a more detailed manner, array of objects
@app.route("/get_entries", methods=["GET"])
def getEntries(data):
    if data is None:
        data = request.get_json()

    user_id = data["user_id"]
    entries = get_entries_by_filter(where=Entry.user_id == user_id)

    entries = [
        {
            "id": entry.id,
            "image": base64.b64encode(entry.image).decode('utf-8'),
            "DL_model": entry.DL_model,
            "prediction": entry.prediction,
            "probability": entry.probability,
            "predicted_on": entry.predicted_on.strftime("%d %b %Y %H:%M"),
            "user_id": entry.user_id,
        }
        for entry in entries
    ]

    if entries is None:
        return jsonify({'error': 'Failed to get entries'})
    else:
        # Return the entries
        return jsonify({'entries': entries})

# Filter entries with the pattern checks to ensure that the entries matched the requirements chosen by the users
@app.route('/filter', methods=['GET'])
def filter_entries(data):
    if data is None:
        data = request.get_json()
    
    user_id = data["user_id"]
    timestamp_filter = data["timestamp_filter"]
    probability_filter = data["probability_filter"]
    model_filter = data["model_filter"]
    prediction_filter = data["prediction_filter"]
    search_bar = data["search_bar"]
    where_clause = (Entry.user_id == user_id)

    # Check for words within search bar
    if search_bar:
        where_clause = where_clause & (Entry.DL_model.like(f"%{search_bar}%") | Entry.prediction.like(f"%{search_bar}%") | Entry.probability.like(f"%{search_bar}%")) | Entry.predicted_on.like(f"%{search_bar}%")

    # Check for certain models
    if model_filter is not None:
        model_conditions = (Entry.DL_model == model for model in model_filter)
        where_clause = where_clause & (reduce(lambda x,y: x|y, model_conditions))

    # Check for the type of predictions
    if prediction_filter is not None:
        prediction_conditions = (Entry.prediction == prediction for prediction in prediction_filter)
        where_clause = where_clause & (reduce(lambda x,y: x|y, prediction_conditions))

    # Retrieve the entries to update them based on where clause
    entries = get_entries_by_filter(where_clause)

    entries = [
        {
            "id": entry.id,
            "image": base64.b64encode(entry.image).decode('utf-8'),
            "DL_model": entry.DL_model,
            "prediction": entry.prediction,
            "probability": entry.probability,
            "predicted_on": entry.predicted_on.strftime("%d %b %Y %H:%M"),
            "user_id": entry.user_id
        }
        for entry in entries
    ]

    # Check timestamp filter
    if timestamp_filter:
        # Return entries according to most recent entries or earliest entries
        if timestamp_filter == "desc":
           entries = sorted(entries, key=lambda x: x["predicted_on"], reverse=True)
        else:
            entries = sorted(entries, key=lambda x: x["predicted_on"])
    
    # Check probability filter
    if probability_filter:
        # Return entries according to greatest probability or smallest probability
        if probability_filter == "desc":
            entries = sorted(entries, key=lambda x: x["probability"], reverse=True)
        else:
            entries = sorted(entries, key=lambda x: x["probability"])

    if entries is None:
        return jsonify({'error': 'Failed to get entries'})
    else:
        # Return the entries
        return jsonify({'entries': entries})

@app.route('/remove', methods=['POST'])
def remove():
    req = request.form
    id = req["id"] 
    remove_entry(id)
    # Redirect to /history
    return redirect(url_for("history_page"))

# Handles http://127.0.0.1:5000/
@app.route("/")
@app.route("/index")
@app.route("/login", methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                flash(f'Welcome {form.username.data}! You are now logged in,', 'success')
                login_user(user, remember=form.remember.data)
                return redirect(url_for("home"))
            
        flash('Login Unsucessful. Please check your credentials again.', 'danger')

    return render_template("login.html", title="Login", form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login_page"))


@app.route("/register", methods=['GET', 'POST'])
def registration_page():
    form = RegistrationForm()
    # Check if user is already logged in
    if current_user.is_authenticated:
        flash(f"You are already logged in as {current_user.username}", "info")
        return redirect(url_for("home"))

    if form.validate_on_submit():
        # Hash password
        hashed_password = bcrypt.generate_password_hash(form.password.data)

        # Change timezone to Singapore
        timezone = pytz.timezone("Asia/Singapore")
        current_time = datetime.datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(timezone)

        # Add user to database
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, timestamp=current_time)
        db.session.add(new_user)
        db.session.commit()
        flash(f'Account created for {form.username.data}! Try logging in now.', 'success')
    return render_template("register.html", title="Registration", form=form)

@app.route("/forgot_password", methods=['GET', 'POST'])
def forgot_password_page():
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        # Checks if email exist in the database
        user = User.query.filter_by(email = form.email.data).first()
        if user:
            send_password_reset_email(user)
            flash("An email has been sent with instructions to reset your password.", "info")
            return redirect(url_for("login_page"))
        flash("Unregistered email. Please try again.", 'danger')
    
    return render_template("forgot_password.html", title="Forgot Password", form=form)

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.verify_reset_password_token(token)
    if not user:
        flash("Invalid or expired token. Please try again.", "danger")
        return redirect(url_for("forgot_password_page"))
    form = PasswordResetForm()
    if form.validate_on_submit():
        # Hash password
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash("Your password has been updated. You are now able to login.", "success")
        return redirect(url_for("login_page"))
    return render_template("reset_password.html", title="Reset Password", form=form)

####################### APIs for Unit Testing #######################

#### APIs - Authentication ####

# Function for registering user to database
def register_user_API(user, email, password):
    try:
        # Hash password
        hashed_password = bcrypt.generate_password_hash(password)

        # Change timezone to Singapore
        timezone = pytz.timezone("Asia/Singapore")
        current_time = datetime.datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(timezone)

        # Add user to database
        new_user = User(username=user, email=email, password=hashed_password, timestamp=current_time)
        db.session.add(new_user)
        db.session.commit()

        # Return the id of the user added
        return new_user.id
    
    # Registration failure
    except Exception as e:
        db.session.rollback()
        flash(e, "danger")
        return None

# Register API - test user registration
@app.route('/api/register', methods=["GET","POST"])
def register_api():
    data = request.get_json()

    # Retrieve each field from data
    username = data['username']
    email = data['email']
    password = data['password']
    confirm_password = data['confirm_password']

    # Check if password do not match the confirmed password
    if password != confirm_password:
        return jsonify({'status': 'error','registered': False ,'message': 'Passwords do not match.'})
        
    # Register the user
    new_user = register_user_API(username, email, password)
    
    if new_user is not None:
        # Return the userid in response
        return jsonify({'status': 'success', "registered": True, 'userid': new_user})
    else:
        return jsonify({'status': 'error', "registered": False})
    

# Function for logging in user
def login_user_API(username, password):
    # Validate the user
    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        # Return the userid in response
        return user.id
    else:
        return None

# Login API - test user login
@app.route('/api/login', methods=["GET", "POST"])
def login_api():
    data = request.get_json()

    # Retrieve each field from data
    username = data["username"]
    password = data["password"]

    # Login the user
    result = login_user_API(username, password)

    if result:
        return jsonify({'status': 'success', 'userid': result, "logged_in": True})
    else:
        return jsonify({'status': 'error',"logged_in": False})
    
#### APIs - Password Reset ####

# Function for confirming user email
def check_email_API(email):
    # Validate the user
    user = User.query.filter_by(email=email).first()

    if user:
        # Return the userid in response
        return user.id
    else:
        return None

# Check email API - test if user email exist in the database
@app.route('/api/email_confirm', methods=["GET"])
def confirm_email():
    data = request.get_json()

    # Retrieve each field from data
    email = data["email"]

    # Check if email exists in the database
    result = check_email_API(email)

    if result:
        return jsonify({'status': 'success', 'userid': result, "email_confirm": True})
    else:
        return jsonify({'status': 'error', "email_confirm": False})
    
#### APIs - Prediction ####

# Predict API - test prediction
@app.route('/api/predict', methods=["GET", "POST"])
def predict_api():
    data = request.get_json()

    # Retrieve each field from data
    selected_model = data["model"]
    instances = data["image"]

    signature_name = data["signature_name"]

    if selected_model == 'veggie_cnn_31x31':
        url = "https://veggietales-cnn.onrender.com/v1/models/veggie_cnn_31x31:predict"
    else:
        url = "https://veggietales-cnn.onrender.com/v1/models/veggie_cnn_128x128:predict"

    # Send POST API request to server
    data = json.dumps({"signature_name": signature_name, "instances": instances})
    headers = {"content-type": "application/json"}
    json_response = requests.post(url, data=data, headers=headers)
    # Parse response
    predictions = json.loads(json_response.text)['predictions']
    predictions_class_index = np.argmax(predictions[0])

    # Predicted class
    predicted_class = veggie_classnames[predictions_class_index]
    
    # Probabilty of prediction
    prob_score = predictions[0][predictions_class_index]*100
    prob_score = round(prob_score, 2)

    # Return the prediction in response
    return jsonify({'status': 'success', 'prediction': predicted_class, 'probability': prob_score, 'status_code': 200})

# Function for adding entry to database for testing
def add_entry_API(new_entry):
    try:
        # Add user id to entry
        db.session.add(new_entry)
        db.session.commit()
        return new_entry.id
    except Exception as error:
        db.session.rollback()
        flash(error,"danger")

# Add entry API - test adding entry to database
@app.route('/api/add_entry', methods=["GET", "POST"])
def add_api():
    #Retrieve data from request
    data = request.get_json()

    #Retrieve each field from data
    image = data["image"]
    DL_model = data["DL_model"]
    prediction = data["prediction"]
    probability = data["probability"]

    email = data["email"]

    image = image.encode('utf-8')
    # Retrieve the user id from database
    user_id = User.query.filter_by(email=email).first().id
    timezone = pytz.timezone("Asia/Singapore")
    current_time = datetime.datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(timezone)

    #Create an Entry object that stores all the data for db action
    new_entry = Entry(
        user_id = user_id,
        image = image,
        DL_model = DL_model,
        prediction = prediction,
        probability = probability,
        predicted_on=current_time)
    
    # Invoke the add entry function to add entry
    new_result = add_entry_API(new_entry)

    # Stores the user's email in the variable
    user_email = User.query.filter_by(id=user_id).first().email

    if new_result:
        # Return the entry id in response
        return jsonify({'status': 'success', 'id': new_result, 'email': user_email})
    else:
        return jsonify({'status': 'error'})

# Function for retrieving entry from database based on user_id
def get_entries_API(user_id):
    try:
        # Retrieve all entries from database
        entries = db.session.execute(db.select(Entry).filter(Entry.user_id==user_id).order_by(Entry.id)).scalars()
        return entries
    except Exception as error:
        db.session.rollback()
        flash(error,"danger") 
        return []
    
# Retrieve entry API test retrieving entry from database based on user_id
@app.route('/api/get_entries', methods=['GET'])
def get_api():
    # Retrieve data from request
    data = request.get_json()

    # Retrieve each field from data
    user_email = data['user_email']

    # Retrieve the user id from database
    user_id = User.query.filter_by(email = user_email).first().id

    # Retrieve all entries from database
    new_result = get_entries_API(user_id)
    new_results = []
    # Serialise the entries retrieved in JSON
    for entry in new_result:
        # Stores the user's email in the variable
        email = User.query.filter_by(id = entry.user_id).first().email
        new_results.append({'entry_id': entry.id,'user_email': email ,'prediction': entry.prediction, 'probability': entry.probability})

    # Return the entries retrieved
    return jsonify({'entries': new_results})

# Function for removing entry from database based on entry_id
def remove_entry_API(entry_id):
    try:
        # Retrieve entry from database
        entry = db.get_or_404(Entry, entry_id)
        db.session.delete(entry)
        db.session.commit()
        return {'status': 'success', 'entry_id':entry_id, 'message':'Entry is removed successfully.'}
    except Exception as error:
        db.session.rollback()
        flash(error, "danger")
        return {'status': 'error', 'entry_id':0, 'message':str(error)}

# Remove entry API - test removing entry from database based on entry_id
@app.route('/api/remove_entry/<id>', methods=['GET'])
def remove_api(id):
    # Delete the entry from the database
    new_result = remove_entry_API(id)

    # Return the id of the entry deleted
    return jsonify(new_result)

# Get entries from database API
@app.route("/api/predict_entries", methods=["GET"])
def getPredictEntriesAPI(data):
    if data is None:
        data = request.get_json()

    user_id = data["user_id"]
    entries = get_entries(whereClause=Entry.user_id == user_id)

    entries = [
        {
            "id": entry.id,
            "image": base64.b64encode(entry.image).decode('utf-8'),
            "DL_model": entry.DL_model,
            "prediction": entry.prediction,
            "probability": entry.probability,
            "predicted_on": entry.predicted_on,
            "user_id": entry.user_id,
        }
        for entry in entries
    ]

    if entries is None:
        return jsonify({'error': 'Failed to get entries', "status_code": 500})
    else:
        # Return the entries
        return jsonify({'entries': entries, "status_code": 200})
    
###### Filter entries from database API according to the search bar, model, prediction, timestamp and probability ######
@app.route('/api/filter_entries', methods=['GET'])
def filter_entries_API(data):
    if data is None:
        data = request.get_json()
    
    user_id = data["user_id"]
    timestamp_filter = data["timestamp_filter"]
    probability_filter = data["probability_filter"]
    model_filter = data["model_filter"]
    prediction_filter = data["prediction_filter"]
    search_bar = data["search_bar"]
    where_clause = (Entry.user_id == user_id)

    # Check for words within search bar
    if search_bar:
        where_clause = where_clause & (Entry.DL_model.like(f"%{search_bar}%") | Entry.prediction.like(f"%{search_bar}%") | Entry.probability.like(f"%{search_bar}%")) | Entry.predicted_on.like(f"%{search_bar}%")

    # Check for certain models
    if model_filter is not None:
        model_conditions = (Entry.DL_model == model for model in model_filter)
        where_clause = where_clause & (reduce(lambda x,y: x|y, model_conditions))

    # Check for the type of predictions
    if prediction_filter is not None:
        prediction_conditions = (Entry.prediction == prediction for prediction in prediction_filter)
        where_clause = where_clause & (reduce(lambda x,y: x|y, prediction_conditions))

    # Retrieve the entries to update them based on where clause
    entries = get_entries_by_filter(where_clause)

    entries = [
        {
            "id": entry.id,
            "image": base64.b64encode(entry.image).decode('utf-8'),
            "DL_model": entry.DL_model,
            "prediction": entry.prediction,
            "probability": entry.probability,
            "predicted_on": entry.predicted_on.strftime("%d %b %Y %H:%M"),
            "user_id": entry.user_id
        }
        for entry in entries
    ]

    # Check timestamp filter
    if timestamp_filter:
        # Return entries according to most recent entries or earliest entries
        if timestamp_filter == "desc":
           entries = sorted(entries, key=lambda x: x["predicted_on"], reverse=True)
        else:
            entries = sorted(entries, key=lambda x: x["predicted_on"])
    
    # Check probability filter
    if probability_filter:
        # Return entries according to greatest probability or smallest probability
        if probability_filter == "desc":
            entries = sorted(entries, key=lambda x: x["probability"], reverse=True)
        else:
            entries = sorted(entries, key=lambda x: x["probability"])

    if entries is None:
        return jsonify({'error': 'Failed to get entries', 'status_code': 500})
    else:
        # Return the entries
        return jsonify({'entries': entries, 'status_code': 200})
    
# Post entries from database API
@app.route("/api/post_entries", methods=["POST"])
def storePredictAPI(data=None):
    if data is None:
        data = request.get_json()
        # Convert the image to bytes
        data['image'] = data['image'].encode('utf-8')

    timezone = pytz.timezone("Asia/Singapore")
    current_time = datetime.datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(timezone)

    new_entry = Entry(
        image=data['image'],
        DL_model=data['DL_model'],
        prediction=data['prediction'],
        probability=data['probability'],
        predicted_on=current_time,
        user_id=data['user_id']
    )

    # Make sure user exists
    user = get_entries_by_filter(where=User.id == data['user_id'])

    if user == []:
        return jsonify({'error': 'User does not exist in the database', "status_code": 404})

    # Add the entry
    result = add_entry(new_entry)

    if result is None:
        return jsonify({'error': 'Failed to add entry into the database', "status_code" : 500})
    else:
        # return the result of the db action
        return jsonify({'id': result, "status_code":200})