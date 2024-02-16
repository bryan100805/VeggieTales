from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileRequired
from wtforms import SubmitField, SelectField, FileField, RadioField, StringField, PasswordField, EmailField, BooleanField, SelectMultipleField
from wtforms.validators import InputRequired, Length, ValidationError, NumberRange, Regexp, EqualTo
from application.models import User
from wtforms import widgets

# Add widgets of checkboxes to widgets of SelectMultipleField
class MultiCheckboxField(SelectMultipleField):
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()
    
class PredictionForm(FlaskForm):
    file_upload = FileField("Upload Image", validators=[FileRequired(), FileAllowed({'jpg', 'png', 'jpeg'}, message="File Rejected: Only jpg, jpeg, and png files are allowed.")])
    model = SelectField("CNN Model", choices=[("veggie_cnn_31x31", "Veggie CNN (31x31)"), ("veggie_cnn_128x128", "Veggie CNN (128x128)")], default="veggie_cnn_31x31", validators=[InputRequired()])
    submit = SubmitField("Predict")

class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=20), Regexp(r"^[a-zA-Z0-9_.]*",
                                                                                                  message="Username must only contain letters, numbers, underscores and periods.")])
    email = EmailField("Email", validators=[InputRequired(), Length(min=3, max=100), Regexp(r"[^@]+@[^@]+\.[^@]+", 
                                                                                            message='Invalid email address, please use a valid email address that contains an @')])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8, max=20),Regexp(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+",
                                                                                            message='Password must contain at least one uppercase letter, one lowercase letter, 1 special character and 1 numerical character.')])
    confirm_password = PasswordField("Confirm Password", validators=[InputRequired(), EqualTo("password", message="Passwords must match, please try again.")])
    submit = SubmitField("Register")

    # Validates the username
    def validate_username(self, username):
        existing_username = User.query.filter_by(username=username.data).first()
        if existing_username:
            raise ValidationError("That username is taken. Please choose a different one.")
        
    # Validates the email
    def validate_email(self, email):
        existing_email = User.query.filter_by(email=email.data).first()
        if existing_email:
            raise ValidationError("That email has been registered. Please use a different one or login instead.")
        
class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8, max=20)])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")

class SearchHistoryForm(FlaskForm):
    search_bar = StringField("Search By")
    filter_by_timestamp = SelectField("Timestamp", choices=[("None", "Sort By:"),("desc", "Latest Prediction"), ("asc", "Earliest Prediction")], default="None")
    filter_by_probability = SelectField("Probability", choices=[("None", "Sort By:"),("desc", "Highest Probability"), ("asc", "Lowest Probability")], default="None")

    # Obtain values for model from the database
    filter_by_model = MultiCheckboxField("Model", choices=[("veggie_cnn_31x31", "Veggie CNN (31x31)"), ("veggie_cnn_128x128", "Veggie CNN (128x128)")])
    filter_by_prediction = MultiCheckboxField("Prediction", choices = [("Bean", "Bean"), ("Bitter Gourd", "Bitter Gourd"), ("Bottle Gourd", "Bottle Gourd"), ("Brinjal", "Brinjal"), ("Broccoli","Broccoli"), ("Cabbage","Cabbage"), ("Capsicum", "Capsicum"), 
                                                                           ("Carrot","Carrot"), ("Cauliflower","Cauliflower"), ("Cucumber","Cucumber"), ("Papaya", "Papaya"), ("Potato","Potato"), 
                                                                           ("Pumpkin","Pumpkin"), ("Radish","Radish"), ("Tomato", "Tomato")]) 

class PasswordResetRequestForm(FlaskForm):
    email = EmailField("Email", validators=[InputRequired(), Length(min=3, max=100), Regexp(r"[^@]+@[^@]+\.[^@]+", 
                                                                                            message='Invalid email address, please use a valid email address that contains an @')])
    submitField = SubmitField("Request Password Reset")

class PasswordResetForm(FlaskForm):
    password = PasswordField("New Password", validators=[InputRequired(), Length(min=8, max=20),Regexp(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+",
                                                                                            message='Password must contain at least one uppercase letter, one lowercase letter, 1 special character and 1 numerical character.')])
    confirm_password = PasswordField("Confirm New Password", validators=[InputRequired(), EqualTo("password", message="Passwords must match, please try again.")])
    submit = SubmitField("Reset Password")