# README

This project involves using the DevOps process to develop a Deep Learning models that is able to predict the vegetable classes based on the images uploaded and the model selected (i.e. CNN 31x31 and CNN 128x128) by the users.
With the help of tensorflow-serving and docker, the models will be served in production environment and containerized with their dependencies. The models would be deployed on Render (i.e. https://veggietales-cnn.onrender.com/v1/models/veggie_cnn_31x31)
(i.e. https://veggietales-cnn.onrender.com/v1/models/veggie_cnn_128x128) so users are able to enjoy the full features of the models to help to make predictions. 

#### CI/CD pipeline has also been demonstrated
CI - Each commit and merge triggers an automated series of tests using PyTest to ensure changes do not conflict with existing codebase <br>
CD - Every change that passed automated testing will be automatically deployed to production via Render <br> 
Feedback Loop - As part of CI, developers receive immediate feedback, allowing problems to be addressed quickly. This was done through Discord, making use of webhooks linked to Gitlab and everytime users commit their code, merge their code, make changes to issues etc., a notification will be send to the Discord Channel

#### Web Application (i.e. https://veggietales.onrender.com/login)
This project aim to develop a Deep Learning Web application that is able to predict the vegetable classes based on the images uploaded and the model selected (i.e. CNN 31x31 and CNN 128x128) by the users.
The result of the prediction will produce these columns in the form of a history table:
  1. Entry ID
  2. Image
  3. Model (CNN 31x31 or CNN 128x128)
  4. Prediction (15 classes):
    - e.g. ["Bean", "Bitter Gourd", "Bottle Gourd", "Brinjal", "Broccoli", "Cabbage", "Capsicum", "Carrot", "Cauliflower", "Cucumber", "Papaya", "Potato", "Pumpkin", "Radish", "Tomato"]
  5. Probability (Max C.I of the prediction)
  6. Timestamp (SG time)

#### Filter and Search Records
Users are also able to view specific records through searching and filtering of values. 
They are able to filter based on timestamps and accuracy in ascending and descending manner, choose records that contains certain predictions and models used for predictions for specific records. 
