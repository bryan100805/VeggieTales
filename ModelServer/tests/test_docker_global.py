import pytest
import requests
import base64
import json
import numpy as np
from tensorflow.keras.preprocessing import image
import os

# Server URLs (test remote deployment)
url_31x31 = "https://veggietales-cnn.onrender.com/v1/models/veggie_cnn_31x31:predict"
url_128x128 = "https://veggietales-cnn.onrender.com/v1/models/veggie_cnn_128x128:predict"

# Load test images from images folder
def load_image(img_size):
    local_path = os.path.join(os.getcwd(), 'tests/images')
    images_list = []
    for label in os.listdir(local_path):
        for filename in os.listdir(os.path.join(local_path,label)):
            # Load image of specified size and feature scale
            img = image.load_img(os.path.join(local_path,label, filename), color_mode='grayscale', target_size=(img_size, img_size))
            img = image.img_to_array(img)/255.0
            # Reshape image to (1, img_size, img_size, 1)
            img = img.reshape(1, img_size, img_size, 1)
            images_list.append(img)
    return images_list

# Predict using test images
def make_prediction(instances, url):
    # Send POST API request to server
    data = json.dumps({"signature_name": "serving_default", "instances": instances.tolist()})
    headers = {"content-type": "application/json"}
    json_response = requests.post(url, data=data, headers=headers)
    # Parse response
    predictions = json.loads(json_response.text)['predictions']
    return predictions

# Test prediction for 31x31 model
def test_prediction_31():
    data = load_image(31)
    for img in data:
        predictions = make_prediction(img, url_31x31)
        # Check if prediction is a list
        assert isinstance(predictions, list)
        # Check if prediction is a list of length 1
        assert len(predictions) == 1
        # Check if each prediction is a float
        assert isinstance(predictions[0][0], float)

# Test prediction for 128x128 model
def test_prediction_128():
    data = load_image(128)
    for img in data:
        predictions = make_prediction(img, url_128x128)
        # Check if prediction is a list
        assert isinstance(predictions, list)
        # Check if prediction is a list of length 1
        assert len(predictions) == 1
        # Check if prediction is a float
        assert isinstance(predictions[0][0], float)