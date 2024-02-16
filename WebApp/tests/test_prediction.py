# Test Cases for Predictions
import pytest
from flask import json
import numpy as np
from PIL import Image
from io import BytesIO
import pytz, datetime

# Consistency Test + GET API Test for Predictions
@pytest.mark.parametrize("predConsistencyList",
    [
        [[np.zeros((1, 31, 31, 1)), "serving_default", "veggie_cnn_31x31"],
         [np.zeros((1, 31, 31, 1)), "serving_default", "veggie_cnn_31x31"],
         [np.zeros((1, 31, 31, 1)), "serving_default", "veggie_cnn_31x31"]],
        [[np.zeros((1, 128, 128, 1)), "serving_default", "veggie_cnn_128x128"],
        [np.zeros((1, 128, 128, 1)), "serving_default", "veggie_cnn_128x128"],
        [np.zeros((1, 128, 128, 1)), "serving_default", "veggie_cnn_128x128"]]
    ]
)
def test_predict_GET_API(client, predConsistencyList, capsys):
    with capsys.disabled():
        predictedOutput = []
        probabilityOutput = []
        for predictions in predConsistencyList:
            data = {
                'image': predictions[0].tolist(),
                'signature_name': predictions[1],
                'model': predictions[2]
            }
            response = client.get('/api/predict', data=json.dumps(data), content_type='application/json')
            response_body = response.json

            # Check if the response is valid
            assert response.status_code == 200
            assert response_body['prediction']
            predictedOutput.append(response_body['prediction'])

            assert response_body['probability']
            probabilityOutput.append(response_body['probability'])

            # Check if the prediction is consistent
            assert len(set(predictedOutput)) == 1
            assert len(set(probabilityOutput)) == 1

            # Make sure all the predictions are the same
            assert all(x == predictedOutput[0] for x in predictedOutput)
            assert all(x == probabilityOutput[0] for x in probabilityOutput)

# Expected Failure Test
@pytest.mark.xfail(reason="different image size inserted into same model")
@pytest.mark.parametrize("entryList", [
    [[np.zeros((1, 31, 31, 1)), "serving_default", "veggie_cnn_31x31"],
    [np.zeros((1, 20, 20, 1)), "serving_default", "veggie_cnn_31x31"],
    [np.zeros((1, 11, 11, 1)), "serving_default", "veggie_cnn_31x31"]],
    [[np.ones((1, 128, 128, 1)), "serving_default", "veggie_cnn_128x128"],
    [np.ones((1, 40, 40, 1)), "serving_default", "veggie_cnn_128x128"],
    [np.ones((1, 31, 31, 1)), "serving_default", "veggie_cnn_128x128"],],
])
def test_ExpectedFail(client,entryList, capsys):
    test_predict_GET_API(client, entryList, capsys)

# Validity Test + GET API Test for Predictions
@pytest.mark.parametrize("predValidityPredList",
    [
        [np.ones((1, 31, 31, 1)), "serving_default", "veggie_cnn_31x31"],
        [np.ones((1, 128, 128, 1)), "serving_default", "veggie_cnn_128x128"]
    ]
)
def test_Valid_GET_API(client, predValidityPredList, capsys):
    with capsys.disabled():
        data = {
            'image': predValidityPredList[0].tolist(),
            'signature_name': predValidityPredList[1],
            'model': predValidityPredList[2]
        }
        response = client.get('/api/predict', data=json.dumps(data), content_type='application/json')
        response_body = response.json

        # Check if the response is valid
        assert response.status_code == 200
        assert response_body['prediction']
        assert response_body['probability']


# Validity Test + POST API Test for Predictions
@pytest.mark.parametrize("predValidityList",
    [
        [np.zeros((1, 31, 31, 1)), "serving_default", "veggie_cnn_31x31", "Radish", 93.22],
        [np.zeros((1, 128, 128, 1)), "serving_default", "veggie_cnn_128x128", "Carrot", 58.62],
        [np.ones((1,31,31,1)), "serving_default", "veggie_cnn_31x31", "Radish", 93.01],
        [np.ones((1, 128, 128, 1)), "serving_default", "veggie_cnn_128x128", "Pumpkin", 62.49]
    ]
)
def test_predict_POST_API(client, predValidityList, capsys):
    with capsys.disabled():
        data = {
            'image': predValidityList[0].tolist(),
            'signature_name': predValidityList[1],
            'model': predValidityList[2]
        }
        response = client.post('/api/predict', data=json.dumps(data), content_type='application/json')
        response_body = response.json

        # Check if the response is valid
        assert response.status_code == 200
        assert response_body['prediction'] == predValidityList[-2]
        assert response_body['probability'] == predValidityList[-1]

# Test Add Entry API
# Uses the email added by the registerAPI
@pytest.mark.parametrize("entryList",
    [
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Radish", 93.22, "testuser1@gmail.com"],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Carrot", 58.62, "testuser2@gmail.com"],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Radish", 93.22, "testuser3@gmail.com"]
    ]
)
def test_addEntry_API(client, entryList, capsys):
    with capsys.disabled():
        data1 = {
            'image': entryList[0].decode('utf-8'),
            'DL_model': entryList[1],
            'prediction': entryList[2],
            'probability': entryList[3],
            'email': entryList[4]
        }


        response = client.post('/api/add_entry', data=json.dumps(data1), content_type='application/json')
        # Check if the response is valid
        assert response.status_code == 200
        assert response.headers["Content-Type"] == 'application/json'
        response_body = json.loads(response.get_data(as_text=True))

        # Check if the response added to the correct user
        assert response_body["email"] == entryList[4]

# Test Get Entries API based on specific emails tested previously
@pytest.mark.parametrize("getEntriesList",
    [
        ["Radish", 93.22, "testuser1@gmail.com"],
        ["Carrot", 58.62, "testuser2@gmail.com"],
        ["Radish", 93.22, "testuser3@gmail.com"]  
    ]
)
def test_getEntries_API(client, getEntriesList, capsys):
    with capsys.disabled():
        data1 = {
            'user_email': getEntriesList[2]
        }
        response = client.get('/api/get_entries', data=json.dumps(data1), content_type = 'application/json')
        # Check if the response is valid
        assert response.status_code == 200
        assert response.headers["Content-Type"] == 'application/json'
        response_body = json.loads(response.get_data(as_text=True))
        for entry in response_body["entries"]:
            # Check if the response retrieved from the correct user and correct entries are being obtained
            assert entry["prediction"] == getEntriesList[0]
            assert entry["probability"] == getEntriesList[1]
            assert entry["user_email"] == getEntriesList[2]

# Test Delete Entry API (Validity Test)
# based on specific entries keyed in previously and match the prediction values to find the correct entry id
@pytest.mark.parametrize('deleteEntryList',
    [
        ["Radish", 93.22, "testuser1@gmail.com"],
        ["Carrot", 58.62, "testuser2@gmail.com"],
        ["Radish", 93.22, "testuser3@gmail.com"]  
    ]             
)
def test_deleteEntry_API(client, deleteEntryList, capsys):
    with capsys.disabled():
        data1 = {
            'user_email': deleteEntryList[-1]
        }
        response = client.get('/api/get_entries', data=json.dumps(data1), content_type='application/json')
        # Check if the response is valid
        response_body = json.loads(response.get_data(as_text=True))

        # Checks for the entry id 
        for entry in response_body["entries"]:
            if entry["prediction"] == deleteEntryList[-2]:
                entry_id = entry["entry_id"]
                assert entry_id
                response2 = client.get(f'/api/remove_entry/{entry_id}')

                # Checks if the response are valid
                assert response2.status_code == 200
                assert response2.headers["Content-Type"] == "application/json"

                response2_body = json.loads(response2.get_data(as_text =True))
                assert response2_body["status"] == "success"
                assert int(response2_body["entry_id"]) == entry_id
                assert response2_body["message"] == "Entry is removed successfully."

# Testing the Delete Entry API with the wrong entry id
# Expected Failure Test
@pytest.mark.xfail(reason="Invalid entry id")
@pytest.mark.parametrize('deleteEntryIDList',
    [
        [1000, 2000, 3000]
    ]
)
def test_deleteEntry_API_Failure(client, deleteEntryIDList, capsys):
    with capsys.disabled():
        for entry_id in deleteEntryIDList:
            response = client.get(f'/api/remove_entry/{entry_id}')
            # Check if the response is valid
            assert response.status_code == 200
            assert response.headers["Content-Type"] == "application/json"
            response_body = json.loads(response.get_data(as_text=True))
            assert response_body["status"] == "failure"
            assert response_body["message"] == "Invalid Entry ID"

# Test filter entries API based on specific emails
@pytest.mark.xfail(reason="Invalid user id")
@pytest.mark.parametrize("filterEntriesList",
    [   # Inserting test entries to test the filters
        [[BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Radish", 93.22],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Carrot", 58.62],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Radish", 93.22],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Cauliflower", 58.62],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Tomato", 58.62],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Radish", 93.22],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Tomato", 58.62],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Tomato", 93.22],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Cauliflower", 58.62],
        ["Radish"], "veggie_cnn_31x31"],
        [[BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Radish", 93.22],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Carrot", 58.62],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Radish", 93.22],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Radish", 58.62],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Tomato", 58.62],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Radish", 93.22],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Tomato", 58.62],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Tomato", 93.22],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Cauliflower", 58.62],
        ["Radish"], "veggie_cnn_128x128"],
        [[BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Radish", 93.22],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Carrot", 58.62],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Radish", 93.22],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Radish", 58.62],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Tomato", 58.62],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Radish", 93.22],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Tomato", 58.62],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Tomato", 93.22],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Cauliflower", 58.62],
        ["Radish", "Cauliflower", "Tomato"], "veggie_cnn_31x31"],   
        [[BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Radish", 93.22],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Carrot", 58.62],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Radish", 93.22],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Broccoli", 58.62],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Tomato", 58.62],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Papaya", 93.22],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Tomato", 58.62],
        [BytesIO(Image.fromarray(np.zeros((128, 128))).tobytes()).getvalue(), "veggie_cnn_128x128", "Tomato", 93.22],
        [BytesIO(Image.fromarray(np.zeros((31, 31))).tobytes()).getvalue(), "veggie_cnn_31x31", "Cauliflower", 58.62],
        ["Radish", "Cauliflower", "Tomato"], ["veggie_cnn_31x31", "veggie_cnn_128x128"]]
    ])
def test_filter_predictions(client, capsys, filterEntriesList, test_client):
    # Use a random user id that was used to testing
    user_id = test_client['userid']
    
    # Singapore timezone timestamp
    timezone = pytz.timezone("Asia/Singapore")
    current_time = datetime.datetime.utcnow().replace(tzinfo=pytz.utc).astimezone(timezone)
    with capsys.disabled():
        for entry in filterEntriesList:
            if type(entry) != list or len(entry) == 0 or type(entry[-1]) != float:
                continue

            data = {
                "image": entry[0].decode('utf-8'),
                "DL_model": entry[1],
                "prediction": entry[2],
                "probability": entry[3],
                "predicted_on": current_time.strftime("%d %b %Y %H:%M"),
                "user_id": user_id
            }
            
            res = client.post('/api/post_entries', data=json.dumps(data), content_type='application/json')

            assert res.status_code == 200
            assert res.headers["Content-Type"] == "application/json"

        # Get the predictions later on
        url2 = "/api/filter_entries"
        data2 = {
            "user_id" : user_id,
            "timestamp_filter" : None,
            "probability_filter" : None,
            "model_filter" : filterEntriesList[-1],
            "prediction_filter" : filterEntriesList[-2],
            "search_bar": ""
        }

        res2 = client.get(url2, data=json.dumps(data2), content_type='application/json')

        assert res2.status_code == 200
        for pred in res2.json['entries']:
            assert pred["DL_model"] == filterEntriesList[-1] or pred["prediction"] in filterEntriesList[-2]
