# Test Cases for Forgotten Password
import pytest
from flask import json

# Validity Test + GET API Test for Email Confirmation
@pytest.mark.parametrize("email_list",[
    ["testuser1@gmail.com"],
    ["testuser2@gmail.com"],
    ["testuser3@gmail.com"]
])
def test_email_Valid_POST_API(client, email_list,capsys):
    with capsys.disabled():
        # Login the user
        data = {
            "email": email_list[0]       
        }
        response = client.get('/api/email_confirm', data=json.dumps(data), content_type="application/json")
        response_body = response.json

        # Check if the response is valid
        assert response.status_code == 200
        assert response.headers["Content-Type"] == "application/json"

        assert response_body["status"] == "success"
        assert response_body["email_confirm"] == True
        assert response_body["userid"]

# Expected Failure Test + GET API Test for Email Confirmation
@pytest.mark.xfail(reason="Not valid email")
@pytest.mark.parametrize("email_list", [
    ["testuser4@gmail.com"],
    ["testuser5@gmail.com"],
    ["testuser6@gmail.com"]
])
def test_login_Failure_POST_API(client, email_list, capsys):
    test_email_Valid_POST_API(client, email_list, capsys)

