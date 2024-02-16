# Test Cases for Authentication (Login/Register)
import pytest
from flask import json

# Validity Test + POST API Test for Register
@pytest.mark.xfail(reason="Already registered user")
@pytest.mark.parametrize("registerList",[
    ["testuser1", "testuser1@gmail.com", "Testuser1!", "Testuser1!", True],
    ["testuser1", "testuser2@gmail.com", "Testuser1!", "Testuser1!", False],
    ["testuser2", "testuser2@gmail.com", "Testuser2!", "Testuser2!", True],
    ["testuser3", "testuser3@gmail.com", "Testuser3!", "Testuser3!", True]
])
def test_register_Valid_POST_API(client, registerList, capsys):
    with capsys.disabled():
        # Register the user
        data = {
            "username": registerList[0],
            "email": registerList[1],
            "password": registerList[2],
            "confirm_password": registerList[3]
        }
        response = client.post('/api/register', data=json.dumps(data), content_type="application/json")
        response_body = response.json

        # Check if the response is valid
        assert response.status_code == 200
        assert response.headers["Content-Type"] == "application/json"

        assert response_body["status"] == "success"
        assert response_body["registered"] == registerList[-1]

        # If the user is registered, check if the user is in present in the json response
        if registerList[-1]:
            assert response_body["userid"]

# Expected Failure Test + POST API Test for Register
@pytest.mark.xfail(reason="Not valid username, email, password or mismatched confirm password")
@pytest.mark.parametrize("registerList",[
    ["testuser@1", "testuser1@gmail.com", "Testuser1!", "Testuser1!", False],
    ["Testuser 2", "testuser2@gmail.com", "Testuser2!", "TestUser2!", False],
    ["testuser.3", "@gmail.com", "Testuser3!", "Testuser3!", False],
    ["testuser4", "testuser4@", "Testuser4!", "Testuser4!", False]
])
def test_register_Failure_POST_API(client, registerList, capsys):
    test_register_Valid_POST_API(client, registerList, capsys)


# Validity Test + GET API Test for Login
@pytest.mark.parametrize("loginlist",[
    ["testuser1", "Testuser1!"],
    ["testuser2", "Testuser2!"],
    ["testuser3", "Testuser3!"]
])
def test_login_Valid_POST_API(client, loginlist,capsys):
    with capsys.disabled():
        # Login the user
        data = {
            "username": loginlist[0],
            "password": loginlist[1]        
        }
        response = client.get('/api/login', data=json.dumps(data), content_type="application/json")
        response_body = response.json

        # Check if the response is valid
        assert response.status_code == 200
        assert response.headers["Content-Type"] == "application/json"

        assert response_body["status"] == "success"
        assert response_body["logged_in"] == True
        assert response_body["userid"]

# Expected Failure Test + GET API Test for Login
@pytest.mark.xfail(reason="Not valid username or password")
@pytest.mark.parametrize("loginlist", [
    ["testuser1", "Testuser2!"],
    ["testuser2", "Testuser3!"],
    ["testuser4", "Testuser4!"]
])
def test_login_Failure_POST_API(client, loginlist, capsys):
    test_login_Valid_POST_API(client, loginlist, capsys)