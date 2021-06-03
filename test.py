import requests
from base64 import b64encode
# Meeting ID: 993 7486 2702 rGBSWhHgYX_NSu_bVQwQLeTf1pCb4fldA

meeting_id = "993 7486 2702"

# baylee's auth code rGBSWhHgYX_NSu_bVQwQLeTf1pCb4fldA

# url = 'https://zoom.us/oauth/token'
# print(url)

"""

"""

# tinas_Access = "eyJhbGciOiJIUzUxMiIsInYiOiIyLjAiLCJraWQiOiIwMDNmMzhmNC04NzhjLTRjOTgtYTFhMS1iZDZmZTE4M2EyZDAifQ.eyJ2ZXIiOjcsImF1aWQiOiI2YTA4ZjE4MDg2YzM3MTRkMGQ2NDYwNzg3NTg4ZDg0ZCIsImNvZGUiOiJlV3dZUHY4cUpnXzJkbDNMeVRMUjFtb0xGZVRKQUtHb3ciLCJpc3MiOiJ6bTpjaWQ6QTlNbXlpNHhRVGFWeWgxRndmbEtWUSIsImdubyI6MCwidHlwZSI6MCwidGlkIjowLCJhdWQiOiJodHRwczovL29hdXRoLnpvb20udXMiLCJ1aWQiOiIyZGwzTHlUTFIxbW9MRmVUSkFLR293IiwibmJmIjoxNjIyNjYyMTMxLCJleHAiOjE2MjI2NjU3MzEsImlhdCI6MTYyMjY2MjEzMSwiYWlkIjoibkpBUDZsTGtSZ2VlQVdJaHBpUFFhUSIsImp0aSI6IjQ4YjU2NWNhLTk3OTgtNDdkNy04M2RiLWZiMDAzZjQxYmM4OCJ9.JDzr1Ft_NU_h2exNb5OhFUyob4pRLsOMuk6MuXhxwBAZiqG_AkwCTsWDG9yDQ6l78uI1LlJh9WhMdh5M4LBc4A"
baylees_access = "eyJhbGciOiJIUzUxMiIsInYiOiIyLjAiLCJraWQiOiIwYTZiOTU2NS0xZWIxLTRiNzgtOTkyZC0zYTlmNTA0Mjk5MWIifQ.eyJ2ZXIiOjcsImF1aWQiOiIyYTRiYTU3ZWFhZDNjYzgxNzdkZDQxZDE2MjhmN2I4NCIsImNvZGUiOiJBb3h1MUo3cTBVX05TdV9iVlF3UUxlVGYxcENiNGZsZEEiLCJpc3MiOiJ6bTpjaWQ6QUxpRlJtclRRQXdKZHBnVnNzbHd3IiwiZ25vIjowLCJ0eXBlIjowLCJ0aWQiOjAsImF1ZCI6Imh0dHBzOi8vb2F1dGguem9vbS51cyIsInVpZCI6Ik5TdV9iVlF3UUxlVGYxcENiNGZsZEEiLCJuYmYiOjE2MjI2NjM1MTcsImV4cCI6MTYyMjY2NzExNywiaWF0IjoxNjIyNjYzNTE3LCJhaWQiOiJuSkFQNmxMa1JnZWVBV0locGlQUWFRIiwianRpIjoiMWIyNTljZDYtZTI5Zi00MDk4LWE5YTctYTFlMGQxMDA2NDBmIn0.EyeRjMDxka5IBtaOVq6oKAHZ6tzpJt1I5xhYqsLVGjnJg43QeuI0Zuo3yMVzH1U70MhnFu0Yo57VJmtaKIEDkA"


authorization2 = "Bearer " + baylees_access

headers2 = {"Authorization": authorization2}

url2 = "https://api.zoom.us/v2/users/me/recordings"
response2 = requests.get(url2, headers=headers2)
# print(response2)
data = response2.json()
# print(data)

# must refresh every time ?
auth_code = "LmlQDb8jDQ_2dl3LyTLR1moLFeTJAKGow"


def get_access_token(auth_code):
    """
    retrieves access token based on someones auth code
    """
    clientid = 'A9Mmyi4xQTaVyh1FwflKVQ'
    clientsec = '4YjioAh3ArPNWGfQRXQ5FChuxznL77Hx'

    str_code = (clientid + ":" + clientsec)
    ascii_code = str_code.encode("ascii")
    authorization = "Basic " + str(b64encode(ascii_code))[2:-1]

    print(authorization)

    content_type = 'application/x-www-form-urlencoded'

    headers = {"Authorization": authorization, "Content-Type": content_type}

    redirect_uri = "https://rice.edu/"

    url = "https://zoom.us/oauth/token?code=" + auth_code + \
        "&grant_type=authorization_code&redirect_uri=" + redirect_uri

    response = requests.post(url, headers=headers)
    print(response.text)
    data = response.json()
    access_token = data['access_token']
    # print(access_token)

    return access_token


def refresh_token():
    """
    refresh access token after 60min
    make post request to https://zoom.us/oauth/token

    """


def get_recordings(access_token, meeting_id):
    """
    returns a list of meeting recordings given a meeting ID
    """
    authorization2 = "Bearer " + access_token

    headers2 = {"Authorization": authorization2}

    url2 = "https://api.zoom.us/v2/meetings/" + meeting_id + "/recordings"
    response2 = requests.get(url2, headers=headers2)
    print(response2)
    data = response2.json()
    # print(data)

    # list of dictionaries
    # recordings = data['recording_files']

    return data


access_token = get_access_token(auth_code)
print(get_recordings(access_token, "99374862702"))
