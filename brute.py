#For this file, the majority of the code that we added can be found in the
#brute_force_attack function (any other additions were just import
#statements or something simple like that).

from csv import reader
from app.util.hash import hash_pbkdf2

COMMON_PASSWORDS_PATH = 'common_passwords.txt'
SALTED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"

def load_breach(fp):
    with open(fp) as f:
        r = reader(f, delimiter=' ') 
        header = next(r)
        assert(header[0] == 'username')
        return list(r)

def load_common_passwords():
    with open(COMMON_PASSWORDS_PATH) as f:
        pws = list(reader(f))
    return pws

#For this function, we read in a target hash and a target salt. We then load in
#the common passwords. For each common password, we convert the plain text
#password to a hashed/salted password using the hash_pbkdf2 function (imported
#from hash.py). If this hashed and salted password equals our target hash, then
#we return the original matching password. If no such case is found, our
#function will return None.
def brute_force_attack(target_hash, target_salt):
    pwds = load_common_passwords()
    for i in range(len(pwds)):
        pwd = pwds[i][0]
        output_salt = hash_pbkdf2(pwd, target_salt)
        if output_salt == target_hash:
            return pwd
        else:
            continue
    return None

#In the main method, we can choose which row in the salted breach csv we want
#to test. We tested rows 0 and 10: row 0 returned the password 'shepherd' and
#row 10 returned the password 'first.'
def main():
    salted_creds = load_breach(SALTED_BREACH_PATH)
    print(brute_force_attack(salted_creds[0][1], salted_creds[0][2]))

if __name__ == "__main__":
    main()
