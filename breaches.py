#For this file, the majority of the code that we added can be found in the
#load_breaches function (any other additions were just import statements
#or defining csv file paths).

from csv import reader

#import statements for creating entries for each respective breach
from app.models.breaches import (
    create_plaintext_breach_entry,
    create_hashed_breach_entry,
    create_salted_breach_entry
)

#csv file paths for all 3 breaches are defined
PLAINTEXT_BREACH_PATH = "app/scripts/breaches/plaintext_breach.csv"
HASHED_BREACH_PATH = "app/scripts/breaches/hashed_breach.csv"
SALTED_BREACH_PATH = "app/scripts/breaches/salted_breach.csv"

#For this function, the code for the plaintext breach was already written out.
#Using the existing code as a model, we implemeted similar code relevant to
#the hashed and salted breaches. We changed the names of the file
#paths to the relevant paths, changed the names of the create entry functions
#to the relevant functions, and changed the inputs for the respective functions
#if necessary.  
def load_breaches(db):
    with open(PLAINTEXT_BREACH_PATH) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        for creds in r:
            create_plaintext_breach_entry(db, creds[0], creds[1])

    with open(HASHED_BREACH_PATH) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        for creds in r:
            create_hashed_breach_entry(db, creds[0], creds[1])

    with open(SALTED_BREACH_PATH) as f:
        r = reader(f, delimiter=' ')
        header = next(r)
        assert(header[0] == 'username')
        for creds in r:
            create_salted_breach_entry(db, creds[0], creds[1], creds[2])
