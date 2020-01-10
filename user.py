#For this file, the majority of the code that we added can be found in the
#create_user function (any other additions were just import statements
#or something simple like that). We also added one line of code to define
#another column in the User class.

from sqlalchemy import Column, Integer, String
from app.models.base import Base
from app.util.hash import hash_pbkdf2, random_salt

class User(Base):
    __tablename__ = "users"

    #We added an additional line to create a random_salt column for our User
    #class
    username = Column(String, primary_key=True)
    random_salt = Column(String)
    password = Column(String)
    coins = Column(Integer)

    def get_coins(self):
        return self.coins

    def credit_coins(self, i):
        self.coins += i

    def debit_coins(self, i):
        self.coins -= i
  
#For this function, the first change we made is to define a rand_salt variable
#and assign it a random salt value. Within the user, we created an additional
#paramater for this random salt so that each user stores the random salt
#assigned to them (random for each user). Additionally, we changed the value
#of password so that the stored password value is the salted/hashed value of
#the plain text password as an added safety measure in case of a breach. We
#used the hash_pbkdf2 function from hash.py to do this.
def create_user(db, username, password):
    rand_salt = random_salt()
    user = User(
        username=username,
        random_salt=rand_salt,
        password=hash_pbkdf2(password, rand_salt),
        coins=100,
    )
    db.add(user)
    return user

def get_user(db, username):
    return db.query(User).filter_by(username=username).first()
