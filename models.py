from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, user_id, name, username, password, role):
        self.id = user_id
        self.name = name
        self.username = username
        self.password = password
        self.role = role

    @property
    def id(self):
        return self._id
    
    @id.setter
    def id(self, value):
        self._id = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        self._username = value

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        self._password = value

    @property
    def role(self):
        return self._role

    @role.setter
    def role(self, value):
        self._role = value