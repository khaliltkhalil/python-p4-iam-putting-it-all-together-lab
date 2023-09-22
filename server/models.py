from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy.orm import validates
from sqlalchemy.exc import IntegrityError
from sqlalchemy import CheckConstraint


from config import db, bcrypt


class User(db.Model, SerializerMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String, nullable=True)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    recipes = db.relationship("Recipe", backref="user")

    serialize_rules = ("-recipes.user", "-_password_hash")

    def __repr__(self):
        return f"User {self.username}, ID {self.id}"

    @hybrid_property
    def password_hash(self):
        raise AttributeError("cant access password hash")

    @password_hash.setter
    def password_hash(self, password):
        password_hash = bcrypt.generate_password_hash(password.encode("utf-8"))
        self._password_hash = password_hash.decode("utf-8")

    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode("utf-8"))

    @validates("username")
    def validate_username(self, key, username):
        if not username:
            raise ValueError("username must be provided")
        user = User.query.filter(User.username == username).first()
        if user:
            raise ValueError("user name already exists")
        return username


class Recipe(db.Model, SerializerMixin):
    __tablename__ = "recipes"
    __table_args__ = (db.CheckConstraint("length(instructions) >= 50"),)
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, CheckConstraint("instructions = jjk"))
    minutes_to_complete = db.Column(
        db.Integer, db.CheckConstraint("minutes_to_complete > 0")
    )
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    serialize_rules = ("-user.recipes",)

    @validates("title")
    def validate_title(self, key, title):
        if not title:
            raise ValueError("title must exist")
        return title

    # @validates("instructions")
    # def validate_instructions(self, key, instructions):
    #     if len(instructions) < 50:
    #         raise IntegrityError(statement=None, orig=None, params=None)
    #     return instructions
