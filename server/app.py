#!/usr/bin/env python3

from flask import request, session, make_response, abort
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import HTTPException

from config import app, db, api
from models import User, Recipe


class Signup(Resource):
    def post(self):
        json = request.get_json()
        if not json.get("password"):
            raise ValueError("password must be provided")
        if not json.get("username"):
            return make_response({"message": "error"}, 422)
        user = User(
            username=json.get("username"),
            image_url=json.get("image_url"),
            bio=json.get("bio"),
        )
        user.password_hash = json["password"]
        db.session.add(user)
        db.session.commit()
        session["user_id"] = user.id
        return make_response(user.to_dict(), 201)


@app.errorhandler(Exception)
def handle_exception(e):
    return make_response({"message": str(e)}, 500)


@app.errorhandler(HTTPException)
def handle_exception(e):
    return make_response({"message": e.description}, e.code)


@app.errorhandler(ValueError)
def handle_integrity_error(e):
    return make_response({"message": str(e)}, 422)


@app.errorhandler(IntegrityError)
def handle_integrity_error(e):
    return make_response({"message": "data is not valid"}, 422)


class CheckSession(Resource):
    def get(self):
        user_id = session.get("user_id")
        if not user_id:
            abort(401, "Unauthorized")

        user = User.query.filter(User.id == user_id).first()
        return make_response(user.to_dict(), 200)


class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json.get("username")
        user = User.query.filter(User.username == username).first()
        if not user:
            abort(401)

        if not user.authenticate(json.get("password")):
            abort(401, "unauthorized user")
        session["user_id"] = user.id
        return make_response(user.to_dict(), 200)


class Logout(Resource):
    def delete(self):
        user_id = session.get("user_id")
        if not user_id:
            abort(401)
        session["user_id"] = None
        return make_response({}, 204)


class RecipeIndex(Resource):
    def get(self):
        user_id = session.get("user_id")
        if not user_id:
            abort(401)
        user = user = User.query.filter(User.id == user_id).first()
        recipes = user.recipes

        return make_response([recipe.to_dict() for recipe in recipes], 200)

    def post(self):
        user_id = session.get("user_id")
        if not user_id:
            abort(401)
        json = request.get_json()
        try:
            recipe = Recipe(
                title=json.get("title"),
                instructions=json.get("instructions"),
                minutes_to_complete=json.get("minutes_to_complete"),
            )
            recipe.user_id = user_id
            db.session.add(recipe)
            db.session.commit()
            return make_response(recipe.to_dict(), 201)
        except IntegrityError as e:
            abort(422, " data bad")


api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")
api.add_resource(RecipeIndex, "/recipes", endpoint="recipes")


if __name__ == "__main__":
    app.run(port=5555, debug=True)
