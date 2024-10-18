#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        print("post1")
        try:
            new_user = User(
                username=request.get_json()['username'],
                image_url=request.get_json()['image_url'] if request.get_json()['image_url'] else None,
                bio=request.get_json()['bio'] if request.get_json()['bio'] else None,
            )
            print(new_user)
            new_user.password_hash = request.get_json()['password']
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id
            return new_user.to_dict(), 201
        except:
            return {'error': '422 Unprocessable Entity'}, 422

class CheckSession(Resource):
    def get(self):
        if session.get('user_id'):
            return User.query.get(session['user_id']).to_dict()
        else:
            return {'error': '401 Unauthorized'}, 401

class Login(Resource):
    def post(self):
        print("post2")
        user = User.query.filter(
            User.username == request.get_json()['username']
        ).first()
        if user and user.authenticate(request.get_json()['password']):
            session['user_id'] = user.id
            print(session['user_id'])

            return user.to_dict()
        else:
            return {'error': '401 Unauthorized'}, 401

class Logout(Resource):
    def delete(self):
        # print(session['user_id'])
        if  session.get('user_id'):
            session['user_id'] = None
            return {}, 204
        else:
            return {'error': '401 Unauthorized'}, 401

class RecipeIndex(Resource):
    def get(self):
        if session['user_id']:
            return [recipe.to_dict() for recipe in Recipe.query.all()], 200
        else:
            return {'error': '401 Unauthorized'}, 401
    def post(self):
        if not session['user_id']:
            return {'error': '401 Unauthorized'}, 401
        try:
            new_recipe = Recipe(
                title=request.get_json()['title'],
                instructions=request.get_json()['instructions'],
                minutes_to_complete=request.get_json()['minutes_to_complete'],
                user_id=session['user_id']
            )
            db.session.add(new_recipe)
            db.session.commit()
            return new_recipe.to_dict(), 201
        except:
            return {'error': '422 Unprocessable Entity'}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)