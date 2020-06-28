from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
import os
from datetime import datetime
from helpers import serialize_list, parse_float, parse_int, parse_datetime, parse_units, parse_title
from constants import PAGE_SIZE
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

load_dotenv()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255), nullable=False, default='')
    last_name = db.Column(db.String(255), nullable=False, default='')
    username = db.Column(db.String(255), nullable=False, unique=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def serialize(self):
        return {
            'id': self.id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'username': self.username,
            'email': self.email,
            'admin': self.admin,
            'created_at': self.created_at
        }

class Run(db.Model):
    __tablename__ = 'runs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    run_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    distance = db.Column(db.Float, nullable=False, default=0)
    duration = db.Column(db.Float, nullable=False, default=0)
    title = db.Column(db.String(255), nullable=False, default='Normal Run')
    description = db.Column(db.Text, nullable=False, default='')
    units = db.Column(db.String(2), nullable=False, default='mi')
    location = db.Column(db.String(255), nullable=False, default='')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def serialize(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'run_date': self.run_date,
            'distance': self.distance,
            'duration': self.duration,
            'title': self.title,
            'description': self.description,
            'units': self.units,
            'location': self.location,
            'created_at': self.created_at
        }

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    if not username:
        return jsonify({'error': 'must supply a username'}), 400
    if not password:
        return jsonify({'error': 'must supply a password'}), 400
    user = User.query.filter_by(username=username).first()
    if user is None:
        return jsonify({'error': 'user with that username does not exist'}), 400
    if not bcrypt.check_password_hash(user.password, password.encode('utf-8')):
        return jsonify({'error': 'incorrect password'}), 400
    access_token = create_access_token(identity=user.serialize(), expires_delta=False)
    return jsonify({'user': user.serialize(), 'access_token': access_token})

@app.route('/api/signup', methods=['POST'])
def signup():
    username = request.json.get('username')
    email = request.json.get('email')
    password = request.json.get('password')
    if not username:
        return jsonify({'error': 'must supply a username'}), 400
    if not email:
        return jsonify({'error': 'must supply an email'}), 400
    if not password:
        return jsonify({'error': 'must supply a password'}), 400
    if len(password) < 8:
        return jsonify({'error': 'password must be at least 8 characters'}), 400
    if User.query.filter_by(username=username).scalar():
        return jsonify({'error': 'username already taken'}), 400
    if User.query.filter_by(email=email).scalar():
        return jsonify({'error': 'email already taken'}), 400
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(
        username=username,
        email=email,
        password=pw_hash
    )
    try:
        db.session.add(user)
        db.session.commit()
    except Exception as e:
        return jsonify({'error': 'unable to create new user', 'code': str(e)}), 500
    access_token = create_access_token(identity=user.serialize(), expires_delta=False)
    return jsonify({'user': user.serialize(), 'access_token': access_token}), 201

@app.route('/api/users', methods=['GET'])
@jwt_required
def user_list():
    identity = get_jwt_identity()
    page = parse_int(request.args.get('page', 1))
    users = User.query.order_by(User.username).paginate(page, PAGE_SIZE, error_out=False)
    return jsonify({'users': serialize_list(users)})

@app.route('/api/users/<int:user_id>', methods=['GET'])
@jwt_required
def user_detail(user_id):
    identity = get_jwt_identity()
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return jsonify({'error': 'user does not exist'}), 404
    return jsonify({'user': user.serialize()})

@app.route('/api/runs', methods=['GET', 'POST'])
@jwt_required
def run_list():
    identity = get_jwt_identity()
    if request.method == 'GET':
        page = parse_int(request.args.get('page', 1))
        runs = Run.query.order_by(Run.run_date.desc()).paginate(page, PAGE_SIZE, error_out=False)
        return jsonify({'runs': serialize_list(runs)})
    else:
        run = Run(
            user_id=identity['id'],
            run_date=parse_datetime(request.json.get('run_date')) or datetime.utcnow(),
            distance=parse_float(request.json.get('distance')),
            duration=parse_float(request.json.get('duration')),
            title=parse_title(request.json.get('title')),
            description=request.json.get('description', ''),
            units=parse_units(request.json.get('units')),
            location=request.json.get('location', '')
        )
        try:
            db.session.add(run)
            db.session.commit()
        except Exception as e:
            return jsonify({'error': 'unable to create new run', 'code': str(e)}), 500
        return jsonify({'run': run.serialize()}), 201

@app.route('/api/runs/<int:run_id>', methods=['GET', 'PUT', 'DELETE'])
@jwt_required
def run_detail(run_id):
    identity = get_jwt_identity()
    run = Run.query.filter_by(id=run_id).first()
    if run is None:
        return jsonify({'error': 'run does not exist'}), 404
    if request.method == 'PUT':
        if identity['id'] != run.user_id:
            return jsonify({'error': 'unauthorized to update run'}), 403
        run.run_date = parse_datetime(request.json['run_date']) if 'run_date' in request.json else run.run_date
        run.distance = parse_float(request.json['distance']) if 'distance' in request.json else run.distance
        run.duration = parse_float(request.json['duration']) if 'duration' in request.json else run.duration
        run.title = request.json['title'] if 'title' in request.json else run.title
        run.description = request.json['description'] if 'description' in request.json else run.description
        run.units = parse_units(request.json['units']) if 'units' in request.json else run.units
        run.location = request.json['location'] if 'location' in request.json else run.location
        try:
            db.session.commit()
        except Exception as e:
            return jsonify({'error': 'unable to update run', 'code': str(e)}), 500
        return jsonify({'run': run.serialize()})
    if request.method == 'DELETE':
        if identity['id'] != run.user_id:
            return jsonify({'error': 'unauthorized to delete run'}), 403
        try:
            db.session.delete(run)
            db.session.commit()
        except Exception as e:
            return jsonify({'error': 'unable to delete run', 'code': str(e)}), 500
    return jsonify({'message': 'run deleted'})

if __name__ == '__main__':
    app.run()
