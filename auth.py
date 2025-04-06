from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Score
import jwt
import datetime

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()

    # Validate data
    if not data or not data.get('email') or not data.get('password') or not data.get('name'):
        return jsonify({'error': 'Missing required fields'}), 400

    if data['password'] != data.get('passwordConfirm'):
        return jsonify({'error': 'Passwords do not match'}), 400

    # Check if user already exists
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already registered'}), 409

    # Create new user
    new_user = User(
        name=data['name'],
        email=data['email'],
        current_level=1,
        completed_levels=''
    )
    new_user.set_password(data['password'])

    db.session.add(new_user)
    db.session.commit()

    # Generate token
    token = new_user.generate_auth_token()

    return jsonify({
        'message': 'User registered successfully',
        'token': token,
        'user': {
            'id': new_user.id,
            'name': new_user.name,
            'email': new_user.email,
            'current_level': new_user.current_level,
            'completed_levels': []
        }
    }), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'error': 'Missing email or password'}), 400

    user = User.query.filter_by(email=data['email']).first()

    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid email or password'}), 401

    token = user.generate_auth_token()

    completed_levels = [int(level) for level in user.completed_levels.split(',')] if user.completed_levels else []

    return jsonify({
        'message': 'Logged in successfully',
        'token': token,
        'user': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'current_level': user.current_level,
            'completed_levels': completed_levels
        }
    })


@auth_bp.route('/progress', methods=['GET', 'OPTIONS'])
@auth_bp.route('/progress/<int:level_id>', methods=['POST', 'OPTIONS'])
def user_progress(level_id=None):
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header must be Bearer token'}), 401

    try:
        token = auth_header.split()[1]
        user = User.verify_auth_token(token)
        if not user:
            return jsonify({'error': 'Invalid or expired token'}), 401

        if request.method == 'GET':
            completed_levels = [int(level) for level in
                                user.completed_levels.split(',')] if user.completed_levels else []
            return jsonify({
                'current_level': user.current_level,
                'completed_levels': completed_levels
            }), 200

        elif request.method == 'POST':
            if not level_id:
                return jsonify({'error': 'Level ID is required'}), 400

            # Ensure the level is the next expected level
            if level_id != user.current_level:
                return jsonify({
                    'error': f'Cannot complete level {level_id}. Current expected level is {user.current_level}'
                }), 400

            user.complete_level(level_id)

            completed_levels = [int(level) for level in
                                user.completed_levels.split(',')] if user.completed_levels else []

            return jsonify({
                'message': f'Level {level_id} completed successfully',
                'current_level': user.current_level,
                'completed_levels': completed_levels
            }), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    except Exception as e:
        current_app.logger.error(f"Error in user_progress: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@auth_bp.route('/scores', methods=['POST', 'GET', 'OPTIONS'])
def handle_scores():
    if request.method == 'OPTIONS':
        return jsonify({}), 200

    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header must be Bearer token'}), 401

    try:
        token = auth_header.split()[1]
        user = User.verify_auth_token(token)
        if not user:
            return jsonify({'error': 'Invalid or expired token'}), 401

        if request.method == 'POST':
            data = request.get_json()
            if not data or 'level' not in data or 'score' not in data:
                return jsonify({'error': 'Missing level or score data'}), 400

            # Check if score already exists for this level
            existing_score = Score.query.filter_by(
                user_id=user.id,
                level=data['level']
            ).first()

            if existing_score:
                # Update if new score is higher
                if data['score'] > existing_score.score:
                    existing_score.score = data['score']
                    existing_score.created_at = datetime.datetime.utcnow()
                    db.session.commit()
                    message = 'Score updated successfully'
                else:
                    message = 'Existing score is higher, keeping previous score'
            else:
                # Create new score record
                new_score = Score(
                    user_id=user.id,
                    level=data['level'],
                    score=data['score']
                )
                db.session.add(new_score)
                db.session.commit()
                message = 'Score saved successfully'

            return jsonify({
                'message': message,
                'level': data['level'],
                'score': data['score']
            }), 200

        elif request.method == 'GET':
            scores = Score.query.filter_by(user_id=user.id).order_by(Score.level).all()
            scores_data = [{
                'level': score.level,
                'score': score.score,
                'date': score.created_at.isoformat()
            } for score in scores]

            return jsonify({
                'scores': scores_data,
                'highest_score': max([score.score for score in scores], default=0)
            }), 200

    except Exception as e:
        current_app.logger.error(f"Error in handle_scores: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500


@auth_bp.route('/quiz', methods=['POST'])
def save_quiz_result():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header must be Bearer token'}), 401

    try:
        token = auth_header.split()[1]
        user = User.verify_auth_token(token)
        if not user:
            return jsonify({'error': 'Invalid or expired token'}), 401

        data = request.get_json()
        if not data or 'level' not in data or 'score' not in data:
            return jsonify({'error': 'Missing required data'}), 400

        # Save quiz results
        user.add_quiz_result(
            level=data['level'],
            score=data['score'],
            correct_answers=data.get('correct_answers', 0),
            total_questions=data.get('total_questions', 1)
        )

        # Also update the user's level progress if needed
        if data.get('mark_level_completed', False):
            user.complete_level(data['level'])
            db.session.commit()

        return jsonify({
            'message': 'Quiz results saved successfully',
            'current_level': user.current_level,
            'completed_levels': list(map(int, user.completed_levels.split(','))) if user.completed_levels else []
        }), 200

    except Exception as e:
        current_app.logger.error(f"Error saving quiz results: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500