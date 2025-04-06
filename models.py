from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from flask import current_app

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    current_level = db.Column(db.Integer, default=1)
    completed_levels = db.Column(db.String(200), default='')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def complete_level(self, level_id):
        completed = set(map(int, self.completed_levels.split(','))) if self.completed_levels else set()
        completed.add(level_id)
        self.completed_levels = ','.join(map(str, sorted(completed)))

        # Find next uncompleted level
        next_level = max(completed) + 1 if completed else 1
        self.current_level = next_level
        db.session.commit()

    def add_quiz_result(self, level, score, correct_answers, total_questions):
        result = QuizResult(
            user_id=self.id,
            level=level,
            score=score,
            correct_answers=correct_answers,
            total_questions=total_questions
        )
        db.session.add(result)
        db.session.commit()

    def generate_auth_token(self, expires_in=3600):
        return jwt.encode(
            {'id': self.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in)},
            current_app.config['SECRET_KEY'],
            algorithm='HS256'
        )

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            return User.query.get(data['id'])
        except Exception:
            return None


class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    level = db.Column(db.Integer, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    user = db.relationship('User', backref=db.backref('scores', lazy=True))

    __table_args__ = (
        db.Index('idx_user_level', 'user_id', 'level'),
    )


class QuizResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    level = db.Column(db.Integer, nullable=False)
    score = db.Column(db.Integer, nullable=False)
    correct_answers = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    user = db.relationship('User', backref=db.backref('quiz_results', lazy=True))

    __table_args__ = (
        db.Index('idx_quiz_user_level', 'user_id', 'level'),
    )