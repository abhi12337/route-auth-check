from flask import Flask, abort, jsonify, request
from flask_cors import CORS
from flask_login import login_required

from .models import Comment, Post, User, db

app = Flask(__name__)
CORS(app, supports_credentials=True)


@app.route("/api/posts/<int:post_id>", methods=["PUT"])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    data = request.get_json()
    for key, value in data.items():
        setattr(post, key, value)
    db.session.commit()
    return jsonify(post.to_dict())


@app.route("/api/comments", methods=["POST"])
def add_comment():
    data = request.get_json()
    comment = Comment(**data)
    db.session.add(comment)
    db.session.commit()
    return jsonify(comment.to_dict()), 201


@app.post("/api/admin/promote/<int:user_id>")
@login_required
def promote(user_id):
    if request.headers.get("X-User-Role") != "admin":
        abort(403)
    user = db.get_or_404(User, user_id)
    user.role = "admin"
    db.session.commit()
    return jsonify(ok=True)
