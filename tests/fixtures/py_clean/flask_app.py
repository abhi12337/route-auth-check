from flask import Flask, abort, jsonify, request
from flask_cors import CORS
from flask_login import current_user, login_required

from .models import Comment, Post, User, db

app = Flask(__name__)
CORS(app, origins=["https://app.example.com"], supports_credentials=True)


@app.route("/api/posts/<int:post_id>", methods=["PUT"])
@login_required
def update_post(post_id):
    post = Post.query.filter_by(id=post_id, user_id=current_user.id).first_or_404()
    data = request.get_json()
    post.title = data["title"]
    post.body = data["body"]
    db.session.commit()
    return jsonify(post.to_dict())


@app.route("/api/comments", methods=["POST"])
@login_required
def add_comment():
    data = request.get_json()
    comment = Comment(post_id=data["post_id"], text=data["text"], user_id=current_user.id)
    db.session.add(comment)
    db.session.commit()
    return jsonify(comment.to_dict()), 201


@app.post("/api/admin/promote/<int:user_id>")
@login_required
def promote(user_id):
    if not current_user.is_admin:
        abort(403)
    user = db.get_or_404(User, user_id)
    user.role = "admin"
    db.session.commit()
    return jsonify(ok=True)


@app.post("/webhooks/github")
def github_webhook():
    return "", 204
