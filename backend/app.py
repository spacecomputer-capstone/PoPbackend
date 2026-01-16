import os
from flask import Flask, send_from_directory, request
from dotenv import load_dotenv
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS

from backend.extensions import db


def register_swagger(app: Flask):
    @app.get("/openapi.yaml")
    def openapi_yaml():
        here = os.path.dirname(__file__)  # backend/
        return send_from_directory(here, "openapi.yaml", mimetype="text/yaml")

    SWAGGER_URL = "/docs"
    API_URL = "/openapi.yaml"

    swaggerui_bp = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={"app_name": "Proof-of-Presence API"},
    )
    app.register_blueprint(swaggerui_bp, url_prefix=SWAGGER_URL)


def create_app():
    load_dotenv()

    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DATABASE_URL"]
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)

    # ✅ CORS for browser frontend on localhost
    CORS(
        app,
        resources={r"/presence/*": {"origins": [
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ]}},
        allow_headers=["Content-Type", "Accept", "X-User-Id"],
        methods=["GET", "POST", "OPTIONS"],
    )

    # ✅ Helps Chrome when calling a private IP (172.20.10.7) from localhost (PNA)
    @app.after_request
    def add_pna_header(resp):
        origin = request.headers.get("Origin")
        if origin in {
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://localhost:9001",
            "http://127.0.0.1:9001",
        }:
            resp.headers["Access-Control-Allow-Private-Network"] = "true"
        return resp

    from backend.routes import presence_bp
    app.register_blueprint(presence_bp)

    @app.get("/health")
    def health():
        return {"ok": True}

    register_swagger(app)

    return app


if __name__ == "__main__":
    app = create_app()
    # Important: allow other devices on LAN to reach it (optional but usually desired)
    app.run(host="0.0.0.0", port=5001, debug=True)
