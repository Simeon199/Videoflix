# Videoflix

This project is designed as a portfolio project for further training as a backend developer. It builds on an existing frontend and is a video streaming backend built with Django REST Framework. It provides user authentication, video upload with automatic HLS conversion, and adaptive bitrate streaming at multiple resolutions. The respective frontend repository can be found under the following link:
[Videoflix Frontend](https://github.com/Developer-Akademie-Backendkurs/project.Videoflix)

## Table of Contents

- [Tech Stack](#tech-stack)
- [Features](#features)
- [API Endpoints](#api-endpoints)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Running Tests](#running-tests)
- [Project Structure](#project-structure)
- [Video Processing Pipeline](#video-processing-pipeline)
- [Contributing](#contributing)
- [License](#license)

## Tech Stack

- **Python 3.12** / **Django 6.0**
- **Django REST Framework** – RESTful API
- **PostgreSQL** – Database
- **Redis** – Caching & task queue
- **Django-RQ** – Background job processing
- **FFmpeg** – Video encoding (HLS)
- **Docker** – Containerized deployment

## Features

- **Authentication** – Registration with email activation, JWT login/logout, token refresh, password reset
- **Video Management** – Upload videos with title, description, category, and thumbnail
- **HLS Streaming** – Automatic conversion to 480p, 720p, and 1080p with adaptive bitrate support
- **Background Processing** – Video conversion runs asynchronously via Redis Queue
- **Caching** – HLS manifests are cached with Redis for fast delivery

## API Endpoints

### Authentication

| Method | Endpoint                                  | Description            |
| ------ | ----------------------------------------- | ---------------------- |
| POST   | `/api/register/`                          | Register a new user    |
| GET    | `/api/activate/<uidb64>/<token>/`         | Activate account       |
| POST   | `/api/login/`                             | Login                  |
| POST   | `/api/logout/`                            | Logout                 |
| POST   | `/api/token/refresh/`                     | Refresh JWT token      |
| POST   | `/api/password_reset/`                    | Request password reset |
| GET    | `/api/password_confirm/<uidb64>/<token>/` | Confirm password reset |

### Video

| Method | Endpoint                                        | Description      |
| ------ | ----------------------------------------------- | ---------------- |
| GET    | `/api/video/`                                   | List all videos  |
| GET    | `/api/video/<movie_id>/<resolution>/index.m3u8` | HLS manifest     |
| GET    | `/api/video/<movie_id>/<resolution>/<segment>/` | HLS segment file |

## Prerequisites

- Docker & Docker Compose
- (For local development without Docker: Python 3.12, PostgreSQL, Redis, FFmpeg)

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/Simeon199/Videoflix.git
cd Videoflix
```

### 2. Configure environment variables

```bash
cp .env.template .env
```

Edit `.env` and set your values:

```env
SECRET_KEY=your-secret-key
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Backend domain (used in activation & password reset email links)
DOMAIN=http://127.0.0.1:8000

# Frontend (adjust port to match your local dev server, e.g. VS Code Live Server)
FRONTEND_DOMAIN=http://127.0.0.1:5500/

# Database
DB_NAME=videoflix_db
DB_USER=my_user
DB_PASSWORD=your-db-password
DB_HOST=db
DB_PORT=5432

# Redis
REDIS_HOST=redis
REDIS_LOCATION=redis://redis:6379/1
REDIS_PORT=6379
REDIS_DB=0

# Superuser
DJANGO_SUPERUSER_USERNAME=admin
DJANGO_SUPERUSER_PASSWORD=your-admin-password
DJANGO_SUPERUSER_EMAIL=admin@example.com

# Email (for account activation & password reset)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=noreply@videoflix.de
```

> **Note:** If your VS Code Live Server runs on a different port (e.g. 5501), update `FRONTEND_DOMAIN` accordingly (e.g. `http://127.0.0.1:5501/`).

### 3a. Start with Docker

> **No local Python or virtual environment required.** All dependencies are installed inside the Docker containers. Red import warnings in your IDE (e.g. VS Code) can be ignored — they do not affect the running application.

```bash
docker-compose up --build -d
```

This starts four services:

- **db** – PostgreSQL
- **redis** – Redis
- **web** – Django API on port 8000
- **rqworker** – Background task worker for video conversion

The entrypoint script automatically runs migrations and creates the superuser.

### 3b. Local development (without Docker)

```bash
python -m venv env
source env/bin/activate      # Linux/macOS
env\Scripts\activate          # Windows
pip install -r requirements.txt
```

Make sure PostgreSQL, Redis, and FFmpeg are running locally, then adjust `DB_HOST` and `REDIS_HOST` in your `.env` to `localhost`.

```bash
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

In a separate terminal (with the virtual environment activated):

```bash
python manage.py rqworker default
```

### 4. Access the application

- API: http://localhost:8000/api/
- Admin: http://localhost:8000/admin/

## Running Tests

```bash
pytest
```

Tests use an in-memory SQLite database and local memory cache, so no external services are required.

## Project Structure

```
Videoflix/
├── core/                  # Django project settings & configuration
├── auth_app/              # Authentication (registration, login, JWT, password reset)
│   ├── api/               # Views, serializers, token & cookie utilities
│   └── tests/             # Auth test suite
├── video_app/             # Video management & HLS streaming
│   ├── api/               # Views, serializers
│   ├── models.py          # Video model
│   ├── signals.py         # Post-save signal for HLS conversion
│   ├── tasks.py           # Background tasks (FFmpeg conversion, thumbnails)
│   └── tests/             # Video test suite
├── docker-compose.yml     # Docker services
├── backend.Dockerfile     # Python 3.12 Alpine + FFmpeg
├── requirements.txt       # Python dependencies
└── .env.template          # Environment variable template
```

## Video Processing Pipeline

1. A video is uploaded via the Django admin panel
2. A post-save signal triggers an RQ background job
3. FFmpeg converts the video to HLS format at three resolutions (480p, 720p, 1080p)
4. A thumbnail is generated from the video
5. The HLS segments and manifests are stored in the `media/` directory
6. Clients request the adaptive `.m3u8` manifest and stream `.ts` segments

## Contributing

Contributions are always welcome! If you have suggestions for improvements or want to propose changes, feel free to open an issue. Alternatively, consider forking the repository and submitting a pull request.

## License

This project is licensed under the MIT License — © 2026 Simon Kiesner.
