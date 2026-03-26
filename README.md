# Videoflix

A video streaming backend built with Django REST Framework. It provides user authentication, video upload with automatic HLS conversion, and adaptive bitrate streaming at multiple resolutions.

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
git clone <repository-url>
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

### 3. Start with Docker

```bash
docker-compose up --build
```

This starts four services:

- **db** – PostgreSQL
- **redis** – Redis
- **web** – Django API on port 8000
- **rqworker** – Background task worker for video conversion

The entrypoint script automatically runs migrations and creates the superuser.

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
