# Secure Login System

A secure web-based login system built with Flask, featuring user authentication, password reset functionality, and protection against common web vulnerabilities.

## Features

- User registration and authentication
- Secure password hashing using bcrypt
- Password reset functionality
- Protection against SQL injection and XSS attacks
- Input validation and sanitization
- Modern, responsive UI
- Session management
- Flash messages for user feedback

## Security Features

- Password hashing with bcrypt
- CSRF protection with Flask-WTF
- Secure session management
- Input validation and sanitization
- SQL injection prevention with SQLAlchemy
- XSS protection with Jinja2 template escaping
- Secure password reset system

## Installation

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
- Copy `.env.example` to `.env`
- Update the `SECRET_KEY` in `.env`

4. Initialize the database:
```bash
python
>>> from app import app, db
>>> with app.app_context():
...     db.create_all()
```

5. Run the application:
```bash
python app.py
```

## Usage

1. Register a new account at `/register`
2. Login at `/login`
3. Access your dashboard at `/dashboard`
4. Reset password using the "Forgot Password" link

## Security Considerations

- The `SECRET_KEY` in `.env` should be changed in production
- Enable HTTPS in production
- Implement rate limiting for login attempts
- Consider adding 2FA for additional security
- Regularly update dependencies
- Monitor for security vulnerabilities

## File Structure

```
secure_login/
├── app.py              # Main application file
├── requirements.txt    # Python dependencies
├── .env               # Environment variables
├── static/
│   └── css/
│       └── style.css  # Custom styles
└── templates/
    ├── base.html
    ├── home.html
    ├── login.html
    ├── register.html
    ├── dashboard.html
    ├── reset_password.html
    └── reset_password_request.html
```
