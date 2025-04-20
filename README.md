# Flask Blog

A feature-rich blogging platform built with Flask, offering a modern and responsive design with comprehensive functionality for both users and administrators.

## Features

### User Features
- 🔐 User Authentication (Register, Login, Logout)
- 👤 User Profiles with customizable avatars
- ✍️ Create, Edit, and Delete Posts
- 💬 Comment System with nested replies
- ❤️ Like/Unlike Posts
- 🏷️ Categories and Tags
- 🔍 Search Functionality
- 📧 Newsletter Subscription
- 👥 Follow/Unfollow Users

### Admin Features
- 📊 Admin Dashboard with statistics
- 📝 Post Management
- 👥 User Management
- 💬 Comment Moderation
- 🏷️ Category and Tag Management
- 📧 Newsletter Subscriber Management

### Technical Features
- 🔒 Secure Password Hashing
- 📁 File Upload Support
- 🎨 Responsive Design
- 📱 Mobile-Friendly Interface
- 🔍 SEO-Friendly URLs
- 📊 View Count Tracking

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd Flask_Blog
```

2. Create a virtual environment and activate it:
```bash
# Windows
pipenv shell

```

3. Install dependencies:
```bash
pipenv install Pipfile
# or using pipenv
pipenv install
```

4. Set up environment variables:
```bash
# Windows
set SECRET_KEY=your-secret-key

# Linux/MacOS
export SECRET_KEY=your-secret-key
```

5. Initialize the database:
```bash
python
>>> from flaskblog import db
>>> db.create_all()
>>> exit()
```

6. Run the application:
```bash
python flaskblog.py
```

The application will be available at `http://127.0.0.1:5000`

## Project Structure
```
Flask_Blog/
├── static/
│   ├── css/
│   ├── post_pics/
│   ├── profile_pics/
│   └── main.css
├── templates/
│   ├── admin/
│   │   └── dashboard.html
│   ├── layout.html
│   ├── home.html
│   ├── post.html
│   └── ...
├── instance/
│   └── site.db
├── flaskblog.py
├── Pipfile
├── Pipfile.lock
└── README.md
```

## Dependencies
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-WTF
- Pillow
- email-validator
- Flask-Admin

## Database Schema
- Users
- Posts
- Comments
- Categories
- Tags
- Likes
- Newsletter Subscribers
- Notifications

## Contributing
1. Fork the repository
2. Create a new branch
3. Make your changes
4. Submit a pull request

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments
- Flask Documentation
- Bootstrap
- Font Awesome
- SQLAlchemy Documentation 