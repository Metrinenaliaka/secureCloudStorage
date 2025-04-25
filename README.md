# Secure Cloud Storage

Secure Cloud Storage is a Django-based web application that allows users to securely upload, download, share, and manage files with end-to-end encryption (E2EE). The platform also supports Multi-Factor Authentication (MFA) for enhanced account security.

## Prerequisites

Before setting up the project, ensure you have the following installed on your system:

- Python 3.10 or higher
- pip (Python package manager)
- Virtualenv (optional but recommended)
- SQLite (default database)
- AWS account with S3 bucket (for file storage)

## Technologies Used

- **Backend Framework**: Django 5.2
- **Database**: SQLite (default, can be replaced with other databases)
- **Cloud Storage**: AWS S3
- **Authentication**: Django OTP for MFA
- **Encryption**: Cryptography library for E2EE
- **Frontend**: Bootstrap 5.3 for styling

## Getting Started

Follow these steps to set up the project locally:

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/secureCloudStorage.git
cd secureCloudStorage

```

### 2. Set Up a Virtual Environment

It is recommended to use a virtual environment to manage dependencies.

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

Install the required Python packages using `requirements.txt`.

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file in the root directory and add the following environment variables:

```env
DEBUG=True
SECRET_KEY=your-secret-key
AWS_ACCESS_KEY_ID=your-aws-access-key-id
AWS_SECRET_ACCESS_KEY=your-aws-secret-access-key
AWS_STORAGE_BUCKET_NAME=your-s3-bucket-name
AWS_REGION=your-aws-region
```

Replace the placeholder values with your actual credentials.

### 5. Apply Migrations

Run the following commands to set up the database:

```bash
python3 manage.py makemigrations
python3 manage.py migrate
```

### 6. Create a Superuser

Create an admin account to access the Django admin panel:

```bash
python3 manage.py createsuperuser
```

### 7. Run the Development Server

Start the Django development server:

```bash
python3 manage.py runserver
```

Access the application at `http://127.0.0.1:8000`.

## Features

- **Secure File Upload**: Files are encrypted before being uploaded to AWS S3.
- **Multi-Factor Authentication (MFA)**: Adds an extra layer of security to user accounts.
- **File Sharing**: Share files with other users with specific permissions (view, download, edit).
- **Trash Management**: Soft delete files and restore them from the trash.
- **Audit Logs**: Tracks user actions like uploads, downloads, and deletions.

## Folder Structure

```
secureCloudStorage/
├── securecloud/          # Core project settings and configurations
├── storage/              # Main app for file management
│   ├── migrations/       # Database migrations
│   ├── templates/        # HTML templates
│   ├── static/           # Static files (CSS, JS, images)
│   ├── views.py          # Application views
│   ├── models.py         # Database models
│   ├── forms.py          # Django forms
│   ├── urls.py           # URL routing
│   └── utils.py          # Utility functions
├── manage.py             # Django management script
├── requirements.txt      # Python dependencies
└── .env                  # Environment variables (not included in version control)
```

## Deployment

To deploy the application, follow these steps:

1. Set `DEBUG=False` in the `.env` file.
2. Configure a production-ready database (e.g., PostgreSQL).
3. Set up a web server (e.g., Gunicorn) and reverse proxy (e.g., Nginx).
4. Use AWS S3 for static and media file storage.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch: `git checkout -b feature-name`.
3. Make your changes and commit them: `git commit -m 'Add feature'`.
4. Push to the branch: `git push origin feature-name`.
5. Submit a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Acknowledgments

- [Django Documentation](https://docs.djangoproject.com/)
- [Bootstrap](https://getbootstrap.com/)
- [AWS S3](https://aws.amazon.com/s3/)
- [Cryptography Library](https://cryptography.io/)



## Authors

- [Sriharsha Mandaloju](https://github.com/placeholder-link)
- [Shiva Sai Gnanesh Namani](https://github.com/placeholder-link)

---
```
