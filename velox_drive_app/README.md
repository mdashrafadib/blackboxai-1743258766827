# Velox Drive

A secure file-sharing drive Android app built with Cordova, React.js, and PHP backend.

## Features

### File Management
- Upload & Download with drag & drop and real-time progress
- Multi-file upload with compression
- Resumable uploads for interrupted connections
- File preview support for various formats (PDF, DOCX, MP4, PNG, ZIP, etc.)
- AI-based smart search & auto-categorization
- File version control
- Organized folder structure with sorting and filtering
- Favorites and recent activity tracking
- Trash/Recycle bin with auto-delete

### Secure File Sharing & Collaboration
- Share via links with expiry dates
- Role-based access control (Viewer, Editor, Owner)
- Real-time collaboration and file synchronization
- In-app chat for team discussions
- Guest access with temporary permissions
- Custom watermarking for sensitive files
- Auto-expiration for shared files

### Security & Privacy
- Two-Factor Authentication (2FA)
- OAuth Login integration
- IP-based access restrictions
- AES-256 Encryption for storage
- End-to-End Encryption for transfers
- Hashed password storage with bcrypt
- CAPTCHA & rate-limiting
- Auto-logout after inactivity
- Real-time monitoring of activities
- Admin security audit dashboard

### User Experience
- Dark/Light mode toggle
- Animated UI using Framer Motion & GSAP
- Progressive Web App support
- Multi-language support
- Push notifications

## Tech Stack

### Frontend
- Cordova (Android compatibility)
- HTML, CSS, JavaScript
- React.js
- jQuery
- AJAX
- Framer Motion & GSAP (animations)

### Backend
- PHP
- MariaDB

## Setup Instructions

1. Install prerequisites:
   - Node.js and npm
   - Cordova CLI
   - XAMPP (for PHP and MariaDB)

2. Clone the repository

3. Install dependencies:
   ```
   npm install
   ```

4. Configure the database:
   - Create a MariaDB database named 'velox_drive'
   - Import the database schema from `database/schema.sql`

5. Start the development server:
   ```
   npm start
   ```

6. Build for Android:
   ```
   cordova platform add android
   cordova build android
   ```

## License

MIT