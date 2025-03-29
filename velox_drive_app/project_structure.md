# Velox Drive Project Structure

```
velox_drive_app/
├── cordova/                  # Cordova project folder
│   ├── config.xml           # Cordova configuration
│   ├── platforms/           # Platform-specific code
│   │   └── android/         # Android platform
│   ├── plugins/             # Cordova plugins
│   └── www/                 # Web assets (built React app)
│
├── frontend/                # React frontend
│   ├── public/              # Static assets
│   │   ├── index.html       # HTML entry point
│   │   ├── manifest.json    # PWA manifest
│   │   └── assets/          # Images, fonts, etc.
│   ├── src/                 # React source code
│   │   ├── components/      # Reusable components
│   │   ├── pages/           # Page components
│   │   ├── services/        # API services
│   │   ├── utils/           # Utility functions
│   │   ├── hooks/           # Custom React hooks
│   │   ├── context/         # React context providers
│   │   ├── animations/      # GSAP & Framer Motion animations
│   │   ├── styles/          # CSS/SCSS styles
│   │   ├── App.js           # Main App component
│   │   └── index.js         # React entry point
│   ├── package.json         # Frontend dependencies
│   └── webpack.config.js    # Webpack configuration
│
├── backend/                 # PHP backend
│   ├── api/                 # API endpoints
│   │   ├── auth/            # Authentication endpoints
│   │   ├── files/           # File management endpoints
│   │   ├── sharing/         # File sharing endpoints
│   │   ├── users/           # User management endpoints
│   │   └── admin/           # Admin dashboard endpoints
│   ├── config/              # Configuration files
│   │   ├── database.php     # Database configuration
│   │   └── security.php     # Security configuration
│   ├── models/              # Database models
│   ├── services/            # Business logic
│   │   ├── FileService.php  # File operations
│   │   ├── AuthService.php  # Authentication
│   │   ├── ShareService.php # Sharing functionality
│   │   └── AdminService.php # Admin functionality
│   ├── utils/               # Utility functions
│   │   ├── Encryption.php   # Encryption utilities
│   │   ├── Validation.php   # Input validation
│   │   └── Logger.php       # Logging functionality
│   └── uploads/             # File storage directory
│       ├── temp/            # Temporary uploads
│       └── user_files/      # User files (organized by user ID)
│
├── database/                # Database scripts
│   └── schema.sql           # Database schema
│
├── docs/                    # Documentation
│
├── .gitignore               # Git ignore file
├── package.json             # Project dependencies
└── README.md                # Project documentation
```

This structure organizes the Velox Drive app into three main sections:

1. **Cordova**: For building the Android app
2. **Frontend**: React.js application with components, services, and animations
3. **Backend**: PHP API with endpoints for authentication, file management, and security features

The database folder contains the MariaDB schema, and the docs folder holds project documentation.