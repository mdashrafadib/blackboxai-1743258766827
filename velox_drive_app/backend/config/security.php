<?php
/**
 * Security Configuration
 */

return [
    // Encryption settings
    'encryption' => [
        'method' => 'aes-256-cbc',
        'key' => getenv('ENCRYPTION_KEY') ?: 'your-secret-key-must-be-changed-in-production',
    ],
    
    // JWT settings for API authentication
    'jwt' => [
        'secret' => getenv('JWT_SECRET') ?: 'your-jwt-secret-key-must-be-changed-in-production',
        'expiration' => 3600, // 1 hour
        'refresh_expiration' => 2592000, // 30 days
    ],
    
    // Password hashing
    'password' => [
        'algorithm' => PASSWORD_BCRYPT,
        'options' => [
            'cost' => 12,
        ],
    ],
    
    // CORS settings
    'cors' => [
        'allowed_origins' => ['*'], // Change in production
        'allowed_methods' => ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        'allowed_headers' => ['Content-Type', 'Authorization', 'X-Requested-With'],
    ],
    
    // Rate limiting
    'rate_limit' => [
        'enabled' => true,
        'max_requests' => 100, // Max requests per window
        'window' => 60, // Window in seconds
    ],
    
    // 2FA settings
    'two_factor' => [
        'issuer' => 'Velox Drive',
        'digits' => 6,
        'period' => 30,
        'algorithm' => 'sha1',
    ],
];
