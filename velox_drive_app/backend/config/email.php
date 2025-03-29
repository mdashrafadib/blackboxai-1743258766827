<?php
/**
 * Email Configuration
 */

return [
    // Sender information
    'from_email' => 'no-reply@veloxsoft.in',
    'from_name' => 'Velox Drive',
    'reply_to' => 'support@veloxsoft.in',
    
    // SMTP configuration
    'smtp' => [
        'host' => 'smtp.veloxsoft.in',
        'auth' => true,
        'username' => 'no-reply@veloxsoft.in',
        'password' => 'P2WxTmNJ23@@',
        'encryption' => 'ssl',
        'port' => 465,
        'smtp_options' => [
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true,
                'verify_depth' => 3,
                'ciphers' => 'DEFAULT@SECLEVEL=1'
            ]
        ],
        'timeout' => 30,
        'debug' => true
    ],
    
    // Email templates
    'templates' => [
        'verification' => [
            'subject' => 'Verify Your Velox Drive Account',
            'body' => "Hello,\n\nThank you for registering with Velox Drive. Please click the link below to verify your email address:\n\n{verification_link}\n\nThis link will expire in 24 hours.\n\nIf you did not create an account, please ignore this email.\n\nRegards,\nThe Velox Drive Team"
        ],
        'otp_verification' => [
            'subject' => 'Your Velox Drive Verification Code',
            'body' => "Hello,\n\nThank you for registering with Velox Drive. Please use the following verification code to verify your email address:\n\n{otp_code}\n\nThis code will expire in 10 minutes.\n\nIf you did not create an account, please ignore this email.\n\nRegards,\nThe Velox Drive Team"
        ],
        'password_reset' => [
            'subject' => 'Reset Your Velox Drive Password',
            'body' => "Hello,\n\nYou have requested to reset your password. Please click the link below to set a new password:\n\n{reset_link}\n\nThis link will expire in 1 hour.\n\nIf you did not request a password reset, please ignore this email.\n\nRegards,\nThe Velox Drive Team"
        ]
    ]
];