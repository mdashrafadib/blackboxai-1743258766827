<?php
header('Content-Type: application/json');

// Allow CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

// Get request body
$json = file_get_contents('php://input');
$data = json_decode($json, true);

// Check for invalid JSON
if ($data === null && json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Invalid JSON format: ' . json_last_error_msg()]);
    exit;
}

// Validate required fields
if (!isset($data['email'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Email is required']);
    exit;
}

// Validate email format
if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Invalid email format']);
    exit;
}

require_once __DIR__ . '/../../models/User.php';
require_once __DIR__ . '/../../utils/EmailSender.php';

// Rate limiting code has been removed to allow unlimited OTP requests during testing
// This will make development and testing easier

try {
    // Generate a new OTP for email verification
    $userModel = new User();
    
    // Add error handling for database connection issues
    try {
        $user = $userModel->findByEmail($data['email']);
    } catch (Exception $dbError) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Database connection error. Please try again later.'
        ]);
        error_log('Database error in resend-otp.php: ' . $dbError->getMessage());
        exit;
    }
    
    // If no user exists, we'll create a temporary verification record
    if (!$user) {
        // Generate a temporary OTP for this email
        try {
            $otpCode = $userModel->generateTemporaryOtp($data['email']);
            
            if ($otpCode) {
                // Send the OTP email
                try {
                    $emailSender = new EmailSender();
                    $result = $emailSender->sendOtpVerificationEmailAsync($data['email'], '', $otpCode);
                    
                    if (!$result) {
                        http_response_code(500);
                        echo json_encode([
                            'success' => false,
                            'error' => 'Failed to send verification code. Please try again later.'
                        ]);
                        error_log('Failed to send OTP email to: ' . $data['email']);
                        exit;
                    }
                } catch (Exception $emailInitError) {
                    http_response_code(500);
                    echo json_encode([
                        'success' => false,
                        'error' => 'Email service unavailable. Please try again later.'
                    ]);
                    error_log('EmailSender initialization error for temporary OTP: ' . $emailInitError->getMessage() . '\nTrace: ' . $emailInitError->getTraceAsString());
                    exit;
                }
            } else {
                // Failed to generate OTP
                http_response_code(500);
                echo json_encode([
                    'success' => false,
                    'error' => 'Failed to generate verification code. Please try again.'
                ]);
                exit;
            }
        } catch (Exception $otpError) {
            // Check for specific error messages
            if (strpos($otpError->getMessage(), 'wait before requesting') !== false) {
                http_response_code(429); // Too Many Requests
            } else {
                http_response_code(500);
            }
            
            echo json_encode([
                'success' => false,
                'error' => $otpError->getMessage()
            ]);
            error_log('OTP generation error: ' . $otpError->getMessage() . '\nTrace: ' . $otpError->getTraceAsString());
            exit;
        }
            
        echo json_encode([
            'success' => true,
            'message' => 'Verification code sent to your email'
        ]);
        exit;
    }
    
    // For existing users, check if already verified
    if ($user['is_verified'] == 1) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'Email is already verified. Please login.'
        ]);
        exit;
    }
    
    // Generate new OTP
    try {
        $otpCode = $userModel->generateNewOtp($data['email']);
        
        if (!$otpCode) {
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => 'Failed to generate verification code. Please try again.'
            ]);
            exit;
        }
    } catch (Exception $otpError) {
        // Check for specific error messages
        if (strpos($otpError->getMessage(), 'wait before requesting') !== false) {
            http_response_code(429); // Too Many Requests
        } else {
            http_response_code(500);
        }
        
        echo json_encode([
            'success' => false,
            'error' => $otpError->getMessage()
        ]);
        error_log('OTP generation error in generateNewOtp: ' . $otpError->getMessage() . '\nTrace: ' . $otpError->getTraceAsString());
        exit;
    }
    
    // Initialize email sender
    try {
        $emailSender = new EmailSender();
    } catch (Exception $initError) {
        http_response_code(500);
        $errorDetails = [
            'message' => $initError->getMessage(),
            'smtp_config' => $emailSender->getConfig()['smtp'] ?? null,
            'trace' => $initError->getTraceAsString()
        ];
        
        error_log('EmailSender Error: ' . print_r($errorDetails, true));
        
        echo json_encode([
            'success' => false,
            'error' => 'Email service unavailable',
            'error_detail' => 'Check server logs for SMTP connection details',
            'error_code' => 'SMTP_CONNECTION_FAILED'
        ]);
        exit;
    }
    
    // Use the asynchronous email sending method with built-in retry logic
    try {
        // This method has built-in retry mechanism and better error handling
        $result = $emailSender->sendOtpVerificationEmailAsync($data['email'], $user['full_name'], $otpCode);
        
        if (!$result) {
            http_response_code(500);
            echo json_encode([
                'success' => false,
                'error' => 'Failed to send verification code. Please try again later.'
            ]);
            error_log('Failed to send OTP email to: ' . $data['email']);
            exit;
        }
        
        // If we get here, the email sending process was started successfully
        echo json_encode([
            'success' => true,
            'message' => 'Verification code sent to your email. Please check your inbox.'
        ]);
        
        // Log success
        error_log("OTP sending process started successfully for {$data['email']}");
    } catch (Exception $emailError) {
        // Email sending failed
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Failed to send verification code. Please try again later.'
        ]);
        
        // Log detailed error
        error_log("Failed to send OTP email to {$data['email']}: " . $emailError->getMessage());
        exit;
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'An unexpected error occurred. Please try again.'
    ]);
    error_log('Unexpected error in resend-otp.php: ' . $e->getMessage() . '\nTrace: ' . $e->getTraceAsString());
    exit;
}
?>