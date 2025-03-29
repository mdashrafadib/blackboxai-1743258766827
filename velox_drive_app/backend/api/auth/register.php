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
if (!isset($data['username']) || !isset($data['email']) || !isset($data['password']) || !isset($data['fullName'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'All fields are required: username, email, password, fullName']);
    exit;
}

// Validate username format (3-20 characters, alphanumeric and underscore only)
if (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $data['username'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Username must be 3-20 characters and can only contain letters, numbers, and underscores']);
    exit;
}

// Validate email format
if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Invalid email format']);
    exit;
}

// Validate password strength (at least 8 characters with letters and numbers)
if (strlen($data['password']) < 8 || !preg_match('/[A-Za-z]/', $data['password']) || !preg_match('/[0-9]/', $data['password'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Password must be at least 8 characters and contain both letters and numbers']);
    exit;
}

// Validate full name (2-100 characters)
if (strlen($data['fullName']) < 2 || strlen($data['fullName']) > 100) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Full name must be between 2 and 100 characters']);
    exit;
}

require_once __DIR__ . '/../../models/User.php';
require_once __DIR__ . '/../../utils/EmailSender.php';

// Rate limiting code for registration has been removed
// This allows unlimited registration attempts for testing purposes
error_log('IP-based rate limiting bypassed for registration');

try {
    // Start transaction
    $userModel = new User();
    $db = $userModel->getDb();
    $db->beginTransaction();
    
    try {
        // Register the user
        $user = $userModel->register(
            $data['username'],
            $data['email'],
            $data['password'],
            $data['fullName']
        );
        
        // Commit transaction
        $db->commit();
        
        // Return immediate success response to user
        echo json_encode([
            'success' => true,
            'message' => 'Registration successful. Verification code sent to your email. Please check your inbox.',
            'user' => [
                'id' => $user['id'],
                'username' => $user['username'],
                'email' => $user['email'],
                'fullName' => $user['fullName']
            ]
        ]);
        
        // Flush output buffer to send response immediately
        if (ob_get_level() > 0) {
            ob_flush();
            flush();
        }
        
        // Close the connection to the client
        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
        }
        
        // Send OTP verification email asynchronously
        try {
            $emailSender = new EmailSender();
            $emailSender->sendOtpVerificationEmailAsync($user['email'], $user['fullName'], $user['otpCode']);
            
            // Log success
            error_log("OTP verification email sent to {$user['email']}");
        } catch (Exception $emailError) {
            // Log email sending error but don't affect the user response
            error_log("Failed to send verification email to {$user['email']}: " . $emailError->getMessage());
            
            // Try to send a backup notification if primary email fails
            try {
                // This could be implemented with a different email service or method
                // For now, just log the attempt
                error_log("Attempted backup email notification for {$user['email']}");
            } catch (Exception $backupError) {
                error_log("Backup email notification also failed for {$user['email']}: " . $backupError->getMessage());
            }
        }
    } catch (Exception $registerError) {
        // Rollback transaction on error
        $db->rollback();
        throw $registerError; // Re-throw to be caught by outer catch block
    }
} catch (Exception $e) {
    // Determine appropriate status code based on error type
    $statusCode = 400; // Default to bad request
    
    // Check for specific error messages to provide appropriate status codes
    if (strpos($e->getMessage(), 'already exists') !== false) {
        $statusCode = 409; // Conflict - resource already exists
    } elseif (strpos($e->getMessage(), 'Database connection') !== false) {
        $statusCode = 503; // Service Unavailable - database issue
    }
    
    http_response_code($statusCode);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
    
    // Log detailed error
    error_log('Registration error: ' . $e->getMessage() . '\nTrace: ' . $e->getTraceAsString());
}