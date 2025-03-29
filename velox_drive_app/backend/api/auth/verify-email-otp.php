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
if (!isset($data['email']) || !isset($data['otp'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Email and OTP code are required']);
    exit;
}

// Validate email format
if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Invalid email format']);
    exit;
}

// Validate OTP format (6 digits)
if (!preg_match('/^\d{6}$/', $data['otp'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Invalid OTP format. Please provide a 6-digit code.']);
    exit;
}

require_once __DIR__ . '/../../models/User.php';

try {
    // Add error handling for database connection issues
    try {
        $userModel = new User();
    } catch (Exception $dbError) {
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Database connection error. Please try again later.'
        ]);
        error_log('Database error in verify-email-otp.php: ' . $dbError->getMessage() . '\nTrace: ' . $dbError->getTraceAsString());
        exit;
    }
    
    try {
        // Start transaction for verification process
        $db = $userModel->getDb();
        $db->beginTransaction();
        
        $verified = $userModel->verifyEmailWithOtp($data['email'], $data['otp']);
        
        if ($verified) {
            // Commit transaction
            $db->commit();
            
            echo json_encode([
                'success' => true,
                'message' => 'Email verified successfully. You can now log in.'
            ]);
            // Log successful verification
            error_log("Email verified successfully for user: {$data['email']}");
        } else {
            // Rollback transaction
            $db->rollback();
            
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Email verification failed']);
            error_log("Email verification failed for user: {$data['email']}");
        }
    } catch (Exception $verifyError) {
        // Rollback transaction on error
        if (isset($db)) {
            $db->rollback();
        }
        
        // Determine appropriate status code based on error type
        $statusCode = 400; // Default to bad request
        
        // Check for specific error messages to provide appropriate status codes
        if (strpos($verifyError->getMessage(), 'expired') !== false) {
            $statusCode = 410; // Gone - resource is no longer available
        } elseif (strpos($verifyError->getMessage(), 'already verified') !== false) {
            $statusCode = 409; // Conflict - request conflicts with current state
        }
        
        http_response_code($statusCode);
        echo json_encode(['success' => false, 'error' => $verifyError->getMessage()]);
        error_log('Verification error in verify-email-otp.php: ' . $verifyError->getMessage() . '\nTrace: ' . $verifyError->getTraceAsString());
    }
} catch (Exception $e) {
    // Rollback transaction on unexpected error
    if (isset($db)) {
        $db->rollback();
    }
    
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'An error occurred. Please try again.'
    ]);
    error_log('Unexpected error in verify-email-otp.php: ' . $e->getMessage() . '\nTrace: ' . $e->getTraceAsString());
}