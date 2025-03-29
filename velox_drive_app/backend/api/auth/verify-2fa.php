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
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// Get request body
$json = file_get_contents('php://input');
$data = json_decode($json, true);

// Validate required fields
if (!isset($data['user_id']) || !isset($data['code'])) {
    http_response_code(400);
    echo json_encode(['error' => 'User ID and verification code are required']);
    exit;
}

require_once __DIR__ . '/../../models/User.php';
require_once __DIR__ . '/../../config/security.php';

try {
    $userModel = new User();
    
    // Verify the 2FA code
    $isValid = $userModel->verifyTwoFactor($data['user_id'], $data['code']);
    
    if (!$isValid) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid verification code']);
        exit;
    }
    
    // Get user data
    $user = $userModel->findById($data['user_id']);
    
    if (!$user) {
        http_response_code(400);
        echo json_encode(['error' => 'User not found']);
        exit;
    }
    
    // Generate JWT token
    $securityConfig = require __DIR__ . '/../../config/security.php';
    $jwtSecret = $securityConfig['jwt']['secret'];
    $issuedAt = time();
    $expiresAt = $issuedAt + $securityConfig['jwt']['expiration'];
    
    $payload = [
        'iat' => $issuedAt,
        'exp' => $expiresAt,
        'user_id' => $user['id'],
        'is_admin' => (bool)$user['is_admin']
    ];
    
    // Create JWT token
    $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
    $header = base64_encode($header);
    $payload = json_encode($payload);
    $payload = base64_encode($payload);
    $signature = hash_hmac('sha256', "$header.$payload", $jwtSecret, true);
    $signature = base64_encode($signature);
    $token = "$header.$payload.$signature";
    
    // Return user data and token
    echo json_encode([
        'success' => true,
        'user' => [
            'id' => $user['id'],
            'username' => $user['username'],
            'email' => $user['email'],
            'fullName' => $user['full_name'],
            'profilePicture' => $user['profile_picture'],
            'twoFactorEnabled' => (bool)$user['two_factor_enabled'],
            'isAdmin' => (bool)$user['is_admin']
        ],
        'token' => $token
    ]);
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['error' => $e->getMessage()]);
}