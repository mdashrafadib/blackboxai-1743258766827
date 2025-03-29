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
if (!isset($data['email']) || !isset($data['password'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Email and password are required']);
    exit;
}

require_once __DIR__ . '/../../models/User.php';
require_once __DIR__ . '/../../config/security.php';

try {
    $userModel = new User();
    $user = $userModel->login($data['email'], $data['password']);
    
    // Check if 2FA is enabled for this user
    if ($user['twoFactorEnabled']) {
        // If 2FA is enabled, return only the user ID and require 2FA verification
        echo json_encode([
            'requireTwoFactor' => true,
            'user_id' => $user['id']
        ]);
    } else {
        // If 2FA is not enabled, generate JWT token and return user data
        $securityConfig = require __DIR__ . '/../../config/security.php';
        $jwtSecret = $securityConfig['jwt']['secret'];
        $issuedAt = time();
        $expiresAt = $issuedAt + $securityConfig['jwt']['expiration'];
        
        $payload = [
            'iat' => $issuedAt,
            'exp' => $expiresAt,
            'user_id' => $user['id'],
            'is_admin' => (bool)$user['isAdmin']
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
            'user' => $user,
            'token' => $token
        ]);
    }
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['error' => $e->getMessage()]);
}