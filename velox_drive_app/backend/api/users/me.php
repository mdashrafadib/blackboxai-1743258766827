<?php
header('Content-Type: application/json');

// Allow CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Only allow GET requests
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

// Check for Authorization header
$headers = getallheaders();
$authHeader = $headers['Authorization'] ?? '';

if (!$authHeader || !preg_match('/Bearer\s+(\S+)/', $authHeader, $matches)) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$token = $matches[1];

// Validate JWT token
require_once __DIR__ . '/../../config/security.php';
$securityConfig = require __DIR__ . '/../../config/security.php';
$jwtSecret = $securityConfig['jwt']['secret'];

// Parse token
$tokenParts = explode('.', $token);
if (count($tokenParts) !== 3) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid token format']);
    exit;
}

[$header, $payload, $signature] = $tokenParts;

// Verify signature
$validSignature = hash_hmac('sha256', "$header.$payload", $jwtSecret, true);
$validSignature = base64_encode($validSignature);

if ($signature !== $validSignature) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid token signature']);
    exit;
}

// Decode payload
$payload = json_decode(base64_decode($payload), true);

// Check if token is expired
if (!isset($payload['exp']) || $payload['exp'] < time()) {
    http_response_code(401);
    echo json_encode(['error' => 'Token expired']);
    exit;
}

// Get user data
require_once __DIR__ . '/../../models/User.php';
$userModel = new User();
$user = $userModel->findById($payload['user_id']);

if (!$user) {
    http_response_code(401);
    echo json_encode(['error' => 'User not found']);
    exit;
}

// Return user data
echo json_encode([
    'user' => [
        'id' => $user['id'],
        'username' => $user['username'],
        'email' => $user['email'],
        'fullName' => $user['full_name'],
        'profilePicture' => $user['profile_picture'],
        'twoFactorEnabled' => (bool)$user['two_factor_enabled'],
        'isAdmin' => (bool)$user['is_admin']
    ]
]);