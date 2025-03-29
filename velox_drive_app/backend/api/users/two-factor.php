<?php
header('Content-Type: application/json');

// Allow CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

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

// Get request body
$json = file_get_contents('php://input');
$data = json_decode($json, true);

// Validate required fields
if (!isset($data['enable'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Enable parameter is required']);
    exit;
}

// Get user data
require_once __DIR__ . '/../../models/User.php';
require_once __DIR__ . '/../../utils/GoogleAuthenticator.php';

$userModel = new User();
$userId = $payload['user_id'];
$user = $userModel->findById($userId);

if (!$user) {
    http_response_code(401);
    echo json_encode(['error' => 'User not found']);
    exit;
}

try {
    if ($data['enable']) {
        // Enable 2FA
        $secret = $userModel->setupTwoFactor($userId);
        
        // Generate QR code URL
        $ga = new GoogleAuthenticator();
        $appName = $securityConfig['two_factor']['issuer'];
        $qrCodeUrl = $ga->getQRCodeUrl($appName . ':' . $user['email'], $secret, $appName);
        
        echo json_encode([
            'success' => true,
            'message' => 'Two-factor authentication setup initiated',
            'secret' => $secret,
            'qrCodeUrl' => $qrCodeUrl
        ]);
    } else {
        // Disable 2FA
        // Note: In a real implementation, you should require the user to verify their 2FA code before disabling
        // For simplicity, we're allowing direct disable here
        $userModel->updateUser($userId, ['two_factor_enabled' => 0, 'two_factor_secret' => null]);
        
        echo json_encode([
            'success' => true,
            'message' => 'Two-factor authentication disabled'
        ]);
    }
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['error' => $e->getMessage()]);
}