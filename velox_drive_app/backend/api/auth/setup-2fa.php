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
if (!isset($data['user_id'])) {
    http_response_code(400);
    echo json_encode(['error' => 'User ID is required']);
    exit;
}

require_once __DIR__ . '/../../models/User.php';

try {
    $userModel = new User();
    
    // Setup 2FA for the user
    $result = $userModel->setupTwoFactor($data['user_id']);
    
    // Return the secret and QR code URL
    echo json_encode([
        'success' => true,
        'secret' => $result['secret'],
        'qrCodeUrl' => $result['qrCodeUrl'],
        'message' => 'Two-factor authentication setup successful. Please scan the QR code with your authenticator app.'
    ]);
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['error' => $e->getMessage()]);
}