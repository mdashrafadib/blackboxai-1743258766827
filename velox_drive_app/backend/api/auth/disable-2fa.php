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

try {
    $userModel = new User();
    
    // Verify the code and disable 2FA
    $result = $userModel->disableTwoFactor($data['user_id'], $data['code']);
    
    if ($result) {
        echo json_encode([
            'success' => true,
            'message' => 'Two-factor authentication has been disabled successfully.'
        ]);
    } else {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'Invalid verification code. Please try again.'
        ]);
    }
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['error' => $e->getMessage()]);
}