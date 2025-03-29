<?php
header('Content-Type: application/json');

// Allow CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

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

// Get token from query string
$token = $_GET['token'] ?? null;

if (!$token) {
    http_response_code(400);
    echo json_encode(['error' => 'Verification token is required']);
    exit;
}

require_once __DIR__ . '/../../models/User.php';

try {
    $userModel = new User();
    $verified = $userModel->verifyEmail($token);
    
    if ($verified) {
        echo json_encode([
            'success' => true,
            'message' => 'Email verified successfully. You can now log in.'
        ]);
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'Email verification failed']);
    }
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['error' => $e->getMessage()]);
}