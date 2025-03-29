<?php
header('Content-Type: application/json');

// Allow CORS
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

require_once __DIR__ . '/../../models/User.php';
require_once __DIR__ . '/../../utils/JWTHelper.php';

// Get authorization header
$headers = getallheaders();
$authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : '';

// Check if token exists
if (!$authHeader || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$token = $matches[1];
$jwtHelper = new JWTHelper();

// Verify token
try {
    $payload = $jwtHelper->verifyToken($token);
    
    // Check if user is admin
    if (!isset($payload['isAdmin']) || $payload['isAdmin'] !== true) {
        http_response_code(403);
        echo json_encode(['error' => 'Forbidden: Admin access required']);
        exit;
    }
    
    $userModel = new User();
    
    // Handle different HTTP methods
    switch ($_SERVER['REQUEST_METHOD']) {
        case 'GET':
            // Get all users
            $users = $userModel->getAllUsers();
            echo json_encode(['users' => $users]);
            break;
            
        case 'POST':
            // Create a new user (admin functionality)
            $data = json_decode(file_get_contents('php://input'), true);
            $newUser = $userModel->createUser($data);
            echo json_encode(['success' => true, 'user' => $newUser]);
            break;
            
        case 'PUT':
            // Update user
            $data = json_decode(file_get_contents('php://input'), true);
            $userId = isset($_GET['id']) ? $_GET['id'] : null;
            
            if (!$userId) {
                http_response_code(400);
                echo json_encode(['error' => 'User ID is required']);
                exit;
            }
            
            $updatedUser = $userModel->updateUser($userId, $data);
            echo json_encode(['success' => true, 'user' => $updatedUser]);
            break;
            
        case 'DELETE':
            // Delete user
            $userId = isset($_GET['id']) ? $_GET['id'] : null;
            
            if (!$userId) {
                http_response_code(400);
                echo json_encode(['error' => 'User ID is required']);
                exit;
            }
            
            $userModel->deleteUser($userId);
            echo json_encode(['success' => true]);
            break;
            
        default:
            http_response_code(405);
            echo json_encode(['error' => 'Method not allowed']);
            break;
    }
} catch (Exception $e) {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid token: ' . $e->getMessage()]);
}