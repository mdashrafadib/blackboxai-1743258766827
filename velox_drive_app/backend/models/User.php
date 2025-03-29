<?php

require_once __DIR__ . '/Database.php';

class User {
    private $db;
    
    public function __construct() {
        $this->db = new Database();
    }
    
    /**
     * Get the database instance for transaction support
     * 
     * @return Database The database instance
     */
    public function getDb() {
        return $this->db;
    }
    
    /**
     * Setup two-factor authentication for a user
     * 
     * @param int $userId User ID
     * @return array Secret key and QR code URL
     * @throws Exception If setup fails
     */
    public function setupTwoFactor($userId) {
        try {
            // Validate user ID
            if (empty($userId) || !is_numeric($userId)) {
                throw new Exception('Invalid user ID');
            }
            
            // Check if user exists
            $user = $this->findById($userId);
            if (!$user) {
                throw new Exception('User not found');
            }
            
            // Check if user is verified
            if (!$user['is_verified']) {
                throw new Exception('Email must be verified before setting up 2FA');
            }
            
            // Create Google Authenticator instance
            require_once __DIR__ . '/../utils/GoogleAuthenticator.php';
            $ga = new GoogleAuthenticator();
            
            // Generate a new secret key
            $secret = $ga->createSecret();
            
            // Get security config
            $securityConfig = require __DIR__ . '/../config/security.php';
            
            // Generate QR code URL
            $qrCodeUrl = $ga->getQRCodeUrl(
                $user['email'],
                $secret,
                $securityConfig['two_factor']['issuer'] . ': ' . $user['username']
            );
            
            // Store the secret in the database (but don't enable 2FA yet)
            $this->db->update('users', [
                'two_factor_secret' => $secret,
                'updated_at' => date('Y-m-d H:i:s')
            ], 'id = ?', [$userId]);
            
            return [
                'secret' => $secret,
                'qrCodeUrl' => $qrCodeUrl
            ];
        } catch (Exception $e) {
            error_log('2FA setup error: ' . $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Enable two-factor authentication for a user after verifying the code
     * 
     * @param int $userId User ID
     * @param string $code Verification code
     * @return bool True if 2FA was enabled successfully
     * @throws Exception If enabling fails
     */
    public function enableTwoFactor($userId, $code) {
        try {
            // Validate inputs
            if (empty($userId) || !is_numeric($userId)) {
                throw new Exception('Invalid user ID');
            }
            
            if (empty($code) || !preg_match('/^\d{6}$/', $code)) {
                throw new Exception('Invalid verification code. Please provide a 6-digit code.');
            }
            
            // Check if user exists
            $user = $this->findById($userId);
            if (!$user) {
                throw new Exception('User not found');
            }
            
            // Check if user has a secret key
            if (empty($user['two_factor_secret'])) {
                throw new Exception('Two-factor authentication has not been set up yet');
            }
            
            // Verify the code
            require_once __DIR__ . '/../utils/GoogleAuthenticator.php';
            $ga = new GoogleAuthenticator();
            
            if (!$ga->verifyCode($user['two_factor_secret'], $code)) {
                return false;
            }
            
            // Enable 2FA for the user
            $this->db->update('users', [
                'two_factor_enabled' => 1,
                'updated_at' => date('Y-m-d H:i:s')
            ], 'id = ?', [$userId]);
            
            return true;
        } catch (Exception $e) {
            error_log('2FA enable error: ' . $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Verify a two-factor authentication code
     * 
     * @param int $userId User ID
     * @param string $code Verification code
     * @return bool True if code is valid
     * @throws Exception If verification fails
     */
    public function verifyTwoFactor($userId, $code) {
        try {
            // Validate inputs
            if (empty($userId) || !is_numeric($userId)) {
                throw new Exception('Invalid user ID');
            }
            
            if (empty($code) || !preg_match('/^\d{6}$/', $code)) {
                throw new Exception('Invalid verification code. Please provide a 6-digit code.');
            }
            
            // Check if user exists
            $user = $this->findById($userId);
            if (!$user) {
                throw new Exception('User not found');
            }
            
            // Check if 2FA is enabled and secret exists
            if (!$user['two_factor_enabled'] || empty($user['two_factor_secret'])) {
                throw new Exception('Two-factor authentication is not enabled for this user');
            }
            
            // Verify the code
            require_once __DIR__ . '/../utils/GoogleAuthenticator.php';
            $ga = new GoogleAuthenticator();
            
            return $ga->verifyCode($user['two_factor_secret'], $code);
        } catch (Exception $e) {
            error_log('2FA verification error: ' . $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Disable two-factor authentication for a user after verifying the code
     * 
     * @param int $userId User ID
     * @param string $code Verification code
     * @return bool True if 2FA was disabled successfully
     * @throws Exception If disabling fails
     */
    public function disableTwoFactor($userId, $code) {
        try {
            // Validate inputs
            if (empty($userId) || !is_numeric($userId)) {
                throw new Exception('Invalid user ID');
            }
            
            if (empty($code) || !preg_match('/^\d{6}$/', $code)) {
                throw new Exception('Invalid verification code. Please provide a 6-digit code.');
            }
            
            // Check if user exists
            $user = $this->findById($userId);
            if (!$user) {
                throw new Exception('User not found');
            }
            
            // Check if 2FA is enabled
            if (!$user['two_factor_enabled']) {
                throw new Exception('Two-factor authentication is not enabled for this user');
            }
            
            // Verify the code
            if (!$this->verifyTwoFactor($userId, $code)) {
                return false;
            }
            
            // Disable 2FA for the user
            $this->db->update('users', [
                'two_factor_enabled' => 0,
                'two_factor_secret' => null,
                'updated_at' => date('Y-m-d H:i:s')
            ], 'id = ?', [$userId]);
            
            return true;
        } catch (Exception $e) {
            error_log('2FA disable error: ' . $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Register a new user
     * 
     * @param string $username Username
     * @param string $email User email
     * @param string $password User password
     * @param string $fullName User's full name
     * @return array User data including OTP code
     * @throws Exception If registration fails for any reason
     */
    public function register($username, $email, $password, $fullName) {
        try {
            // Validate inputs
            if (empty($username) || !preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
                throw new Exception('Username must be 3-20 characters and can only contain letters, numbers, and underscores');
            }
            
            if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                throw new Exception('Invalid email format');
            }
            
            if (empty($password) || strlen($password) < 8 || !preg_match('/[A-Za-z]/', $password) || !preg_match('/[0-9]/', $password)) {
                throw new Exception('Password must be at least 8 characters and contain both letters and numbers');
            }
            
            if (empty($fullName) || strlen($fullName) < 2 || strlen($fullName) > 100) {
                throw new Exception('Full name must be between 2 and 100 characters');
            }
            
            // Check if username or email already exists
            $user = $this->findByUsernameOrEmail($username, $email);
            if ($user) {
                if ($user['username'] === $username) {
                    throw new Exception('Username already exists');
                }
                if ($user['email'] === $email) {
                    // Check if it's a temporary record
                    if ($user['username'] === null) {
                        // Delete the temporary record as we're creating a full user now
                        $this->db->delete('users', 'id = ?', [$user['id']]);
                    } else {
                        throw new Exception('Email already exists');
                    }
                }
            }
            
            // Generate OTP code for verification
            $otpCode = $this->generateOtpCode();
            $otpExpires = date('Y-m-d H:i:s', strtotime('+30 minutes'));
            
            // Hash password with stronger algorithm
            $hashedPassword = password_hash($password, PASSWORD_ARGON2ID);
            
            // Insert user
            $userData = [
                'username' => $username,
                'email' => $email,
                'password' => $hashedPassword,
                'full_name' => $fullName,
                'verification_token' => null,
                'verification_expires' => null,
                'otp_code' => $otpCode,
                'otp_expires' => $otpExpires,
                'is_verified' => 0,
                'is_active' => 0,
                'otp_attempts' => 0,
                'created_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s')
            ];
            
            $userId = $this->db->insert('users', $userData);
            
            if (!$userId) {
                throw new Exception('Failed to create user account. Please try again.');
            }
            
            error_log("User registered successfully: {$email} (ID: {$userId})");
            
            return [
                'id' => $userId,
                'username' => $username,
                'email' => $email,
                'fullName' => $fullName,
                'otpCode' => $otpCode
            ];
        } catch (Exception $e) {
            error_log('Registration error: ' . $e->getMessage());
            throw $e;
        }
    }
    
    /**
     * Generate a random OTP code for email verification
     * 
     * @return string 6-digit OTP code
     */
    private function generateOtpCode() {
        // Generate a more secure 6-digit OTP code using random_bytes for better entropy
        $randomBytes = random_bytes(4);
        $randomInt = hexdec(bin2hex($randomBytes)) % 1000000;
        return str_pad($randomInt, 6, '0', STR_PAD_LEFT);
    }
    
    /**
     * Verify email using OTP code
     * 
     * @param string $email User email
     * @param string $otpCode OTP code to verify
     * @return bool True if verification successful
     * @throws Exception If verification fails for any reason
     */
    public function verifyEmailWithOtp($email, $otpCode) {
        try {
            // Validate inputs
            if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                error_log("Verification failed: Invalid email format: {$email}");
                throw new Exception('Invalid email format. Please provide a valid email address.');
            }
            
            if (empty($otpCode) || !preg_match('/^\d{6}$/', $otpCode)) {
                error_log("Verification failed: Invalid OTP format for email: {$email}");
                throw new Exception('Invalid verification code format. Please provide a 6-digit code.');
            }
            
            // First check if there's a verification record for this email
            $userCheck = $this->findByEmail($email);
            if (!$userCheck) {
                error_log("Verification failed: No user found with email: {$email}");
                throw new Exception('Invalid or expired verification code. Please try again.');
            }
            
            // Check if user is already verified
            if ($userCheck['is_verified'] == 1) {
                error_log("Verification failed: Email already verified: {$email}");
                throw new Exception('Email is already verified. Please login.');
            }
            
            // Check if OTP exists and matches
            if (empty($userCheck['otp_code'])) {
                error_log("Verification failed: No OTP code found for user: {$email}");
                throw new Exception('No verification code found. Please request a new one.');
            }
            
            // Check if OTP is expired
            if (strtotime($userCheck['otp_expires']) < time()) {
                error_log("Verification failed: OTP expired for user: {$email}. Expired at: {$userCheck['otp_expires']}");
                throw new Exception('Verification code has expired. Please request a new one.');
            }
            
            // Verify OTP with constant-time comparison to prevent timing attacks
            if (!hash_equals($userCheck['otp_code'], $otpCode)) {
                error_log("Verification failed: Invalid OTP for user: {$email}. Provided: {$otpCode}");
                throw new Exception('Invalid verification code. Please try again.');
            }
            
            // Update user as verified and active
            try {
                $this->db->update('users', [
                    'is_verified' => 1,
                    'is_active' => 1,
                    'otp_code' => null,
                    'otp_expires' => null,
                    'email_verified_at' => date('Y-m-d H:i:s')
                ], 'id = ?', [$userCheck['id']]);
            } catch (Exception $updateError) {
                error_log("Database update error during verification for user: {$email}. Error: {$updateError->getMessage()}");
                throw new Exception('Error updating user verification status. Please try again.');
            }
            
            // Log successful verification
            error_log("Email verified successfully for user: {$email}");
            
            return true;
        } catch (Exception $e) {
            // Re-throw the exception to be caught by the caller
            throw $e;
        }
    }
    
    /**
     * Login a user with email and password
     * 
     * @param string $email User email
     * @param string $password User password
     * @return array User data
     * @throws Exception If login fails for any reason
     */
    public function login($email, $password) {
        try {
            // Validate inputs
            if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                throw new Exception('Invalid email format');
            }
            
            if (empty($password)) {
                throw new Exception('Password is required');
            }
            
            // Find user by email
            $user = $this->findByEmail($email);
            if (!$user) {
                // Use a generic error message to prevent email enumeration
                throw new Exception('Invalid email or password');
            }
            
            // Check if user is verified
            if ($user['is_verified'] != 1) {
                throw new Exception('Email not verified. Please verify your email before logging in.');
            }
            
            // Check if user is active
            if ($user['is_active'] != 1) {
                throw new Exception('Account is inactive. Please contact support.');
            }
            
            // Verify password
            if (!password_verify($password, $user['password'])) {
                // Log failed login attempt
                error_log("Failed login attempt for user: {$email}");
                throw new Exception('Invalid email or password');
            }
            
            // Update last login time and IP address
            $this->db->update('users', [
                'last_login' => date('Y-m-d H:i:s'),
                'ip_address' => $_SERVER['REMOTE_ADDR'] ?? null
            ], 'id = ?', [$user['id']]);
            
            // Log successful login
            error_log("User logged in successfully: {$email}");
            
            // Return user data
            return [
                'id' => $user['id'],
                'username' => $user['username'],
                'email' => $user['email'],
                'fullName' => $user['full_name'],
                'profilePicture' => $user['profile_picture'],
                'twoFactorEnabled' => (bool)$user['two_factor_enabled'],
                'isAdmin' => (bool)$user['is_admin']
            ];
        } catch (Exception $e) {
            // Re-throw the exception to be caught by the caller
            throw $e;
        }
    }
    
    /**
     * Find a user by ID
     * 
     * @param int $userId User ID
     * @return array|false User data or false if not found
     */
    public function findById($userId) {
        try {
            // Validate user ID
            if (empty($userId) || !is_numeric($userId)) {
                return false;
            }
            
            // Query the database
            $query = "SELECT * FROM users WHERE id = ? LIMIT 1";
            $result = $this->db->query($query, [$userId]);
            
            if (!$result || count($result) === 0) {
                return false;
            }
            
            return $result[0];
        } catch (Exception $e) {
            error_log('Error finding user by ID: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Generate a new OTP code for an existing user
     * 
     * @param string $email User email
     * @return string|false New OTP code or false if user not found
     * @throws Exception If there's an error generating or storing the OTP
     */
    public function generateNewOtp($email) {
        try {
            // Validate email
            if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                error_log("OTP generation failed: Invalid email format: {$email}");
                throw new Exception('Invalid email format. Please provide a valid email address.');
            }
            
            // Find user by email
            $user = $this->findByEmail($email);
            
            if (!$user) {
                error_log("OTP generation failed: No user found with email: {$email}");
                return false;
            }
            
            // Check if user is already verified
            if ($user['is_verified'] == 1) {
                error_log("OTP generation failed: Email already verified: {$email}");
                throw new Exception('Email is already verified. Please login.');
            }
            
            // Rate limiting code removed for testing purposes
            // This allows unlimited OTP requests without cooldown
            error_log("Rate limiting bypassed for user: {$email}");
            
            // Generate OTP code
            $otpCode = $this->generateOtpCode();
            $otpExpires = date('Y-m-d H:i:s', strtotime('+30 minutes'));
            
            // Update user with new OTP
            $result = $this->db->update('users', [
                'otp_code' => $otpCode,
                'otp_expires' => $otpExpires,
                'otp_attempts' => 0 // Reset attempts counter
            ], 'id = ?', [$user['id']]);
            
            if (!$result) {
                error_log("Failed to update OTP for user: {$email}");
                throw new Exception('Failed to generate verification code. Please try again.');
            }
            
            error_log("New OTP generated successfully for user: {$email}");
            return $otpCode;
        } catch (\Exception $e) {
            // Log the error for debugging
            error_log('Error in generateNewOtp: ' . $e->getMessage() . '\nTrace: ' . $e->getTraceAsString());
            // Re-throw the exception to be handled by the caller
            throw $e;
        }
    }
    
    /**
     * Generate a temporary OTP code for email verification before account creation
     * 
     * @param string $email User email
     * @return string New OTP code
     * @throws Exception If there's an error generating or storing the OTP
     */
    public function generateTemporaryOtp($email) {
        try {
            // Validate email
            if (empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                error_log("Temporary OTP generation failed: Invalid email format: {$email}");
                throw new Exception('Invalid email format. Please provide a valid email address.');
            }
            
            // Check if a regular user already exists with this email
            $existingUser = $this->findByEmail($email);
            if ($existingUser && $existingUser['username'] !== null) {
                // If user exists but is not verified, suggest verification
                if ($existingUser['is_verified'] == 0) {
                    error_log("Temporary OTP generation failed: Unverified user exists with email: {$email}");
                    throw new Exception('An account with this email already exists but is not verified. Please check your email for a verification code or request a new one.');
                } else {
                    // If user exists and is verified, suggest login
                    error_log("Temporary OTP generation failed: Verified user exists with email: {$email}");
                    throw new Exception('An account with this email already exists. Please login.');
                }
            }
            
            // Generate OTP code
            $otpCode = $this->generateOtpCode();
            $otpExpires = date('Y-m-d H:i:s', strtotime('+30 minutes'));
            
            // Check if a temporary record already exists
            $sql = "SELECT * FROM users WHERE email = ? AND username IS NULL";
            $tempUser = $this->db->selectOne($sql, [$email]);
            
            // Rate limiting code removed for testing purposes
            // This allows unlimited temporary OTP requests without cooldown
            error_log("Rate limiting bypassed for temporary OTP: {$email}");
            
            if ($tempUser) {
                // Update existing temporary record
                $result = $this->db->update('users', [
                    'otp_code' => $otpCode,
                    'otp_expires' => $otpExpires,
                    'otp_attempts' => 0, // Reset attempts counter
                    'updated_at' => date('Y-m-d H:i:s')
                ], 'id = ?', [$tempUser['id']]);
                
                if (!$result) {
                    error_log("Failed to update temporary OTP for email: {$email}");
                    throw new Exception('Failed to generate verification code. Please try again.');
                }
            } else {
                // Create a temporary user record for verification only
                $userData = [
                    'email' => $email,
                    'username' => null, // Null username indicates this is a temporary verification record
                    'password' => null,
                    'full_name' => null,
                    'verification_token' => null,
                    'verification_expires' => null,
                    'otp_code' => $otpCode,
                    'otp_expires' => $otpExpires,
                    'is_verified' => 0,
                    'is_active' => 0,
                    'otp_attempts' => 0,
                    'created_at' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s')
                ];
                
                $result = $this->db->insert('users', $userData);
                if (!$result) {
                    error_log("Failed to create temporary user record for email: {$email}");
                    throw new Exception('Failed to generate verification code. Please try again.');
                }
            }
            
            error_log("Temporary OTP generated successfully for email: {$email}");
            return $otpCode;
        } catch (\Exception $e) {
            // Log the error for debugging
            error_log('Error in generateTemporaryOtp: ' . $e->getMessage() . '\nTrace: ' . $e->getTraceAsString());
            // Re-throw the exception to be handled by the caller
            throw $e;
        }
    }
    
    /**
     * Legacy method for token-based verification
     * Kept for backward compatibility
     */
    public function verifyEmail($token) {
        $sql = "SELECT * FROM users WHERE verification_token = ? AND verification_expires > NOW() AND is_verified = 0";
        $user = $this->db->selectOne($sql, [$token]);
        
        if (!$user) {
            throw new Exception('Invalid or expired verification token');
        }
        
        // Update user as verified and active
        $this->db->update('users', [
            'is_verified' => 1,
            'is_active' => 1,
            'verification_token' => null,
            'verification_expires' => null
        ], 'id = ?', [$user['id']]);
        
        return true;
    }
    
    public function findByUsernameOrEmail($username, $email) {
        $sql = "SELECT * FROM users WHERE username = ? OR email = ? LIMIT 1";
        return $this->db->selectOne($sql, [$username, $email]);
    }
    
    public function findByEmail($email) {
        $sql = "SELECT * FROM users WHERE email = ?";
        return $this->db->selectOne($sql, [$email]);
    }
    

    
    public function getAllUsers() {
        $sql = "SELECT id, username, email, full_name, profile_picture, two_factor_enabled, 
               is_admin, is_active, created_at, last_login FROM users ORDER BY id DESC";
        return $this->db->select($sql);
    }
    
    public function updateUser($id, $data) {
        return $this->db->update('users', $data, 'id = ?', [$id]);
    }
    
    public function deleteUser($id) {
        return $this->db->delete('users', 'id = ?', [$id]);
    }
    
    /**
     * Create a new user (admin functionality)
     * 
     * @param array $data User data
     * @return array Created user data
     */
    public function createUser($data) {
        // Validate required fields
        $requiredFields = ['username', 'email', 'password', 'full_name'];
        foreach ($requiredFields as $field) {
            if (!isset($data[$field]) || empty($data[$field])) {
                throw new Exception("Field '{$field}' is required");
            }
        }
        
        // Check if username or email already exists
        $user = $this->findByUsernameOrEmail($data['username'], $data['email']);
        if ($user) {
            if ($user['username'] === $data['username']) {
                throw new Exception('Username already exists');
            }
            if ($user['email'] === $data['email']) {
                throw new Exception('Email already exists');
            }
        }
        
        // Hash password
        $hashedPassword = password_hash($data['password'], PASSWORD_DEFAULT);
        
        // Prepare user data
        $userData = [
            'username' => $data['username'],
            'email' => $data['email'],
            'password' => $hashedPassword,
            'full_name' => $data['full_name'],
            'is_verified' => 1, // Admin-created users are verified by default
            'is_active' => isset($data['is_active']) ? $data['is_active'] : 1,
            'is_admin' => isset($data['is_admin']) ? $data['is_admin'] : 0
        ];
        
        // Insert user
        $userId = $this->db->insert('users', $userData);
        
        // Return user data without password
        unset($userData['password']);
        $userData['id'] = $userId;
        
        return $userData;
    }
    
    public function isAdmin($userId) {
        $sql = "SELECT is_admin FROM users WHERE id = ?";
        $user = $this->db->selectOne($sql, [$userId]);
        return $user && (bool)$user['is_admin'];
    }
}