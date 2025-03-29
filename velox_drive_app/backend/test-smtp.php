<?php
require_once __DIR__ . '/utils/EmailSender.php';

function testSmtpConnection($host, $port, $encryption) {
    $errno = 0;
    $errstr = '';
    $timeout = 20;
    
    echo "Testing SMTP connection to $host:$port...\n";
    
    // Test basic socket connection
    $socket = @fsockopen(
        $encryption === 'ssl' ? "ssl://$host" : $host,
        $port,
        $errno,
        $errstr,
        $timeout
    );
    
    if (!$socket) {
        echo "Socket connection failed: ($errno) $errstr\n";
        return false;
    }
    
    echo "Socket connection successful!\n";
    fclose($socket);
    return true;
}

try {
    // Load email configuration
    $config = require __DIR__ . '/config/email.php';
    $host = $config['smtp']['host'];
    $port = $config['smtp']['port'];
    $encryption = $config['smtp']['encryption'];
    
    // Test basic SMTP connection first
    if (!testSmtpConnection($host, $port, $encryption)) {
        throw new Exception("Failed to establish basic SMTP connection");
    }
    
    // Initialize EmailSender
    echo "\nInitializing EmailSender...\n";
    $emailSender = new EmailSender();
    echo "SMTP connection and authentication successful!\n";
    
    // Test email sending
    $testEmail = 'test@example.com';
    echo "\nAttempting to send test email to: $testEmail\n";
    
    // Use synchronous method for testing
    $result = $emailSender->sendOtpVerificationEmail($testEmail, 'Test User', '123456');
    
    if ($result) {
        echo "Test email sent successfully!\n";
        error_log("SMTP Test: Email sent successfully to $testEmail");
    } else {
        echo "Failed to send test email. Check error logs for details.\n";
        error_log("SMTP Test: Failed to send email to $testEmail");
        exit(1);
    }
    
} catch (Exception $e) {
    echo "\nSMTP Error: " . $e->getMessage() . "\n";
    error_log('SMTP Test Error: ' . $e->getMessage());
    error_log('Stack trace: ' . $e->getTraceAsString());
    exit(1);
}