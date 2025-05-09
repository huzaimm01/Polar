<?php
// Enable error reporting for development (remove in production)
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Set headers for CORS and JSON response
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Methods: POST");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With");

// Get the posted data
$data = json_decode(file_get_contents("php://input"));

// Check if data is complete
if (!isset($data->username) || !isset($data->password)) {
    http_response_code(400);
    echo json_encode([
        "success" => false,
        "message" => "Username and password are required."
    ]);
    exit;
}

// Sanitize user input
$username = filter_var($data->username, FILTER_SANITIZE_STRING);
$password = $data->password; // Will be verified using password_verify

// Include database connection and encryption functions
require_once 'config.php';
require_once 'encryption.php';

// Initialize the encryption handler
$encryption = new Encryption();

// Path to the encrypted user data file
$userDataPath = "../data/users.encrypted";

// Check if encrypted file exists
if (!file_exists($userDataPath)) {
    http_response_code(500);
    echo json_encode([
        "success" => false,
        "message" => "User database not found."
    ]);
    exit;
}

try {
    // Read and decrypt the user data
    $encryptedData = file_get_contents($userDataPath);
    $decryptedData = $encryption->decrypt($encryptedData);
    
    // Parse the decrypted JSON data
    $users = json_decode($decryptedData, true);
    
    // User authentication
    $authenticated = false;
    $userData = null;
    
    foreach ($users as $user) {
        if ($user['username'] === $username && password_verify($password, $user['password'])) {
            $authenticated = true;
            $userData = $user;
            break;
        }
    }
    
    if ($authenticated) {
        // Remove sensitive data
        unset($userData['password']);
        
        // Start session
        session_start();
        $_SESSION['user_id'] = $userData['id'];
        $_SESSION['username'] = $userData['username'];
        
        // Return success response
        http_response_code(200);
        echo json_encode([
            "success" => true,
            "message" => "Login successful",
            "user" => $userData
        ]);
    } else {
        // Authentication failed
        http_response_code(401);
        echo json_encode([
            "success" => false,
            "message" => "Invalid username or password"
        ]);
    }
} catch (Exception $e) {
    // Error handling
    http_response_code(500);
    echo json_encode([
        "success" => false,
        "message" => "An error occurred: " . $e->getMessage()
    ]);
}