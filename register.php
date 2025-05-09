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
if (!isset($data->username) || !isset($data->email) || !isset($data->password)) {
    http_response_code(400);
    echo json_encode([
        "success" => false,
        "message" => "All fields are required."
    ]);
    exit;
}

// Validate the input data
if (empty($data->username) || empty($data->email) || empty($data->password)) {
    http_response_code(400);
    echo json_encode([
        "success" => false,
        "message" => "Fields cannot be empty."
    ]);
    exit;
}

// Validate email format
if (!filter_var($data->email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode([
        "success" => false,
        "message" => "Invalid email format."
    ]);
    exit;
}

// Generate a unique encryption key for this deployment
function generateEncryptionKey() {
    return bin2hex(random_bytes(32)); // 256-bit key
}

// Simple encryption function
function encryptData($data, $key) {
    $ivlen = openssl_cipher_iv_length($cipher = "AES-256-CBC");
    $iv = openssl_random_pseudo_bytes($ivlen);
    $encrypted = openssl_encrypt($data, $cipher, $key, 0, $iv);
    return base64_encode($iv . $encrypted);
}

// Simple decryption function
function decryptData($data, $key) {
    $data = base64_decode($data);
    $ivlen = openssl_cipher_iv_length($cipher = "AES-256-CBC");
    $iv = substr($data, 0, $ivlen);
    $encrypted = substr($data, $ivlen);
    return openssl_decrypt($encrypted, $cipher, $key, 0, $iv);
}

// Load or create encryption key
$keyFile = "encryption_key.txt";
if (!file_exists($keyFile)) {
    $encryptionKey = generateEncryptionKey();
    file_put_contents($keyFile, $encryptionKey);
} else {
    $encryptionKey = file_get_contents($keyFile);
}

// Path to the user database file
$dbFile = "users_db.csv";

// Create the file if it doesn't exist with headers
if (!file_exists($dbFile)) {
    file_put_contents($dbFile, "username,email,password,created_at\n");
}

// Check if username or email already exists
$existingUsers = array_map('str_getcsv', file($dbFile));
$headers = array_shift($existingUsers); // Remove header row

foreach ($existingUsers as $user) {
    $decryptedUsername = decryptData($user[0], $encryptionKey);
    $decryptedEmail = decryptData($user[1], $encryptionKey);
    
    if ($decryptedUsername === $data->username) {
        http_response_code(409);
        echo json_encode([
            "success" => false,
            "message" => "Username already exists."
        ]);
        exit;
    }
    
    if ($decryptedEmail === $data->email) {
        http_response_code(409);
        echo json_encode([
            "success" => false,
            "message" => "Email already registered."
        ]);
        exit;
    }
}

// Hash the password
$hashedPassword = password_hash($data->password, PASSWORD_DEFAULT);

// Encrypt the user data
$encUsername = encryptData($data->username, $encryptionKey);
$encEmail = encryptData($data->email, $encryptionKey);
$encPassword = encryptData($hashedPassword, $encryptionKey);
$createdAt = date('Y-m-d H:i:s');

// Prepare the new user data
$newUser = [
    $encUsername,
    $encEmail,
    $encPassword,
    $createdAt
];

// Append the new user to the CSV file
$file = fopen($dbFile, 'a');
fputcsv($file, $newUser);
fclose($file);

// Return success response
http_response_code(201);
echo json_encode([
    "success" => true,
    "message" => "User registered successfully.",
    "user" => [
        "username" => $data->username,
        "email" => $data->email,
        "created_at" => $createdAt
    ]
]);
?>