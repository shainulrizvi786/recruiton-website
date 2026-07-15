<?php
/**
 * submit-lead.php
 * Handles lead form submissions from saudi-saso-saber-certification.html
 * (and any other page using the same lead-form pattern).
 *
 * What it does:
 *  1. Validates and sanitizes incoming POST data
 *  2. Rejects spam via a honeypot field
 *  3. Emails the lead to the configured recipient
 *  4. Appends a backup row to leads-log.csv (protected from public access via .htaccess)
 *  5. Returns a JSON response for the frontend fetch() call
 *
 * SETUP NOTE: change RECIPIENT_EMAIL below to the address that should
 * actually receive leads (e.g. your sales/support inbox).
 */

// ---- Configuration ----
define('RECIPIENT_EMAIL', 'hello@recruiton.io'); // <-- change to your real inbox
define('FROM_EMAIL', 'noreply@recruiton.io');     // should match your domain to avoid spam filters
define('LOG_FILE', __DIR__ . '/leads-log.csv');
define('MAX_FIELD_LENGTH', 2000);

// ---- Basic request setup ----
header('Content-Type: application/json');

// Only allow POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

// Simple same-origin check (optional, helps reduce abuse from other sites)
$allowedHost = 'recruiton.io';
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$referer = $_SERVER['HTTP_REFERER'] ?? '';
if ($origin && stripos($origin, $allowedHost) === false && stripos($origin, 'localhost') === false) {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Invalid origin']);
    exit;
}

// ---- Honeypot spam check ----
// The frontend includes a hidden field named "website" that real users never fill.
if (!empty($_POST['website'])) {
    // Silently pretend success so bots don't learn the honeypot worked.
    echo json_encode(['success' => true]);
    exit;
}

// ---- Helper: sanitize a text field ----
function clean_field($value) {
    $value = trim((string) $value);
    $value = substr($value, 0, MAX_FIELD_LENGTH);
    // Strip control characters (prevents email header injection via newlines etc.)
    $value = preg_replace('/[\r\n\x00-\x1F\x7F]+/', ' ', $value);
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

// ---- Collect + validate fields ----
$name          = clean_field($_POST['name'] ?? '');
$phone         = clean_field($_POST['phone'] ?? '');
$email         = clean_field($_POST['email'] ?? '');
$product       = clean_field($_POST['product'] ?? '');
$company       = clean_field($_POST['company'] ?? '');
$certification = clean_field($_POST['certification'] ?? '');
$message       = clean_field($_POST['message'] ?? '');
$source        = clean_field($_POST['source'] ?? 'Unknown Form');

$errors = [];
if ($name === '') {
    $errors[] = 'Name is required.';
}
if ($phone === '' && $email === '') {
    $errors[] = 'Please provide a phone number or email.';
}
if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'Please provide a valid email address.';
}

if (!empty($errors)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'errors' => $errors]);
    exit;
}

// ---- Build email ----
$subject = 'New SASO/SABER Enquiry - ' . $source;

$body  = "New lead submitted on recruiton.io\n\n";
$body .= "Source: {$source}\n";
$body .= "Name: {$name}\n";
$body .= "Phone: {$phone}\n";
$body .= "Email: {$email}\n";
$body .= "Company: {$company}\n";
$body .= "Product/Certification: {$product}\n";
$body .= "Required Certification: {$certification}\n";
$body .= "Message: {$message}\n";
$body .= "Submitted at: " . date('Y-m-d H:i:s') . "\n";
$body .= "IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . "\n";

$headers   = [];
$headers[] = 'From: Recruiton Website <' . FROM_EMAIL . '>';
if ($email !== '') {
    $headers[] = 'Reply-To: ' . $email;
}
$headers[] = 'Content-Type: text/plain; charset=UTF-8';
$headers[] = 'X-Mailer: PHP/' . phpversion();

$mailSent = @mail(RECIPIENT_EMAIL, $subject, $body, implode("\r\n", $headers));

// ---- Backup log (CSV) ----
// Protected from public download via the .htaccess rule deployed alongside this file.
$logRow = [
    date('Y-m-d H:i:s'),
    $source,
    $name,
    $phone,
    $email,
    $company,
    $product,
    $certification,
    str_replace(["\r", "\n"], ' ', $message),
    $_SERVER['REMOTE_ADDR'] ?? '',
];

$fileExists = file_exists(LOG_FILE);
$fp = @fopen(LOG_FILE, 'a');
if ($fp) {
    if (!$fileExists) {
        fputcsv($fp, ['Timestamp', 'Source', 'Name', 'Phone', 'Email', 'Company', 'Product', 'Certification', 'Message', 'IP']);
    }
    fputcsv($fp, $logRow);
    fclose($fp);
}

// ---- Response ----
if ($mailSent) {
    echo json_encode(['success' => true]);
} else {
    // Even if mail() fails (common on some shared hosting without SMTP configured),
    // the lead is still safely logged to leads-log.csv, so we still report success
    // to the visitor but flag it server-side isn't fully confirmed.
    echo json_encode(['success' => true, 'warning' => 'Logged, but email dispatch could not be confirmed.']);
}
