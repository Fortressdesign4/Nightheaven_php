<?php
// Beispiel-API-Key (normalerweise aus config oder apikey.php)
$VALID_API_KEY = 'MEIN_GEHEIMER_API_KEY';

// Funktion, um Authorization Header auszulesen
function getAuthorizationHeader() {
    if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        return trim($_SERVER["HTTP_AUTHORIZATION"]);
    } elseif (function_exists('apache_request_headers')) {
        $headers = apache_request_headers();
        if (isset($headers['Authorization'])) {
            return trim($headers['Authorization']);
        }
    }
    return null;
}

// API-Key aus Header auslesen
$authHeader = getAuthorizationHeader();
if (!$authHeader || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'API-Key fehlt oder ungültig']);
    exit;
}

$apiKey = $matches[1];

// Prüfen, ob API-Key korrekt ist
if ($apiKey !== $VALID_API_KEY) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Ungültiger API-Key']);
    exit;
}

// --- Sicherheits-Header ---
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: no-referrer-when-downgrade");
header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
header("Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'");

// No-Cache Header
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: 0");

// Content-Type JSON
header("Content-Type: application/json");

// Beispiel-News
$news = [
    "status" => "ok",
    "articles" => [
        [
            "title" => "Wir suchen einen Schlagzeuger",
            "description" => "Unsere Plattform ist live. Entdecke neue Funktionen.",
            "publishedAt" => "01. Mai 2025"
        ],
        [
            "title" => "Wir suchen einen Schlagzeuger",
            "description" => "Ab sofort kannst du das neue Design ausprobieren.",
            "publishedAt" => "15. Mai 2025"
        ],
    ]
];

// Ausgabe
echo json_encode($news, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
?>
