#!/usr/bin/env php
<?php

declare(strict_types=1);

const DEFAULT_AUTH_URL = 'https://cloud.supla.org/oauth/v2/auth';
const DEFAULT_TOKEN_URL = 'https://cloud.supla.org/oauth/v2/token';
const DEFAULT_SCOPE = 'account_r';

function option_value(array $options, string $name, ?string $default = null): ?string
{
    if (array_key_exists($name, $options)) {
        return is_array($options[$name]) ? (string) reset($options[$name]) : (string) $options[$name];
    }

    $env = getenv($name);
    if ($env !== false && $env !== '') {
        return $env;
    }

    return $default;
}

function http_request(string $method, string $url, array $headers = [], ?string $body = null): array
{
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        if ($ch === false) {
            throw new RuntimeException('Failed to initialize cURL.');
        }

        $headerLines = [];
        foreach ($headers as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_HEADER => true,
        ]);

        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $response = curl_exec($ch);
        if ($response === false) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException('Request failed: ' . $error);
        }

        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $headerSize = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $contentType = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        curl_close($ch);

        return [
            'status' => $status,
            'content_type' => $contentType,
            'headers' => substr($response, 0, $headerSize),
            'body' => substr($response, $headerSize),
        ];
    }

    $headerLines = [];
    foreach ($headers as $name => $value) {
        $headerLines[] = $name . ': ' . $value;
    }

    $context = stream_context_create([
        'http' => [
            'method' => $method,
            'header' => implode("\r\n", $headerLines),
            'content' => $body ?? '',
            'ignore_errors' => true,
            'timeout' => 30,
        ],
    ]);

    $response = file_get_contents($url, false, $context);
    if ($response === false) {
        $error = error_get_last();
        $message = $error['message'] ?? 'unknown error';
        throw new RuntimeException('Request failed: ' . $message);
    }

    $responseHeaders = $http_response_header ?? [];
    $status = 0;
    $contentType = '';
    $rawHeaders = implode("\n", $responseHeaders);

    foreach ($responseHeaders as $line) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $matches)) {
            $status = (int) $matches[1];
        } elseif (stripos($line, 'Content-Type:') === 0) {
            $contentType = trim(substr($line, strlen('Content-Type:')));
        }
    }

    return [
        'status' => $status,
        'content_type' => $contentType,
        'headers' => $rawHeaders,
        'body' => $response,
    ];
}

function supla_host_from_encoded_value(string $value): ?string
{
    $value = trim($value);
    if ($value === '') {
        return null;
    }

    $dotPos = strrpos($value, '.');
    if (false === $dotPos) {
        return null;
    }

    $suffix = substr($value, $dotPos + 1);

    $suffix = rawurldecode($suffix);
    $decoded = base64_decode($suffix, true);
    if (false !== $decoded && looks_like_url($decoded)) {
        $suffix = $decoded;
    } elseif (!looks_like_url($suffix)) {
        return null;
    }

    $suffix = trim($suffix);
    if ($suffix === '') {
        return null;
    }

    if (false === strpos($suffix, '://')) {
        $suffix = 'https://' . $suffix;
    }

    $parsed = parse_url($suffix);
    if (!is_array($parsed) || empty($parsed['host'])) {
        return null;
    }

    return $parsed['host'];
}

function looks_like_url(string $value): bool
{
    return (bool) preg_match('#^https?://[A-Za-z0-9.-]+(?::\d+)?(?:/.*)?$#i', trim($value));
}

function supla_api_url_from_host(?string $host): ?string
{
    if (null === $host || trim($host) === '') {
        return null;
    }

    return 'https://' . trim($host) . '/api/v3';
}

function supla_auth_url_from_host(?string $host): ?string
{
    if (null === $host || trim($host) === '') {
        return null;
    }

    return 'https://' . trim($host) . '/oauth/v2/auth';
}

function supla_token_url_from_host(?string $host): ?string
{
    if (null === $host || trim($host) === '') {
        return null;
    }

    return 'https://' . trim($host) . '/oauth/v2/token';
}

function supla_api_url_from_token_data(array $tokenData): ?string
{
    return null;
}

function print_usage(string $script): void
{
    fwrite(STDERR, "Usage:\n");
    fwrite(STDERR, "  php {$script} --client-id=... --client-secret=... [--redirect-uri=...] [--server-host=...] [--auth-url=...] [--token-url=...] [--api-url=...]\n");
    fwrite(STDERR, "\n");
    fwrite(STDERR, "Environment variables may be used instead of options:\n");
    fwrite(STDERR, "  SUPLA_CLIENT_ID, SUPLA_CLIENT_SECRET, SUPLA_REDIRECT_URI, SUPLA_SERVER_HOST, SUPLA_AUTH_URL, SUPLA_TOKEN_URL, SUPLA_API_URL, SUPLA_SCOPE\n");
}

$options = getopt('', [
    'client-id:',
    'client-secret:',
    'redirect-uri::',
    'server-host::',
    'auth-url::',
    'token-url::',
    'api-url::',
    'scope::',
    'code::',
    'help',
]);

$script = basename($argv[0]);

if (isset($options['help'])) {
    print_usage($script);
    exit(0);
}

$clientId = option_value($options, 'client-id', option_value($options, 'SUPLA_CLIENT_ID'));
$clientSecret = option_value($options, 'client-secret', option_value($options, 'SUPLA_CLIENT_SECRET'));
$redirectUri = option_value($options, 'redirect-uri', option_value($options, 'SUPLA_REDIRECT_URI', 'http://127.0.0.1:8765/callback'));
$serverHost = option_value($options, 'server-host', option_value($options, 'SUPLA_SERVER_HOST'));
$authUrl = option_value($options, 'auth-url', option_value($options, 'SUPLA_AUTH_URL', DEFAULT_AUTH_URL));
$tokenUrl = option_value($options, 'token-url', option_value($options, 'SUPLA_TOKEN_URL', DEFAULT_TOKEN_URL));
$apiUrl = option_value($options, 'api-url', option_value($options, 'SUPLA_API_URL'));
$scope = option_value($options, 'scope', option_value($options, 'SUPLA_SCOPE', DEFAULT_SCOPE));
$code = option_value($options, 'code', option_value($options, 'SUPLA_AUTH_CODE'));

if ($clientId === null || $clientSecret === null) {
    print_usage($script);
    fwrite(STDERR, "\nMissing SUPLA client credentials.\n");
    exit(1);
}

if ($serverHost !== null && trim($serverHost) !== '') {
    $hostAuthUrl = supla_auth_url_from_host($serverHost);
    $hostTokenUrl = supla_token_url_from_host($serverHost);
    $hostApiUrl = supla_api_url_from_host($serverHost);

    if (null !== $hostAuthUrl) {
        $authUrl = $hostAuthUrl;
    }

    if (null !== $hostTokenUrl) {
        $tokenUrl = $hostTokenUrl;
    }

    if (null !== $hostApiUrl) {
        $apiUrl = $hostApiUrl;
    }
}

if ($code === null || $code === '') {
    $state = bin2hex(random_bytes(16));
    $query = http_build_query([
        'client_id' => $clientId,
        'redirect_uri' => $redirectUri,
        'response_type' => 'code',
        'scope' => $scope,
        'state' => $state,
    ]);
    $authorizationUrl = rtrim($authUrl, '?') . '?' . $query;

    echo "Open this URL in a browser and complete the SUPLA login/consent flow:\n";
    echo $authorizationUrl . "\n\n";
    echo "After SUPLA redirects back, paste the full callback URL or just the `code` parameter.\n";
    echo "Callback URL / code: ";

    $input = trim((string) fgets(STDIN));
    if ($input === '') {
        fwrite(STDERR, "No callback URL or code provided.\n");
        exit(1);
    }

    if (preg_match('/[?&]code=([^&]+)/', $input, $matches)) {
        $code = rawurldecode($matches[1]);
    } elseif (preg_match('/^[A-Za-z0-9._~-]+$/', $input)) {
        $code = $input;
    } else {
        fwrite(STDERR, "Could not extract `code` from the provided input.\n");
        exit(1);
    }
}

$resolvedHost = supla_host_from_encoded_value($code);
if (null === $resolvedHost && null === $apiUrl) {
    fwrite(STDERR, "Could not resolve SUPLA host from the callback code.\n");
    exit(1);
}

if (null === $apiUrl) {
    $apiUrl = supla_api_url_from_host($resolvedHost);
}

if (null === $apiUrl) {
    $apiUrl = 'https://cloud.supla.org/api/v3';
}

$tokenResponse = http_request('POST', $tokenUrl, [
    'Accept' => 'application/json',
    'Content-Type' => 'application/x-www-form-urlencoded',
], http_build_query([
    'grant_type' => 'authorization_code',
    'client_id' => $clientId,
    'client_secret' => $clientSecret,
    'redirect_uri' => $redirectUri,
    'code' => $code,
]));

$tokenData = json_decode($tokenResponse['body'], true);
if ($tokenResponse['status'] < 200 || $tokenResponse['status'] >= 300 || !is_array($tokenData) || empty($tokenData['access_token'])) {
    fwrite(STDERR, "Token exchange failed.\n");
    fwrite(STDERR, "HTTP status: {$tokenResponse['status']}\n");
    fwrite(STDERR, $tokenResponse['body'] . "\n");
    exit(1);
}

$tokenApiUrl = supla_api_url_from_token_data($tokenData);
if (null !== $tokenApiUrl) {
    $apiUrl = $tokenApiUrl;
}

$accessToken = (string) $tokenData['access_token'];

$userResponse = http_request('GET', $apiUrl . '/users/current', [
    'Accept' => 'application/json',
    'Authorization' => 'Bearer ' . $accessToken,
]);

$userData = json_decode($userResponse['body'], true);
if ($userResponse['status'] < 200 || $userResponse['status'] >= 300 || !is_array($userData)) {
    fwrite(STDERR, "User lookup failed.\n");
    fwrite(STDERR, "HTTP status: {$userResponse['status']}\n");
    fwrite(STDERR, $userResponse['body'] . "\n");
    exit(1);
}

echo "SUPLA OAuth flow succeeded.\n";
echo json_encode([
    'resolved_host' => $resolvedHost,
    'api_url' => $apiUrl,
    'token_keys' => array_keys($tokenData),
    'current_user' => $userData,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
