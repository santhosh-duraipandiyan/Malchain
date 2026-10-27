<?php
/**
 * MalChain IOC proxy for PHP hosts (Hostinger, cPanel, etc.).
 * Same-origin from the site, so no CORS. Holds your MalwareBazaar Auth-Key server-side.
 *
 *   GET api/lookup.php?hash=<sha256|sha1|md5>              -> get_info (IOC page)
 *   GET api/lookup.php?type=signature&value=<fam>&limit=6  -> get_siginfo (technique pages)
 *   GET api/lookup.php?type=tag&value=<tag>&limit=6        -> get_taginfo (technique pages)
 */
header('Content-Type: application/json');

$key = getenv('MWB_API_KEY');
if (!$key && is_file(__DIR__ . '/config.php')) {
    $cfg = require __DIR__ . '/config.php';
    $key = isset($cfg['MWB_API_KEY']) ? $cfg['MWB_API_KEY'] : '';
}
if (!$key || strpos($key, 'PASTE_') === 0) {
    http_response_code(500); echo json_encode(array('query_status' => 'no_api_key')); exit;
}

$hash  = isset($_GET['hash'])  ? trim($_GET['hash'])  : '';
$type  = isset($_GET['type'])  ? trim($_GET['type'])  : '';
$value = isset($_GET['value']) ? trim($_GET['value']) : '';
$limit = isset($_GET['limit']) ? (int)$_GET['limit']  : 6;
if ($limit < 1)  $limit = 1;
if ($limit > 20) $limit = 20;

if ($hash !== '') {
    if (!preg_match('/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/', $hash)) {
        http_response_code(400); echo json_encode(array('query_status' => 'bad_hash')); exit;
    }
    $params = array('query' => 'get_info', 'hash' => $hash);
} elseif ($type === 'signature' && $value !== '') {
    $params = array('query' => 'get_siginfo', 'signature' => $value, 'limit' => $limit);
} elseif ($type === 'tag' && $value !== '') {
    $params = array('query' => 'get_taginfo', 'tag' => $value, 'limit' => $limit);
} else {
    http_response_code(400); echo json_encode(array('query_status' => 'bad_request')); exit;
}

$url  = 'https://mb-api.abuse.ch/api/v1/';
$post = http_build_query($params);
$resp = false;

if (function_exists('curl_init')) {
    $ch = curl_init($url);
    curl_setopt_array($ch, array(
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $post,
        CURLOPT_HTTPHEADER     => array('Auth-Key: ' . $key),
        CURLOPT_TIMEOUT        => 30,
    ));
    $resp = curl_exec($ch);
    if ($resp === false) {
        http_response_code(502);
        echo json_encode(array('query_status' => 'upstream_error', 'detail' => curl_error($ch)));
        curl_close($ch); exit;
    }
    curl_close($ch);
} else {
    $ctx = stream_context_create(array('http' => array(
        'method'  => 'POST',
        'header'  => "Content-Type: application/x-www-form-urlencoded\r\nAuth-Key: " . $key . "\r\n",
        'content' => $post,
        'timeout' => 30,
    )));
    $resp = @file_get_contents($url, false, $ctx);
    if ($resp === false) { http_response_code(502); echo json_encode(array('query_status' => 'upstream_error')); exit; }
}
echo $resp;
