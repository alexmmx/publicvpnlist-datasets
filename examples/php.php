<?php
declare(strict_types=1);

$url = 'https://publicvpnlist.com/api/v1/servers?country=US&per_page=10';
$payload = json_decode((string)file_get_contents($url), true, flags: JSON_THROW_ON_ERROR);
print_r($payload['data']);
