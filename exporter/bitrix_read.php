<?php
declare(strict_types=1);

use Bitrix\Main\Loader;

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "This reader is CLI-only.\n");
    exit(2);
}

$options = getopt('', ['site-root:', 'limit::', 'source::', 'protocol::', 'now:']);
$siteRoot = realpath((string)($options['site-root'] ?? ''));
$nowTs = filter_var($options['now'] ?? null, FILTER_VALIDATE_INT);
$limit = filter_var($options['limit'] ?? 0, FILTER_VALIDATE_INT);
$sourceFilter = trim((string)($options['source'] ?? ''));
$protocolFilter = strtolower(trim((string)($options['protocol'] ?? '')));

if ($siteRoot === false || !is_dir($siteRoot) || !is_int($nowTs) || $nowTs <= 0) {
    fwrite(STDERR, "Invalid reader arguments.\n");
    exit(2);
}
if ($limit === false || $limit < 0 || $limit > 100000) {
    fwrite(STDERR, "Invalid record limit.\n");
    exit(2);
}
if ($protocolFilter !== '' && $protocolFilter !== 'openvpn') {
    echo "[]\n";
    exit(0);
}

$_SERVER['DOCUMENT_ROOT'] = $siteRoot;
define('NO_KEEP_STATISTIC', true);
define('NOT_CHECK_PERMISSIONS', true);
define('BX_CRONTAB', true);

try {
    require $siteRoot . '/bitrix/modules/main/include/prolog_before.php';
    require_once $siteRoot . '/local/include/vpn_seo.php';
    if (!Loader::includeModule('iblock')) {
        throw new RuntimeException('IBlock module is unavailable.');
    }
    $iblock = CIBlock::GetList([], ['=CODE' => 'vpn_servers'])->Fetch();
    if (!$iblock) {
        throw new RuntimeException('VPN Servers IBlock is unavailable.');
    }

    $select = [
        'ID',
        'ACTIVE',
        'DATE_CREATE',
        'TIMESTAMP_X',
        'IBLOCK_SECTION_ID',
        'PROPERTY_IP',
        'PROPERTY_HOST',
        'PROPERTY_CC',
        'PROPERTY_COUNTRY',
        'PROPERTY_SPEED_MBPS',
        'PROPERTY_PING_MS',
        'PROPERTY_SESSIONS',
        'PROPERTY_UPTIME_HOURS',
        'PROPERTY_CLEAN',
        'PROPERTY_PORT',
        'PROPERTY_PROTO',
        'PROPERTY_SOURCE',
        'PROPERTY_CHECKED_AT',
        'PROPERTY_LAST_CHECK_OK',
        'PROPERTY_FAIL_STREAK',
        'PROPERTY_VPN_CHECK_STATUS',
        'PROPERTY_OVPN_PATH',
        'PROPERTY_OVPN_FILE',
        'PROPERTY_LAST_SUCCESS_AT',
        'PROPERTY_ACTIVATED_AT',
    ];
    $navigation = $limit > 0 ? ['nTopCount' => $limit] : false;
    $filter = ['IBLOCK_ID' => (int)$iblock['ID'], 'ACTIVE' => 'Y'];
    if ($sourceFilter !== '') {
        $filter['PROPERTY_SOURCE'] = $sourceFilter;
    }
    $result = CIBlockElement::GetList(
        ['ID' => 'ASC'],
        $filter,
        false,
        $navigation,
        $select
    );

    $rows = [];
    $sections = [];
    while ($item = $result->Fetch()) {
        $source = scalarValue($item['PROPERTY_SOURCE_VALUE'] ?? '');
        $sectionId = (int)($item['IBLOCK_SECTION_ID'] ?? 0);
        if ($sectionId > 0 && !array_key_exists($sectionId, $sections)) {
            $sections[$sectionId] = CIBlockSection::GetByID($sectionId)->Fetch() ?: [];
        }
        $section = $sections[$sectionId] ?? [];
        $countrySlug = scalarValue($item['PROPERTY_CC_VALUE'] ?? '');
        if ($countrySlug === '') {
            $countrySlug = scalarValue($section['CODE'] ?? '');
        }
        $countryName = scalarValue($item['PROPERTY_COUNTRY_VALUE'] ?? '');
        if ($countryName === '') {
            $countryName = scalarValue($section['NAME'] ?? '');
        }
        $countryCode = strtoupper(pvl_country_alpha2(pvl_normalize_country_slug($countrySlug)));
        $host = scalarValue($item['PROPERTY_HOST_VALUE'] ?? '');
        $ip = scalarValue($item['PROPERTY_IP_VALUE'] ?? '');
        $transport = strtolower(scalarValue($item['PROPERTY_PROTO_VALUE'] ?? ''));
        $configAvailable = configAvailable(
            $siteRoot,
            scalarValue($item['PROPERTY_OVPN_PATH_VALUE'] ?? ''),
            scalarValue($item['PROPERTY_OVPN_FILE_VALUE'] ?? '')
        );
        $rowForRules = [
            'active' => true,
            'host' => $host,
            'ip' => $ip,
            'country' => strtolower($countrySlug),
            'countryName' => $countryName,
            'speed' => numericValue($item['PROPERTY_SPEED_MBPS_VALUE'] ?? null),
            'latency' => numericValue($item['PROPERTY_PING_MS_VALUE'] ?? null),
            'sessions' => integerValue($item['PROPERTY_SESSIONS_VALUE'] ?? null),
            'uptime' => numericValue($item['PROPERTY_UPTIME_HOURS_VALUE'] ?? null),
            'clean' => yesValue($item['PROPERTY_CLEAN_VALUE'] ?? null),
            'port' => integerValue($item['PROPERTY_PORT_VALUE'] ?? null),
            'proto' => $transport,
            'source' => $source,
            'lastCheckOk' => yesValue($item['PROPERTY_LAST_CHECK_OK_VALUE'] ?? null),
            'failStreak' => integerValue($item['PROPERTY_FAIL_STREAK_VALUE'] ?? 0) ?? 0,
            'checkerStatus' => scalarValue($item['PROPERTY_VPN_CHECK_STATUS_VALUE'] ?? ''),
            'configAvailable' => $configAvailable,
            'checkedAt' => isoTime(scalarValue($item['PROPERTY_CHECKED_AT_VALUE'] ?? '')),
            'createdAt' => isoTime((string)($item['DATE_CREATE'] ?? $item['TIMESTAMP_X'] ?? '')),
        ];
        $score = pvl_technical_score_details($rowForRules, $nowTs);
        $rows[] = [
            'active' => true,
            'host' => $host,
            'ip' => $ip,
            'country_code' => $countryCode,
            'country_name' => (string)$rowForRules['countryName'],
            'speed_mbps' => $rowForRules['speed'],
            'latency_ms' => $rowForRules['latency'],
            'sessions' => $rowForRules['sessions'],
            'uptime_hours' => $rowForRules['uptime'],
            'clean' => $rowForRules['clean'],
            'port' => $rowForRules['port'],
            'protocol' => 'openvpn',
            'transport' => $transport,
            'source' => $source,
            'checked_at' => $rowForRules['checkedAt'],
            'first_seen_at' => $rowForRules['createdAt'],
            'last_success_at' => isoTime(scalarValue($item['PROPERTY_LAST_SUCCESS_AT_VALUE'] ?? '')),
            'config_updated_at' => null,
            'last_check_ok' => $rowForRules['lastCheckOk'],
            'fail_streak' => $rowForRules['failStreak'],
            'checker_status' => $rowForRules['checkerStatus'],
            'config_available' => $configAvailable,
            'canonical_visible' => pvl_is_server_live_visible($rowForRules, $nowTs),
            'canonical_downloadable' => pvl_is_server_downloadable($rowForRules, $nowTs),
            'technical_quality_score' => (int)($score['score'] ?? 0),
            'score_label' => (string)($score['label'] ?? 'Unknown'),
        ];
    }
    echo json_encode(
        $rows,
        JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    ) . "\n";
} catch (Throwable $error) {
    fwrite(STDERR, "Bitrix metadata read failed.\n");
    exit(1);
}

function scalarValue(mixed $value): string
{
    if (is_array($value)) {
        $value = reset($value);
    }
    return trim((string)$value);
}

function numericValue(mixed $value): ?float
{
    $value = scalarValue($value);
    return $value !== '' && is_numeric($value) ? (float)$value : null;
}

function integerValue(mixed $value): ?int
{
    $value = scalarValue($value);
    return $value !== '' && is_numeric($value) ? (int)$value : null;
}

function yesValue(mixed $value): bool
{
    return in_array(strtolower(scalarValue($value)), ['1', 'y', 'yes', 'true'], true);
}

function isoTime(string $value): ?string
{
    $timestamp = strtotime($value);
    return $timestamp === false ? null : gmdate('Y-m-d\TH:i:s\Z', $timestamp);
}

function configAvailable(string $siteRoot, string $rawPath, string $rawFileId): bool
{
    $allowedBase = realpath($siteRoot . '/public/ovpn');
    if ($allowedBase === false) {
        return false;
    }
    $candidates = [];
    if ($rawFileId !== '' && ctype_digit($rawFileId)) {
        $file = CFile::GetFileArray((int)$rawFileId);
        if (is_array($file) && isset($file['SRC'])) {
            $candidates[] = $siteRoot . '/' . ltrim((string)$file['SRC'], '/');
        }
    }
    if ($rawPath !== '') {
        $relative = ltrim(str_replace('\\', '/', $rawPath), '/');
        if (str_starts_with($relative, 'public/ovpn/')) {
            $candidates[] = $siteRoot . '/' . $relative;
        } elseif (str_starts_with($relative, 'ovpn/')) {
            $candidates[] = $siteRoot . '/public/' . $relative;
        } else {
            $candidates[] = $siteRoot . '/public/ovpn/' . $relative;
        }
    }
    foreach (array_unique($candidates) as $candidate) {
        $resolved = realpath($candidate);
        if ($resolved !== false
            && is_file($resolved)
            && strtolower((string)pathinfo($resolved, PATHINFO_EXTENSION)) === 'ovpn'
            && (int)filesize($resolved) > 0
            && str_starts_with($resolved, $allowedBase . '/')
        ) {
            return true;
        }
    }
    return false;
}
