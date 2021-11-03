<?
/***************************************************************************
 *          ___       ___
 *         /   \     /   \    VESvault
 *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
 *            \\     //                   https://vesvault.com https://ves.host
 *             \\   //
 *     ___      \\_//
 *    /   \     /   \         VESlocker:        Hardware-level PIN Security API
 *    \__ /     \ __/
 *       \\     //            https://veslocker.com
 *        \\   //
 *         \\_//
 *         /   \
 *         \___/
 *
 *
 * (c) 2021 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/


// MySQL settings
    $DBhost = "127.0.0.1";
    $DBdatabase = "VESlocker";
    $DBuser = "VESlocker";
    $DBpasswd = "secret";
    $DBtable = "VESlocker";
    
    $GraceSecs = 30;
    
    function b64dec($b64) {
	return base64_decode(str_replace(['-', '_'], ['+', '/'], $b64));
    }
    
    function b64enc($bin) {
	return str_replace(['=', '+', '/'], ['', '-', '_'], base64_encode($bin));
    }
    
    function error500() {
	header("HTTP/1.0 500 Internal Error");
	echo "Internal Error";
	exit;
    }
    
    $DB = new mysqli($DBhost, $DBuser, $DBpasswd, $DBdatabase);
    if (!$DB) error500();
    
    if (preg_match('/^application\/json/i', $_SERVER['HTTP_CONTENT_TYPE'])) {
	$req = json_decode(file_get_contents("php://input"));
	if (!$req) error500();
	$id = b64dec($req->challenge);
	$challenge = b64dec($req->challenge);
    } else {
	$id = b64dec($_REQUEST['id']);
	$challenge = b64dec($_REQUEST['challenge']);
    }
    
    $json = preg_match('/^application\/json', $_SERVER['HTTP_ACCEPT']);
    if (strlen($id) < 32) $id .= str_repeat("\x00", 32 - strlen($id));
    
    $id_cond = "id='" . $DB->real_escape_string($id) . "'";

    $recs = $DB->query("SELECT * FROM $DBtable WHERE $id_cond");
    if (!$recs) error500();
    if ($recs->num_rows > 0) {
	$row = $recs->fetch_object();
	$wait = strtotime($row->access_at) - $GraceSecs + 2 ** $row->access_count - time();
	if ($wait > 0) {
	    header("HTTP/1.0 403 Access Denied");
	    header("Refresh: $wait");
	    if ($json) {
		header("Content-Type: application/json");
		echo "{\"retry\":$wait}\n";
	    } else {
		header("Content-Type: text/plain");
		echo "Retry in $wait seconds\n";
	    }
	    exit;
	}
	$secret = $row->secret;
	header("X-VESlocker-Access-Count: {$row->access_count}");
	header("Last-Modified: " . gmdate('D, d M Y H:i:s T', strtotime($row->access_at)));
	$ok = $DB->query("UPDATE $DBtable SET access_at=NOW(), access_count=LEAST(32,access_count+1) WHERE $id_cond");
	if (!$ok) error500();
    } else {
	$secret = openssl_random_pseudo_bytes(32);
	$ok = $DB->query("INSERT INTO $DBtable SET $id_cond, secret='" . $DB->real_escape_string($secret) . "', access_at=NOW(), access_count=0");
	if (!$ok) error500();
	header("X-VESlocker-Access-Count: 0");
    }
    $key = b64enc(hash("sha256", $secret . $challenge, true));
    if ($json) {
	header("Content-Type: application/json");
	echo "{\"key\":\"$key\"}\n";
    } else {
	header("Content-Type: text/plain");
	echo "$key\n";
    }
    