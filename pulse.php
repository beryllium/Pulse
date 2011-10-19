<?php

/**
 * Pulse 1.0
 *
 * Generates an encrypted array of information intended to provide an update on the health of a server.
 *
 * In order to fully use it, you must first give values to the Keymaster and Gatekeeper variables.
 *
 * Usage example:
 * 		$data = file_get_contents( 'http://slimer.example.com/pulse.php?gatekeeper=ZUUL' );
 *
 * 		$array = unserialize( mcrypt_decrypt( 
 * 		             MCRYPT_RIJNDAEL_256, 
 * 		             'my secret keymaster value which is of course STAY PUFT MARSHMALLOW MAN',
 * 		             $data,
 * 		             MCRYPT_MODE_ECB );
 *
 * 		print_r( $array );
 *
 * @author Kevin Boyd (aka Beryllium) <beryllium@beryllium.ca> http://www.beryllium.ca/
 */

//$keymaster = ''; //Set this to a secret key that only your monitoring software knows (do NOT pass it by URL)
//$gatekeeper = ''; //Set this to a semi-secret key that can be passed to the script to extract the complex data.

//If gatekeeper is not provided, only a simple text message will be returned (useful for Amazon ELB health checks).

header( 'Content-type: text/plain' );
if ( empty( $keymaster ) || empty( $gatekeeper ) )
{
	echo "Pulse script is not configured.\n\nAre you the Keymaster?";
	exit;
}

if ( $gatekeeper !== $_REQUEST[ 'gatekeeper' ] )
{
	echo "Server is up.\n\nAre you the Gatekeeper?";
	exit;
}

if ( !extension_loaded( 'mcrypt' ) )
{
	echo "MCrypt not loaded.\n\nWho ya gonna call?";
	exit;
}

$windows = (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') ? true : false;

$status_array = array();
$status_array[ 'pulse_version' ] = '1.0';
$status_array[ 'server_status' ] = 'up';
$status_array[ 'date' ] = date( 'Y-m-d H:i:s' );
$status_array[ 'phpversion' ] = phpversion();
$status_array[ 'uname' ] = php_uname();
$status_array[ 'extensions' ] = get_loaded_extensions();
$status_array[ 'diskfree' ] = disk_free_space( '.' );
$status_array[ 'disktotal' ] = disk_total_space( '.' );

//Certain older PHP versions don't have this
if ( function_exists( 'gc_enabled' ) )
{
	$status_array[ 'gc' ] = gc_enabled();
}

//The Windows PHP api does not have these methods
if (!$windows)
{
	$status_array[ 'load_avg' ] = sys_getloadavg();
	$status_array[ 'resource_usage' ] = getrusage();
}

$packet = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $keymaster, serialize( $status_array ), MCRYPT_MODE_ECB );
$packet = base64_encode( $packet );

echo $packet;