<?php
/**
 * WP_Framework_Social Interfaces Social
 *
 * @author Technote
 * @copyright Technote All Rights Reserved
 * @license http://www.opensource.org/licenses/gpl-2.0.php GNU General Public License, version 2
 * @link https://technote.space
 */

namespace WP_Framework_Social\Interfaces;

use WP_Framework_Core\Interfaces\Hook;
use WP_Framework_Core\Interfaces\Singleton;

if ( ! defined( 'WP_CONTENT_FRAMEWORK' ) ) {
	exit;
}

/**
 * Interface Social
 * @package WP_Framework_Social\Interfaces
 */
interface Social extends Singleton, Hook {

	/**
	 * @return string
	 */
	public function get_service_name();

	/**
	 * @return array
	 */
	public function get_link_args();

	/**
	 * @return string
	 */
	public function get_link_contents();

	/**
	 * @return array
	 */
	public function get_oauth_settings();

	/**
	 * @return string|false
	 */
	public function get_oauth_link();

	/**
	 * @param array $params
	 *
	 * @return bool|false|int
	 */
	public function check_state_params( array $params );

	/**
	 * @param string $code
	 * @param string $client_id
	 * @param string $client_secret
	 *
	 * @return false|string
	 */
	public function get_access_token( $code, $client_id, $client_secret );

	/**
	 * @param string $access_token
	 *
	 * @return array|null
	 */
	public function get_user_info( $access_token );

	/**
	 * @param array $user
	 */
	public function register_or_login_customer( array $user );
}
