<?php
/**
 * WP_Framework_Social Traits Social
 *
 * @author Technote
 * @copyright Technote All Rights Reserved
 * @license http://www.opensource.org/licenses/gpl-2.0.php GNU General Public License, version 2
 * @link https://technote.space
 */

namespace WP_Framework_Social\Traits;

use WP_Framework;
use WP_Framework_Core\Traits\Hook;
use WP_Framework_Core\Traits\Singleton;
use WP_User;

if ( ! defined( 'WP_CONTENT_FRAMEWORK' ) ) {
	exit;
}

/**
 * Trait Social
 * @package WP_Framework_Social\Traits
 * @property WP_Framework $app
 */
trait Social {

	use Singleton, Hook;

	/**
	 * @var string $slug
	 */
	private $slug = null;

	/**
	 * @return string
	 */
	public function get_service_name() {
		if ( ! isset( $this->slug ) ) {
			$this->slug = $this->get_file_slug();
		}

		return $this->slug;
	}

	/**
	 * @return array
	 */
	abstract public function get_link_args();

	/**
	 * @return string
	 */
	abstract public function get_link_contents();

	/**
	 * @return array
	 */
	public function get_oauth_settings() {
		return $this->filter_oauth_settings( [
			$this->apply_filters( $this->get_service_name() . '_oauth_client_id' ),
			$this->apply_filters( $this->get_service_name() . '_oauth_client_secret' ),
		] );
	}

	/**
	 * @return array
	 */
	protected function get_configs() {
		return $this->app->get_config( 'social', $this->get_service_name(), [] );
	}

	/**
	 * @param string $key
	 * @param mixed $default
	 *
	 * @return mixed
	 */
	protected function get_config_value( $key, $default = null ) {
		return $this->app->array->get( $this->get_configs(), $key, $default );
	}

	/**
	 * @param array $settings
	 *
	 * @return array
	 */
	protected function filter_oauth_settings( array $settings ) {
		return $settings;
	}

	/**
	 * @param string $client_id
	 *
	 * @return array
	 */
	protected function get_oauth_link_query( $client_id ) {
		return $this->filter_oauth_link_query( [
			'client_id'     => $client_id,
			'redirect_uri'  => $this->apply_filters( $this->get_service_name() . '_oauth_redirect_uri' ),
			'scope'         => $this->get_config_value( 'scope' ),
			'response_type' => 'code',
			'state'         => $this->get_state(),
		], $client_id );
	}

	/**
	 * @param array $query
	 * @param string $client_id
	 *
	 * @return array
	 * @SuppressWarnings(PHPMD.UnusedFormalParameter)
	 */
	protected function filter_oauth_link_query(
		/** @noinspection PhpUnusedParameterInspection */
		array $query, $client_id
	) {
		return $query;
	}

	/**
	 * @param string $url
	 * @param array $params
	 *
	 * @return string
	 */
	protected function get_url( $url, array $params ) {
		if ( empty( $params ) ) {
			return $url;
		}
		$query = strpos( $url, '?' ) !== false ? '&' : '?';

		return $url . $query . http_build_query( $params );
	}

	/**
	 * @return string|false
	 */
	public function get_oauth_link() {
		list( $client_id, $client_secret ) = $this->get_oauth_settings();
		if ( empty( $client_id ) || empty( $client_secret ) ) {
			return false;
		}

		return $this->get_url( $this->get_config_value( 'auth_url' ), $this->get_oauth_link_query( $client_id ) );
	}

	/**
	 * @return string
	 */
	protected function get_auth_session_name() {
		return $this->get_service_name() . '_auth_session';
	}

	/**
	 * @return string
	 */
	protected function get_state() {
		$uuid  = $this->app->utility->uuid();
		$state = [
			'service'  => $this->get_service_name(),
			'uuid'     => $uuid,
			'redirect' => $this->app->input->get_current_path(),
		];
		$this->app->set_session( $this->get_auth_session_name(), $this->wp_create_nonce( $this->create_hash( $uuid ), false ) );

		return $this->encode_state( $state );
	}

	/**
	 * @return string
	 */
	protected function get_hash_source() {
		$key  = 'hash_source_' . $this->get_service_name();
		$rand = $this->app->get_option( $key );
		if ( empty( $rand ) ) {
			$rand = $this->app->utility->uuid();
			$this->app->option->set( $key, $rand );
		}

		return $rand;
	}

	/**
	 * @param $uuid
	 *
	 * @return false|string
	 */
	protected function create_hash( $uuid ) {
		return $this->app->utility->create_hash( $uuid, $this->get_hash_source() );
	}

	/**
	 * @param array $state
	 *
	 * @return string
	 */
	protected function encode_state( array $state ) {
		return strtr( base64_encode( wp_json_encode( $state ) ), '+/=', '-_,' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * @param array $params
	 *
	 * @return bool|false|int
	 */
	public function check_state_params( array $params ) {
		if (
			empty( $params ) ||
			empty( $params['uuid'] ) ||
			empty( $params['redirect'] ) ||
			! preg_match( '#\A/[^/]+#', $params['redirect'] ) ||
			! $this->app->session->exists( $this->get_auth_session_name() )
		) {
			return false;
		}

		$nonce = $this->app->get_session( $this->get_auth_session_name() );
		$this->app->session->delete( $this->get_auth_session_name() );

		return $this->wp_verify_nonce( $nonce, $this->create_hash( $params['uuid'] ), false );
	}

	/**
	 * @param string $code
	 * @param string $client_id
	 * @param string $client_secret
	 *
	 * @return array
	 */
	protected function get_access_token_params( $code, $client_id, $client_secret ) {
		return $this->filter_access_token_params( [
			'code'          => $code,
			'redirect_uri'  => $this->apply_filters( $this->get_service_name() . '_oauth_redirect_uri' ),
			'client_id'     => $client_id,
			'client_secret' => $client_secret,
		], $code, $client_id, $client_secret );
	}

	/**
	 * @param array $params
	 * @param string $code
	 * @param string $client_id
	 * @param string $client_secret
	 *
	 * @return array
	 * @SuppressWarnings(PHPMD.UnusedFormalParameter)
	 */
	protected function filter_access_token_params(
		/** @noinspection PhpUnusedParameterInspection */
		array $params, $code, $client_id, $client_secret
	) {
		return $params;
	}

	/**
	 * @param string $code
	 * @param string $client_id
	 * @param string $client_secret
	 *
	 * @return false|string
	 */
	public function get_access_token( $code, $client_id, $client_secret ) {
		$contents = $this->get_contents( 'token_url', $this->get_access_token_params( $code, $client_id, $client_secret ) );
		$response = @json_decode( $contents, true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( empty( $response ) || ! empty( $response['error'] ) ) {
			$this->app->log( 'social response error', [
				'$contents' => $contents,
				'$response' => $response,
			] );

			return false;
		}

		return $response['access_token'];
	}

	/**
	 * @param string $access_token
	 *
	 * @return array|null
	 */
	public function get_user_info( $access_token ) {
		$contents = $this->get_contents( 'user_info_url', [ 'access_token' => $access_token ] );
		$info     = @json_decode( $contents, true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( empty( $info ) ) {
			$this->app->log( 'social response error', [
				'$contents' => $contents,
				'$info'     => $info,
			] );

			return null;
		}

		return $info;
	}

	/**
	 * @param string $key
	 *
	 * @return bool
	 */
	protected function is_post_access( $key ) {
		return $this->get_config_value( 'is_post_' . $key, false );
	}

	/**
	 * @return string
	 */
	protected function get_user_agent() {
		return $this->apply_filters( 'user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36' );
	}

	/**
	 * @param array $query
	 * @param string $key
	 *
	 * @return bool|string
	 */
	protected function get_contents( $key, array $query = [] ) {
		$url = $this->get_config_value( $key );
		if ( empty( $url ) ) {
			return false;
		}

		$options                            = [];
		$options['ssl']['verify_peer']      = false;
		$options['ssl']['verify_peer_name'] = false;
		$options['http']['ignore_errors']   = true;
		if ( $this->is_post_access( $key ) ) {
			$options['http'] = [
				'method' => 'POST',
				'header' => implode( "\r\n", [
					'Content-Type: application/x-www-form-urlencoded',
					'Accept: application/json',
					'User-Agent: ' . $this->get_user_agent(),
				] ),
			];
			if ( ! empty( $query ) ) {
				$options['http']['content'] = http_build_query( $query );
			}
		} else {
			$url                       = $this->get_url( $url, $query );
			$options['http']['header'] = 'User-Agent: ' . $this->get_user_agent();
		}

		return @file_get_contents( $url, false, stream_context_create( $options ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents,WordPress.PHP.NoSilencedErrors.Discouraged
	}

	/**
	 * @param array $user
	 *
	 * @return array
	 */
	protected function get_user_data( array $user ) {
		if ( ! isset( $user['last_name'] ) && ! isset( $user['family_name'] ) ) {
			if ( ! empty( $user['name'] ) ) {
				$exploded = array_filter( explode( ' ', $user['name'] ) );
				if ( count( $exploded ) > 0 ) {
					$user['last_name'] = $exploded[0];
					if ( count( $exploded ) > 1 ) {
						$user['first_name'] = $exploded[1];
					}
				}
			}
		}

		return [
			isset( $user['last_name'] ) ? $user['last_name'] : ( isset( $user['family_name'] ) ? $user['family_name'] : '' ),
			isset( $user['first_name'] ) ? $user['first_name'] : ( isset( $user['given_name'] ) ? $user['given_name'] : '' ),
			$user['email'],
		];
	}

	/**
	 * @param int $user_id
	 *
	 * @return mixed
	 */
	abstract protected function find_social_customer( $user_id );

	/**
	 * @param array $user
	 * @param WP_User|null $wp_user
	 * @param bool $is_verified
	 *
	 * @return bool
	 */
	abstract protected function register_customer( array $user, WP_User $wp_user, $is_verified );

	/**
	 * @param array $user
	 * @param WP_User|null $wp_user
	 *
	 * @return bool
	 */
	abstract protected function logged_in_customer( array $user, WP_User $wp_user );

	/**
	 * @param array $user
	 */
	public function register_or_login_customer( array $user ) {
		$wp_user = null;
		if ( ! empty( $user['email'] ) ) {
			$wp_user = get_user_by( 'email', $user['email'] );
		}

		$social_id_key = 'social_login_' . $this->get_service_name();
		if ( empty( $wp_user ) ) {
			$user_id = $this->app->user->first( $social_id_key, $user['id'] );
			$wp_user = ! empty( $user_id ) ? get_user_by( 'id', $user_id ) : false;
		}

		$customer    = false;
		$is_verified = false;
		if ( empty( $wp_user ) ) {
			if ( empty( $user['email'] ) ) {
				/** @var \WP_Framework_Social\Classes\Models\Social $social */
				$social        = \WP_Framework_Social\Classes\Models\Social::get_instance( $this->app );
				$user['email'] = $social->get_pseudo_email( $user['id'] );
			} else {
				$is_verified = true;
			}
		}
		if ( ! empty( $wp_user ) ) {
			$customer = $this->find_social_customer( $wp_user->ID );
		}

		$this->check_succeeded( $user, $wp_user, $social_id_key, $customer, $is_verified );
	}

	/**
	 * @param $user
	 * @param $wp_user
	 * @param $social_id_key
	 * @param $customer
	 * @param $is_verified
	 */
	private function check_succeeded( $user, $wp_user, $social_id_key, $customer, $is_verified ) {
		$this->app->set_shared_object( 'is_social_login', true );
		if ( empty( $customer ) ) {
			if ( ! $this->register_customer( $this->get_user_data( $user ), ! empty( $wp_user ) ? $wp_user : null, $is_verified ) ) {
				return;
			}

			$wp_user = get_user_by( 'email', $user['email'] );
			if ( empty( $wp_user ) ) {
				$this->app->log( 'register customer error', [
					'user' => $user,
				] );

				return;
			}
		} else {
			if ( ! $this->logged_in_customer( $user, $wp_user ) ) {
				return;
			}
		}
		$this->app->user->delete_matched( $social_id_key, $user['id'] );
		$this->app->user->set( $social_id_key, $user['id'], $wp_user->ID );

		global $current_user;
		$current_user = null; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		wp_set_current_user( $wp_user->ID );
		wp_set_auth_cookie( $wp_user->ID, true );
		$this->app->user->reset_user_data();
	}
}
