<?php
/**
 *
 * Extend OAuth login. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2023, DSR! https://github.com/xchwarze
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 */

namespace dsr\oauthlogin\auth\provider\oauth\service;

use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\OAuth2\Service\SuplaExtend as SuplaService;
use phpbb\auth\provider\oauth\service\base;
use phpbb\auth\provider\oauth\service\exception;
use phpbb\config\config;
use phpbb\request\request_interface;

class supla extends base
{
    /** @var config */
    protected $config;

    /** @var request_interface */
    protected $request;

    /**
     * Constructor.
     *
     * @param config $config Config object
     * @param request_interface $request Request object
     */
    public function __construct(config $config, request_interface $request)
    {
        $this->config = $config;
        $this->request = $request;
    }

    /**
     * {@inheritdoc}
     */
    public function get_auth_scope()
    {
        return [
            'account_r',
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function get_external_service_class()
    {
        return 'SuplaExtend';
    }

    /**
     * {@inheritdoc}
     */
    public function get_service_credentials()
    {
        return [
            'key' => $this->config['auth_oauth_supla_key'],
            'secret' => $this->config['auth_oauth_supla_secret'],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function perform_auth_login()
    {
        if (!($this->service_provider instanceof SuplaService)) {
            throw new exception('AUTH_PROVIDER_OAUTH_ERROR_INVALID_SERVICE_TYPE');
        }

        $code = $this->request->variable('code', '');

        if (method_exists($this->service_provider, 'resolve_host_from_encoded_value')) {
            $this->service_provider->resolve_host_from_encoded_value($code);
        }

        try {
            // This was a callback request, get the token
            $this->service_provider->requestAccessToken($code);
        } catch (TokenResponseException $e) {
            throw new exception('AUTH_PROVIDER_OAUTH_ERROR_REQUEST');
        }

        if (method_exists($this->service_provider, 'sync_resolved_api_host_from_storage')) {
            $this->service_provider->sync_resolved_api_host_from_storage();
        }

        try {
            // Send a request with it
            $result = (array) json_decode($this->service_provider->request('/users/current'), true);
        } catch (\OAuth\Common\Exception\Exception $e) {
            throw new exception('AUTH_PROVIDER_OAUTH_ERROR_REQUEST');
        }

        // Return the unique identifier
        return $result['id'];
    }

    /**
     * {@inheritdoc}
     */
    public function perform_token_auth()
    {
        if (!($this->service_provider instanceof SuplaService)) {
            throw new exception('AUTH_PROVIDER_OAUTH_ERROR_INVALID_SERVICE_TYPE');
        }

        if (method_exists($this->service_provider, 'sync_resolved_api_host_from_storage')) {
            $this->service_provider->sync_resolved_api_host_from_storage();
        }

        try {
            // Send a request with it
            $result = (array) json_decode($this->service_provider->request('/users/current'), true);
        } catch (\OAuth\Common\Exception\Exception $e) {
            throw new exception('AUTH_PROVIDER_OAUTH_ERROR_REQUEST');
        }

        // Return the unique identifier
        return $result['id'];
    }
}
