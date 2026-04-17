<?php
/**
 *
 * Extend OAuth login. An extension for the phpBB Forum Software package.
 *
 * @copyright (c) 2023, DSR! https://github.com/xchwarze
 * @license GNU General Public License, version 2 (GPL-2.0)
 *
 */

namespace OAuth\OAuth2\Service;

use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Http\Uri\UriInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\OAuth2\Token\StdOAuth2Token;

class SuplaExtend extends AbstractService
{
    /**
     * Scope list
     * @see https://github.com/SUPLA/api-client-php
     */
    const SCOPE_ACCOUNT_READ = 'account_r';

    /** @var string|null */
    protected $resolvedApiHost = null;

    public function __construct(
        CredentialsInterface  $credentials,
        ClientInterface       $httpClient,
        TokenStorageInterface $storage,
                              $scopes = array(),
        UriInterface          $baseApiUri = null
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri, true);

        if (null === $baseApiUri) {
            $this->baseApiUri = new Uri('https://cloud.supla.org/api/v3/');
        }
    }

    /**
     * Resolve the target SUPLA host from an encoded token/code value.
     *
     * SUPLA appends the target server as a base64-encoded URL in the suffix
     * after the last dot. Example:
     *   <opaque>.<base64("https://svr23.supla.org")>
     *
     * @param string $value Encoded code or token value
     * @return string|null
     */
    public function resolve_host_from_encoded_value($value)
    {
        $host = $this->extract_host_from_encoded_value($value);

        if (null === $host) {
            return null;
        }

        $this->apply_resolved_api_host($host);

        return $host;
    }

    /**
     * Try to resolve the host from the stored access token.
     *
     * @return string|null
     */
    public function sync_resolved_api_host_from_storage()
    {
        if (!empty($this->resolvedApiHost)) {
            return $this->resolvedApiHost;
        }

        if (!isset($this->storage) || !is_object($this->storage) || !method_exists($this->storage, 'retrieveAccessToken')) {
            return null;
        }

        try {
            $token = $this->storage->retrieveAccessToken($this->service());
        } catch (\Exception $e) {
            return null;
        }

        $accessToken = null;

        if (is_object($token)) {
            if (method_exists($token, 'getAccessToken')) {
                $accessToken = $token->getAccessToken();
            } elseif (method_exists($token, 'getToken')) {
                $accessToken = $token->getToken();
            } elseif (isset($token->access_token)) {
                $accessToken = $token->access_token;
            }
        } elseif (is_array($token) && isset($token['access_token'])) {
            $accessToken = $token['access_token'];
        } elseif (is_string($token)) {
            $accessToken = $token;
        }

        if (!is_string($accessToken) || $accessToken === '') {
            return null;
        }

        return $this->resolve_host_from_encoded_value($accessToken);
    }

    /**
     * {@inheritdoc}
     */
    public function service()
    {
        return 'SUPLA';
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri('https://cloud.supla.org/oauth/v2/auth');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri('https://cloud.supla.org/oauth/v2/token');
    }

    /**
     * {@inheritdoc}
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }

    /**
     * {@inheritdoc}
     */
    protected function parseAccessTokenResponse($responseBody)
    {
        $data = json_decode($responseBody, true);

        if (null === $data || !is_array($data)) {
            throw new TokenResponseException('Unable to parse response.');
        } elseif (isset($data['error'])) {
            $message = is_scalar($data['error']) ? (string) $data['error'] : 'unknown error';
            throw new TokenResponseException('Error in retrieving token: "' . $message . '"');
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);
        unset($data['access_token']);

        if (isset($data['expires_in'])) {
            $token->setLifeTime($data['expires_in']);
            unset($data['expires_in']);
        }

        if (isset($data['refresh_token'])) {
            $token->setRefreshToken($data['refresh_token']);
            unset($data['refresh_token']);
        }

        $token->setExtraParams($data);

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    protected function getExtraApiHeaders()
    {
        return array(
            'Accept' => 'application/json',
        );
    }

    /**
     * Apply a resolved host to the base API URI.
     *
     * @param string $host
     * @return void
     */
    protected function apply_resolved_api_host($host)
    {
        $host = strtolower(trim($host));

        if ($host === '') {
            return;
        }

        $this->resolvedApiHost = $host;
        $this->baseApiUri = new Uri('https://' . $host . '/api/v3/');
    }

    /**
     * Extract a host from the SUPLA encoded token/code suffix.
     *
     * @param string $value
     * @return string|null
     */
    protected function extract_host_from_encoded_value($value)
    {
        $value = trim((string) $value);
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
        if (false !== $decoded && is_string($decoded) && $this->looks_like_url($decoded)) {
            $suffix = $decoded;
        } elseif ($this->looks_like_url($suffix)) {
            // Keep the suffix as-is.
        } else {
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

    /**
     * Check whether a string looks like a URL we can safely parse.
     *
     * @param string $value
     * @return bool
     */
    protected function looks_like_url($value)
    {
        return is_string($value) && (bool) preg_match('#^https?://[A-Za-z0-9.-]+(?::\d+)?(?:/.*)?$#i', trim($value));
    }
}
