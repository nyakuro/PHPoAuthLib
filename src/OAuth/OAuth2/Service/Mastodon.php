<?php

namespace OAuth\OAuth2\Service;

use OAuth\OAuth2\Token\StdOAuth2Token;
use OAuth\Common\Http\Exception\TokenResponseException;
use OAuth\Common\Http\Uri\Uri;
use OAuth\Common\Consumer\CredentialsInterface;
use OAuth\Common\Http\Client\ClientInterface;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Http\Uri\UriInterface;

class Mastodon extends AbstractService
{

    /**
     * Defined scopes
     *
     * @link https://github.com/tootsuite/documentation/blob/master/Using-the-API/OAuth-details.md
     */
    const SCOPE_READ   = 'read';
    const SCOPE_WRITE  = 'write';
    const SCOPE_FOLLOW = 'follow';

    protected $host = 'https://mastodon.social';

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient,
        TokenStorageInterface $storage,
        $scopes = array(),
        UriInterface $baseApiUri = null,
        $apiVersion = ""
    ) {
        parent::__construct($credentials, $httpClient, $storage, $scopes, $baseApiUri, true, $apiVersion);

        // $baseApiUri: like https://example.com
        // ToDo other instances
        $this->apiVersion = 1;

        // $this->host = $baseApiUri;
        $this->baseApiUri = new Uri($this->host . '/api' . $this->getApiVersionString() . '/');
    }

    /**
     * {@inheritdoc}
     */
    public function getAuthorizationEndpoint()
    {
        return new Uri($this->host . '/oauth/authorize');
    }

    /**
     * {@inheritdoc}
     */
    public function getAccessTokenEndpoint()
    {
        return new Uri($this->host . '/oauth/token');
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
            throw new TokenResponseException('Error in retrieving token: "' . $data['error'] . '"');
        }

        $token = new StdOAuth2Token();
        $token->setAccessToken($data['access_token']);
        // Instagram tokens evidently never expire...
        $token->setEndOfLife(StdOAuth2Token::EOL_NEVER_EXPIRES);
        unset($data['access_token']);

        $token->setExtraParams($data);

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    protected function getApiVersionString()
    {
        return empty($this->apiVersion) ? '' : '/v' . $this->apiVersion;
    }

    /**
     * {@inheritdoc}
     */
    protected function getScopesDelimiter()
    {
        return ' ';
    }

    /**
     * Returns a class constant from ServiceInterface defining the authorization method used for the API
     * Header is the sane default.
     *
     * @return int
     */
    protected function getAuthorizationMethod()
    {
        return static::AUTHORIZATION_METHOD_HEADER_BEARER;
    }
}
