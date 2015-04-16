<?php namespace AdamWathan\EloquentOAuth\Providers;

use AdamWathan\EloquentOAuth\Exceptions\InvalidAuthorizationCodeException;

class SpotifyProvider extends Provider
{
    protected $authorizeUrl   = "https://accounts.spotify.com/authorize";
    protected $accessTokenUrl = "https://accounts.spotify.com/api/token";
    protected $userDataUrl    = "https://api.spotify.com/v1/me";
    protected $scope = [ ];

    protected function getAuthorizeUrl()
    {
        return $this->authorizeUrl;
    }

    protected function getAccessTokenBaseUrl()
    {
        return $this->accessTokenUrl;
    }

    protected function getUserDataUrl()
    {
        return $this->userDataUrl;
    }

    protected function parseTokenResponse($response)
    {
        $params = [];
        parse_str($response, $params);
        if (! isset($params['access_token'])) {
            throw new InvalidAuthorizationCodeException;
        }
        return $params['access_token'];
    }

    protected function parseUserDataResponse($response)
    {
        return json_decode($response, true);
    }

    protected function userId()
    {
        return $this->getProviderUserData('id');
    }

    protected function imageUrl()
    {
        return null;
    }

    protected function nickname()
    {
        return $this->getProviderUserData('display_name');
    }

    protected function firstName()
    {
        return $this->getProviderUserData('display_name');
    }

    protected function lastName()
    {
        return $this->getProviderUserData('last_name');
    }

    protected function email()
    {
        return $this->getProviderUserData('email');
    }

    protected function compileScopes()
    {
        return implode(' ', $this->scope);
    }

}
