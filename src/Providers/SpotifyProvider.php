<?php namespace AdamWathan\EloquentOAuth\Providers;

use AdamWathan\EloquentOAuth\Exceptions\InvalidAuthorizationCodeException;

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\BadResponseException;

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
        return json_decode($response);
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

    protected function requestAccessToken()
    {
        $url = $this->getAccessTokenBaseUrl();
        try {
            $response = $this->httpClient->post($url, [
                'body' => [
                    'code' => $this->getAuthorizationCode(),
                    'client_id' => $this->clientId,
                    'client_secret'=>$this->clientSecret,
                    'redirect_uri'=>$this->redirectUri(),
                    'grant_type'=>'authorization_code'
                ]
            ]);
        } catch (BadResponseException $e) {
            dd([$url, $body, (string)$e->getResponse()]);
            throw new InvalidAuthorizationCodeException((string) $e->getResponse());
        }
        return $this->parseTokenResponse((string) $response->getBody());
    }

    protected function buildUserDataUrl()
    {
        $url = $this->getUserDataUrl();
        $url .= "?access_token=".$this->accessToken->access_token;
        return $url;
    }

    protected function redirectUri()
    {
        return urlencode($this->redirectUri);
    }
}
