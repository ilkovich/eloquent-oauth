<?php namespace AdamWathan\EloquentOAuth\Providers;

use AdamWathan\EloquentOAuth\ProviderUserDetails as UserDetails;
use AdamWathan\EloquentOAuth\Exceptions\ApplicationRejectedException;
use AdamWathan\EloquentOAuth\Exceptions\InvalidAuthorizationCodeException;
use AdamWathan\EloquentOAuth\Exceptions\InvalidConfigurationException;
use AdamWathan\EloquentOAuth\Exceptions\NotImplementedException;

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\BadResponseException;

use Illuminate\Http\Request as Input;

class InstapaperProvider implements ProviderInterface
{
    private $authUrl    = "https://www.instapaper.com/api/1/oauth/access_token";
    private $detailsUrl = "https://www.instapaper.com/api/1/account/verify_credentials";
    private $consumer_key;
    private $consumer_secret;

    private $oauth_token = null;
    private $oauth_token_secret = '';

    private $httpClient;

    public function __construct($config, HttpClient $httpClient, Input $input) {
        if(!isset($config['consumer_key'], $config['consumer_secret']))
            throw new InvalidConfigurationException('Missing consumer_key or consumer_secret in config');

        $this->consumer_key     = $config['consumer_key'];
        $this->consumer_secret  = $config['consumer_secret'];

        $this->httpClient = $httpClient;
    }

    public function authorizeUrl($state) {
        //stub just to make sure we have state setup
        return true;
    }
    
    private function generateHeaders($bodyParams, $url) {
        $headers = [
            "oauth_version"          => '1.0',
            "oauth_nonce"            => $this->generate_nonce(),
            "oauth_timestamp"        => time(),
            "oauth_consumer_key"     => $this->consumer_key,
            "oauth_signature_method" => "HMAC-SHA1",
        ];

        if(isset($this->oauth_token)) {
            $headers['oauth_token'] = $this->oauth_token;
        }


        $params = array_merge($bodyParams, $headers);

        $headers["oauth_signature"]   = $this->build_signature($this->build_http_query($params), $url);

        return $this->to_header($headers);
    }

      /**
       * builds the Authorization: header
       */
    public function to_header($parameters) {
        $first = true;
        $out = 'OAuth';

        $total = array();
        foreach ($parameters as $k => $v) {
            $out .= ($first) ? ' ' : ',';
            $out .= $this->urlencode_rfc3986($k) .
                '="' .
                $this->urlencode_rfc3986($v) .
                '"';
            $first = false;
        }
        return ['Authorization' => $out];
    }

    public function build_http_query($params) {
        if (!$params) return '';

        // Urlencode both keys and values
        $keys =   array_keys($params);
        $values = array_values($params);

        $keys = array_map([$this, 'urlencode_rfc3986'], $keys);
        $values = array_map([$this, 'urlencode_rfc3986'], $values);

        $params = array_combine($keys, $values);

        // Parameters are sorted by name, using lexicographical byte value ordering.
        // Ref: Spec: 9.1.1 (1)
        uksort($params, 'strcmp');

        $pairs = array();
        foreach ($params as $parameter => $value) {
            if (is_array($value)) {
                // If two or more parameters share the same name, they are sorted by their value
                // Ref: Spec: 9.1.1 (1)
                // June 12th, 2010 - changed to sort because of issue 164 by hidetaka
                sort($value, SORT_STRING);
                foreach ($value as $duplicate_value) {
                    $pairs[] = $parameter . '=' . $duplicate_value;
                }
            } else {
                $pairs[] = $parameter . '=' . $value;
            }
        }
        // For each parameter, the name is separated from the corresponding value by an '=' character (ASCII code 61)
        // Each name-value pair is separated by an '&' character (ASCII code 38)
        return implode('&', $pairs);
    }

    private function build_signature($params, $url) {
        $base_string = $this->get_signature_base_string($params, $url);
        $key         = $this->urlencode_rfc3986($this->consumer_secret).'&'.$this->urlencode_rfc3986($this->oauth_token_secret);

        return base64_encode(hash_hmac('sha1', $base_string, $key, true));
    }

    public function get_signature_base_string($params, $url) {
        $parts = array( 'POST', $url, $params);

        $parts = array_map(function($part) {
            return $this->urlencode_rfc3986($part);
        }, $parts);

        return implode('&', $parts);
    }

    private function urlencode_rfc3986($input) {
        return str_replace(
            '+',
            ' ',
            str_replace('%7E', '~', rawurlencode($input))
        );
    }

    private function generate_nonce() {
        $mt = microtime();
        $rand = mt_rand();

        return md5($mt . $rand); // md5s look nicer than numbers
    }


    public function getUserDetails()
    {
        $bodyParams = [
                "x_auth_username" => \Input::get('username'),
                "x_auth_password" => \Input::get('password'),
                "x_auth_mode"     => 'client_auth'
            ];

        $headers = $this->generateHeaders($bodyParams, $this->authUrl);

        try {
            $response = $this->httpClient->post($this->authUrl, [
                'headers' => $headers,
                'body' => $bodyParams
            ]);
        } catch (BadResponseException $e) {
            throw new InvalidAuthorizationCodeException((string) $e->getResponse());
        }

        $body = $response->getBody(true);
        $parts = explode('&', $body);
        $map = [];
        foreach($parts as $part) {
            $pair = explode('=', $part);
            $map[$pair[0]] = $pair[1];
        }

        if(!isset($map['oauth_token'], $map['oauth_token_secret']))
            throw new ApplicationRejectedException($body);

        $this->oauth_token        = $map['oauth_token'];
        $this->oauth_token_secret = $map['oauth_token_secret'];

        $headers = $this->generateHeaders([], $this->detailsUrl);

        try {
            $response = $this->httpClient->post($this->detailsUrl, [
                'headers' => $headers
            ])->json();
        } catch (BadResponseException $e) {
            throw new InvalidAuthorizationCodeException((string) $e->getResponse());
        }

        $details = array_merge($response[0], $map);

        return new UserDetails([
                'accessToken' => json_encode($map),
                'userId' =>  $details['user_id'],
                'email' => $details['username']
            ], $details);
    }
}
