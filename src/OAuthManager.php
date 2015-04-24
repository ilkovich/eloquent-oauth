<?php namespace AdamWathan\EloquentOAuth;

use Closure;
use Illuminate\Auth\AuthManager as Auth;
use AdamWathan\EloquentOAuth\Exceptions\ProviderNotRegisteredException;
use AdamWathan\EloquentOAuth\Exceptions\InvalidAuthorizationCodeException;
use AdamWathan\EloquentOAuth\Providers\ProviderInterface;

class OAuthManager
{
    protected $authorizer;
    protected $authenticator;
    protected $stateManager;
    protected $providers;

    public function __construct(Authorizer $authorizer, Authenticator $authenticator, StateManager $stateManager, ProviderRegistrar $providers)
    {
        $this->authorizer = $authorizer;
        $this->authenticator = $authenticator;
        $this->stateManager = $stateManager;
        $this->providers = $providers;
    }

    public function registerProvider($alias, ProviderInterface $provider)
    {
        $this->providers->registerProvider($alias, $provider);
    }

    public function authorize($providerAlias)
    {
        $state = $this->stateManager->generateState();
        return $this->authorizer->authorize($this->getProvider($providerAlias), $state);
    }

    public function login($providerAlias, Closure $callback = null, $requiresAuth = true)
    {
        if ($requiresAuth && ! $this->stateManager->verifyState()) {
            throw new InvalidAuthorizationCodeException;
        }
        $details = $this->getProvider($providerAlias)->getUserDetails();
        return $this->authenticator->login($providerAlias, $details, $callback);
    }

    public function associate($providerAlias, Closure $callback = null, $requiresAuth = true) {
        if ($requiresAuth && ! $this->stateManager->verifyState()) {
            throw new InvalidAuthorizationCodeException;
        }
        $details = $this->getProvider($providerAlias)->getUserDetails();

        return $this->authenticator->associate($providerAlias, $details, $callback);
    }

    public function revoke($providerAlias) {
        return $this->authenticator->revoke($providerAlias);
    }

    public function getAssociation($providerAlias, $user = null) {
        return $this->authenticator->getAssociation($providerAlias, $user);
    }

    public function getAllAssociations(array $providerAliases, $user = null) {
        return $this->authenticator->getAllAssociations($providerAliases, $user);
    }

    public function checkAssociation($providerAlias) {
        return $this->authenticator->checkAssociation($providerAlias);
    }

    public function refresh($providerAlias, $user = null) {
        $ident = $this->getAssociation($providerAlias, $user);

        $ident->access_token = (object)array_merge(
            (array)$ident->access_token,
            (array)$this->getProvider($ident->provider)->refreshToken($ident)
        );
        $ident->save();

        return $ident;
    }

    protected function getProvider($providerAlias)
    {
        return $this->providers->getProvider($providerAlias);
    }
}
