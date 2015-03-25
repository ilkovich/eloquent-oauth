<?php namespace AdamWathan\EloquentOAuth;

class IdentityStore
{
    public function getByProvider($provider, $providerUserDetails, $user = null)
    {
        $q = OAuthIdentity::where('provider', $provider)
            ->where('provider_user_id', $providerUserDetails->userId);

        if($user) 
            $q = $q->where('user_id', $user->id);

        return $q->first();
    }

    public function flush($user, $provider)
    {
        OAuthIdentity::where('user_id', $user->getKey())
            ->where('provider', $provider)
            ->delete();
    }

    public function store(OAuthIdentity $identity)
    {
        $identity->save();
    }

    public function userExists($user, $provider, ProviderUserDetails $details)
    {
        return (bool) $this->getByProvider($provider, $details, $user);
    }
}
