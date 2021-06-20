<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Http;

class GrantAuthController extends Controller
{
    /**
     * Get password grant client token for the given credentials.
     *
     * https://laravel.com/docs/8.x/passport#requesting-password-grant-tokens
     * https://laravel.com/docs/8.x/http-client#guzzle-options
     *
     * http://docs.guzzlephp.org/en/stable/request-options.html
     * https://docs.guzzlephp.org/en/stable/request-options.html#verify
     *
     * @param string $email
     * @param string $password
     * @return array
     **/
    private function getAccessWithRefreshedTokens(string $email, string $password): array
    {
        $url    = config('app.url', 'http://127.0.0.1:8000');
        $verify = (config('app.env') == 'local') ? false : true ;

        $response = Http::withOptions([
            'verify' => $verify,
        ])->asForm()->post("{$url}/oauth/token", [
            'grant_type'    => 'password',
            'client_id'     => config('passport.personal_access_client.id'),
            'client_secret' => config('passport.personal_access_client.secret'),
            'username'      => $email,
            'password'      => $password,
            'scope'         => '*',
        ]);

        return $response->json();
    }
}
