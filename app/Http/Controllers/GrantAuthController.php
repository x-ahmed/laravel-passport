<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Illuminate\Validation\Rules\Password;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

class GrantAuthController extends Controller
{
    /**
     * Register password grant client users
     *
     * @param \Illuminate\Http\Request $request Description
     * @return \Illuminate\Http\Response
     **/
    public function register(Request $request): Response
    {
        $data = $request->validate([
            'name'     => ['required', 'string', 'max:255'],
            'email'    => ['required', 'string', 'email', 'max:255', 'unique:users,email'],
            'password' => ['required', 'string', new Password(8), 'confirmed'],
        ]);

        $user = User::create(\array_merge($data, [
            'password' => bcrypt($data['password']),
        ]));

        $response = match ($request->wantsJson()) {
            true  => response()->json([
                'message' => 'registered successfully.',
                'data'    => $this->getAccessWithRefreshedTokens(
                    email   : $data['email'],
                    password: $data['password']
                ),
                'status' => Response::HTTP_CREATED,
            ], Response::HTTP_CREATED),
            false => null,
        };
        return $response;
    }

    /**
     * Login password grant client users
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\Response
     **/
    public function login(Request $request): Response
    {
        $data = $request->validate([
            'email'    => ['required', 'string', 'email', 'max:255'],
            'password' => ['required', 'string', new Password(8)],
        ]);

        if (!$user = Auth::attempt($data)) {
            throw ValidationException::withMessages([
                'error'   => 'Your credentials doesn\'t match our records',
                'status'  => Response::HTTP_UNPROCESSABLE_ENTITY,
            ]);
        }

        $response = match ($request->wantsJson()) {
            true  => response()->json([
                'message' => 'logged in successfully.',
                'data'    => $this->getAccessWithRefreshedTokens(
                    email   : $data['email'],
                    password: $data['password']
                ),
                'status' => Response::HTTP_OK,
            ], Response::HTTP_OK),
            false => null,
        };
        return $response;
    }

    /**
     * Refresh expired access token using refresh token.
     *
     * https://laravel.com/docs/8.x/passport#refreshing-tokens
     * https://laravel.com/docs/8.x/http-client#guzzle-options
     *
     * http://docs.guzzlephp.org/en/stable/request-options.html
     * https://docs.guzzlephp.org/en/stable/request-options.html#verify
     *
     * @param Request $request
     * @return \Illuminate\Http\Response
     **/
    public function refreshToken(Request $request): Response
    {
        $refreshToken = $request->header('RefreshToken');

        $url    = config('app.url', 'http://127.0.0.1:8000');
        $verify = (config('app.env') == 'local') ? false : true ;

        $response = Http::withOptions([
            'verify' => $verify,
        ])->asForm()->post("{$url}/oauth/token", [
            'grant_type'    => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id'     => config('passport.personal_access_client.id'),
            'client_secret' => config('passport.personal_access_client.secret'),
            'scope'         => '*',
        ]);

        if(\array_key_exists(key: 'error', array: $response->json())) return response()->json([
            'message' => 'The request is missing a required parameter.',
            'data'    => [
                'error'       => 'invalid_request',
                'hint'        => 'Check the `refresh_token` parameter',
                'description' => 'Request must have `RefreshToken` key: valueWithoutQuotes',
            ],
            'status'  => \Symfony\Component\HttpFoundation\Response::HTTP_BAD_REQUEST,
        ], \Symfony\Component\HttpFoundation\Response::HTTP_BAD_REQUEST);


        return response()->json([
            'message' => 'Access token created successfully.',
            'data'    => $response->json(),
            'status'  => \Symfony\Component\HttpFoundation\Response::HTTP_CREATED,
        ], \Symfony\Component\HttpFoundation\Response::HTTP_CREATED);
    }

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
