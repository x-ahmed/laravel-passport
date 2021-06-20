<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules\Password;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index(Request $request)
    {
        $data = $request->validate([
            'name'     => ['required'],
            'email'    => ['required', 'email', 'unique:users,email'],
            'password' => ['required', new Password(8), 'confirmed'],
        ]);

        $user = User::create(\array_merge($data, [
            'password' => bcrypt($data['password']),
        ]));

        $response = match ($request->wantsJson()) {
            true  => response()->json([
                'message' => 'registered successfully.',
                'data'    => [
                    'name'   => $user->name,
                    'email'  => $user->email,
                    'status' => Response::HTTP_CREATED,
                ]
            ], Response::HTTP_CREATED),
            false => null,
        };
        return $response;
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        $data = $request->validate([
            'email'    => ['required', 'email'],
            'password' => ['required', new Password(8),],
        ]);

        $user = User::whereEmail($data['email'])->first();

        if (!$user || !Hash::check($data['password'], $user->password)) {
            throw ValidationException::withMessages([
                'error'   => 'Your credentials doesn\'t match our records',
                'status'  => Response::HTTP_UNPROCESSABLE_ENTITY,
            ]);
        }

        $token = $user->createToken('Authentication')->accessToken;

        $response = match ($request->wantsJson()) {
            true  => response()->json([
                'message' => 'Logged in successfully.',
                'data'    => [
                    'token'  => $token,
                    'status' => Response::HTTP_OK,
                ],
            ], Response::HTTP_OK),
            false => null,
        };

        return $response;
    }

    /**
     * Display the specified resource.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        //
    }
}
