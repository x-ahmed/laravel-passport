<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\GrantAuthController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

// Password Grant Client
Route::post('grant/register', [GrantAuthController::class, 'register']);

// Personal Access Client
Route::post('login', [AuthController::class, 'store']);
Route::post('register', [AuthController::class, 'index']);

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});
