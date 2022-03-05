<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class ResetController extends Controller
{
    public function sendToken( Request $request )
    {
        $validator = Validator::make($request->all(),[
            'email' => 'required|string|email|max:255',
        ]);

        if ($validator->fails()){
            return response()->json($validator->errors());
        }

        $user = User::where('email', $request->email)->first();

        if(!$user){
            return response()->json(['message' => 'Akun tidak ditemukan'], 404);
        }

        $token = Str::random(64);

        DB::table('password_resets')->insert([
            'email' => $request->email,
            'token' => $token,
            'created_at' => now(),
            'expires_at' => now()->addMinutes(30),
        ]);

        return response()->json(['message' => 'Reset password telah dikirim', 'reset_token' => $token, 'token_type' => 'Bearer'], 200);
    }

    public function doReset(Request $request)
    {
        $validator = Validator::make($request->all(),[
            'email' => 'required|string|email|max:255',
            'password' => 'required|string|min:8',
            'reset_token' => 'required|string',
        ]);

        if ($validator->fails()){
            return response()->json($validator->errors());
        }

        $user = User::where('email', $request->email)->first();

        if(!$user){
            return response()->json(['message' => 'Akun tidak ditemukan'], 404);
        }

        $reset = DB::table('password_resets')->where('email', $request->email)->where('token', $request->reset_token)->first();

        if(!$reset){
            return response()->json(['message' => 'Token tidak valid atau ditemukan'], 404);
        }

        if($reset->used_token == 1){
            return response()->json(['message' => 'Token telah digunakan'], 404);
        }

        if($reset->expires_at < now()){
            return response()->json(['message' => 'Token telah kadaluarsa, mohon buat baru'], 404);
        }

        $user->password = Hash::make($request->password);
        $user->save();

        DB::table('password_resets')->where('email', $request->email)->where('token', $request->reset_token)->update([
            'used_token' => 1,
        ]);

        return response()->json(['message' => 'Password berhasil diubah'], 200);
    }
}
